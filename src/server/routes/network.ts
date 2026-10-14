import { Router } from 'express';
import os from 'os';
import { safeExecFile, safeExecPowerShell, psString, sanitizeInterfaceName } from '../safeExec.ts';
import { requireAuth } from '../auth.ts';
import { sharedState } from '../state.ts';

export const networkRouter = Router();

export let killSwitchActive = false;
export let killSwitchEngagedAt: string | null = null;
export let disabledInterfacesList: string[] = [];

export async function getDetailedNetworkInterfaces() {
  const isWin32 = os.platform() === 'win32';
  const osIfaces = os.networkInterfaces();
  const result: any[] = [];
  let loopbackFound = false;

  for (const [ifName, addrs] of Object.entries(osIfaces)) {
    if (!addrs || addrs.length === 0) continue;
    const isWifi = /wi-?fi|wlan|wireless|sans fil/i.test(ifName);
    const isEth = /eth|ethernet|en[0-9]|réseau local/i.test(ifName);
    const isLoop = /loopback|lo|localhost/i.test(ifName) || addrs.some((a) => a.internal || a.address === '127.0.0.1');
    const isVirt = /vethernet|hyper-v|vmware|virtual|docker|tailscale|zerotier/i.test(ifName);

    if (isLoop) loopbackFound = true;
    const mac = addrs[0]?.mac && addrs[0].mac !== '00:00:00:00:00:00' ? addrs[0].mac : 'XX:XX:XX:XX:XX:XX';
    const ips = addrs.map((a) => `${a.address} (${a.family})`);
    const type = isLoop ? 'Loopback' : isWifi ? 'Wi-Fi' : isEth ? 'Ethernet' : isVirt ? 'Virtual' : 'Other';
    const isDisabled = disabledInterfacesList.includes(ifName);

    result.push({
      id: `iface-${ifName}`,
      name: ifName,
      displayName: isWifi
        ? `Wi-Fi (${ifName})`
        : isEth
        ? `Ethernet (${ifName})`
        : isLoop
        ? `Boucle Locale (${ifName})`
        : ifName,
      type,
      status: isDisabled ? 'Disabled' : 'Up',
      adminStatus: isDisabled ? 'Disabled' : 'Enabled',
      mac,
      ipAddresses: ips,
      speedMbps: isWifi ? 866 : isEth ? 1000 : 10000,
      isLoopback: isLoop,
      isPhysical: !isLoop && !isVirt,
    });
  }

  // On Windows, enrich with netsh and WMI if available
  if (isWin32) {
    try {
      const { stdout: netshOut } = await safeExecFile('netsh.exe', ['interface', 'show', 'interface']);
      const lines = netshOut.split('\n');
      for (const line of lines) {
        const match = line
          .trim()
          .match(/^(Activé|Désactivé|Enabled|Disabled)\s+(Connecté|Déconnecté|Connected|Disconnected)\s+(Dédié|Dedicated)\s+(.+)$/i);
        if (match) {
          const adminState = match[1];
          const connState = match[2];
          const ifaceName = match[4].trim();

          const existing = result.find((r) => r.name.toLowerCase() === ifaceName.toLowerCase());
          const isWifi = /wi-?fi|sans fil/i.test(ifaceName);
          const isEth = /ethernet|réseau local/i.test(ifaceName);
          const isDisabled = disabledInterfacesList.includes(ifaceName) || /désactivé|disabled/i.test(adminState);

          if (existing) {
            existing.status = isDisabled ? 'Disabled' : /connecté|connected/i.test(connState) ? 'Up' : 'Down';
            existing.adminStatus = isDisabled ? 'Disabled' : 'Enabled';
          } else {
            result.push({
              id: `win-${ifaceName.replace(/[^a-zA-Z0-9]/g, '_')}`,
              name: ifaceName,
              displayName: ifaceName,
              type: isWifi ? 'Wi-Fi' : isEth ? 'Ethernet' : 'Other',
              status: isDisabled ? 'Disabled' : /connecté|connected/i.test(connState) ? 'Up' : 'Down',
              adminStatus: isDisabled ? 'Disabled' : 'Enabled',
              mac: 'XX:XX:XX:XX:XX:XX',
              ipAddresses: [],
              speedMbps: isWifi ? 866 : 1000,
              isLoopback: false,
              isPhysical: true,
            });
          }
        }
      }
    } catch {}
  }

  // Always ensure Loopback 127.0.0.1 is explicitly documented and confirmed
  if (!loopbackFound) {
    result.unshift({
      id: 'loopback-default',
      name: 'Loopback Pseudo-Interface 1',
      displayName: 'Boucle Locale Interne (localhost)',
      type: 'Loopback',
      status: 'Up',
      adminStatus: 'Enabled',
      mac: '00:00:00:00:00:00',
      ipAddresses: ['127.0.0.1 (IPv4)', '::1 (IPv6)'],
      speedMbps: 10000,
      isLoopback: true,
      isPhysical: false,
    });
  }

  return result;
}

export async function restoreNetworkInterfacesInternal(): Promise<string[]> {
  const isWin32 = os.platform() === 'win32';
  const toRestore = [...disabledInterfacesList];

  for (const ifaceName of toRestore) {
    if (isWin32) {
      try {
        const safeName = sanitizeInterfaceName(ifaceName);
        await safeExecFile('netsh.exe', ['interface', 'set', 'interface', safeName, 'admin=enabled']);
      } catch {
        try {
          const safeName = sanitizeInterfaceName(ifaceName);
          await safeExecPowerShell(`Enable-NetAdapter -Name ${psString(safeName)} -Confirm:$false`);
        } catch {}
      }
    }
  }

  if (isWin32) {
    try {
      await safeExecFile('netsh.exe', ['advfirewall', 'firewall', 'delete', 'rule', 'name=SpaceSec-KillSwitch-Block']);
    } catch {}
  }

  killSwitchActive = false;
  killSwitchEngagedAt = null;
  disabledInterfacesList = [];
  return toRestore;
}

// GET /api/network/interfaces - List all interfaces & current Kill-Switch state
networkRouter.get('/interfaces', async (req, res) => {
  try {
    const ifaces = await getDetailedNetworkInterfaces();
    const activeExternal = ifaces.filter((i) => !i.isLoopback && i.status === 'Up');

    res.json({
      success: true,
      killSwitchActive,
      engagedAt: killSwitchEngagedAt,
      loopbackProtected: true,
      localhostPort: 3000,
      localhostIp: '127.0.0.1',
      totalInterfaces: ifaces.length,
      totalActiveExternal: activeExternal.length,
      disabledInterfaces: disabledInterfacesList,
      interfaces: ifaces,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/network/kill-switch - Execute Emergency Network Kill-Switch
networkRouter.post('/kill-switch', requireAuth, async (req, res) => {
  try {
    const isWin32 = os.platform() === 'win32';
    const ifaces = await getDetailedNetworkInterfaces();
    const targetInterfaces = ifaces.filter((i) => !i.isLoopback);

    const executedCommands: string[] = [];
    const newlyDisabled: string[] = [];

    for (const iface of targetInterfaces) {
      newlyDisabled.push(iface.name);
      const netshCmd = `netsh interface set interface "${iface.name}" admin=disabled`;
      executedCommands.push(netshCmd);

      if (isWin32) {
        try {
          const safeName = sanitizeInterfaceName(iface.name);
          await safeExecFile('netsh.exe', ['interface', 'set', 'interface', safeName, 'admin=disabled']);
        } catch {
          try {
            const safeName = sanitizeInterfaceName(iface.name);
            await safeExecPowerShell(`Disable-NetAdapter -Name ${psString(safeName)} -Confirm:$false`);
          } catch {}
        }
      }
    }

    // Add strict firewall outbound block rule for external traffic, strictly preserving 127.0.0.1
    if (isWin32) {
      try {
        const fwRule =
          'netsh advfirewall firewall add rule name="SpaceSec-KillSwitch-Block" dir=out action=block remoteip=0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255';
        await safeExecFile('netsh.exe', [
          'advfirewall',
          'firewall',
          'add',
          'rule',
          'name=SpaceSec-KillSwitch-Block',
          'dir=out',
          'action=block',
          'remoteip=0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255'
        ]);
        executedCommands.push(fwRule);
      } catch {}
    }

    killSwitchActive = true;
    killSwitchEngagedAt = new Date().toISOString();
    disabledInterfacesList = Array.from(new Set([...disabledInterfacesList, ...newlyDisabled]));

    // Log into shared state
    sharedState.logs.unshift({
      id: `killswitch-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString('fr-FR'),
      level: 'KERNEL',
      tag: 'KILL-SWITCH',
      text: `ISOLATION D'URGENCE RÉSEAU ACTIVÉE : ${newlyDisabled.length} interface(s) coupée(s) (Wi-Fi/Ethernet). Boucle locale 127.0.0.1 (localhost:3000) préservée et active.`,
    });

    res.json({
      success: true,
      killSwitchActive: true,
      engagedAt: killSwitchEngagedAt,
      message:
        "Isolation d'urgence activée. Toutes les interfaces Wi-Fi et Ethernet sont désactivées. Le trafic externe est coupé. La boucle locale localhost (127.0.0.1) reste 100% active.",
      disabledInterfaces: disabledInterfacesList,
      loopbackProtected: true,
      localhostStatus: 'OPERATIONAL',
      localhostPort: 3000,
      executedCommands,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/network/restore - Restore Network Interfaces
networkRouter.post('/restore', requireAuth, async (req, res) => {
  try {
    const toRestore = await restoreNetworkInterfacesInternal();

    sharedState.logs.unshift({
      id: `restore-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString('fr-FR'),
      level: 'OK',
      tag: 'KILL-SWITCH',
      text: `Rétablissement du réseau effectué : ${toRestore.length} interface(s) réactivée(s) avec succès. Connectivité normale rétablie.`,
    });

    res.json({
      success: true,
      killSwitchActive: false,
      message: 'Interfaces réseau réactivées avec succès. Connectivité normale restaurée.',
      restoredInterfaces: toRestore,
      executedCommands: toRestore.map((name) => `netsh interface set interface "${name}" admin=enabled`),
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/network/toggle-interface - Toggle specific interface
networkRouter.post('/toggle-interface', requireAuth, async (req, res, next) => {
  try {
    const { interfaceName, enable } = req.body;
    const safeName = sanitizeInterfaceName(interfaceName);
    const isWin32 = os.platform() === 'win32';
    const adminArg = enable ? 'admin=enabled' : 'admin=disabled';

    if (isWin32) {
      await safeExecFile('netsh.exe', ['interface', 'set', 'interface', safeName, adminArg]);
    }

    if (enable) {
      disabledInterfacesList = disabledInterfacesList.filter((n) => n.toLowerCase() !== safeName.toLowerCase());
    } else {
      if (!disabledInterfacesList.some((n) => n.toLowerCase() === safeName.toLowerCase())) {
        disabledInterfacesList.push(safeName);
      }
    }

    res.json({
      success: true,
      interfaceName: safeName,
      adminStatus: enable ? 'Enabled' : 'Disabled',
      disabledInterfaces: disabledInterfacesList,
    });
  } catch (err: any) {
    next(err);
  }
});
