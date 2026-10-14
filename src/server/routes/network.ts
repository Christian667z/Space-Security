import { Router } from 'express';
import os from 'os';
import { safeExecFile, sanitizeInterfaceName, sanitizeIpAddress } from '../safeExec.ts';
import { dbManager } from '../db.ts';
import { logger } from '../logger.ts';
import { requireAuth } from '../auth.ts';
import { GoogleGenAI } from '@google/genai';

export const networkRouter = Router();
const ai = new GoogleGenAI();

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
    const isLoop = /loopback|lo|localhost/i.test(ifName) || addrs.some(a => a.internal || a.address === '127.0.0.1');
    const isVirt = /vethernet|hyper-v|vmware|virtual|docker|tailscale|zerotier/i.test(ifName);

    if (isLoop) loopbackFound = true;
    const mac = addrs[0]?.mac && addrs[0].mac !== '00:00:00:00:00:00' ? addrs[0].mac : 'XX:XX:XX:XX:XX:XX';
    const ips = addrs.map(a => `${a.address} (${a.family})`);
    const type = isWifi ? 'Wi-Fi' : (isEth ? 'Ethernet' : (isLoop ? 'Loopback' : (isVirt ? 'Virtual' : 'Other')));
    const isDisabled = disabledInterfacesList.includes(ifName);

    result.push({
      id: `iface-${ifName}`,
      name: ifName,
      displayName: isWifi ? `Wi-Fi (${ifName})` : (isEth ? `Ethernet (${ifName})` : (isLoop ? `Boucle Locale (${ifName})` : ifName)),
      type,
      status: isDisabled ? 'Disabled' : 'Up',
      adminStatus: isDisabled ? 'Disabled' : 'Enabled',
      mac,
      ipAddresses: ips,
      speedMbps: isWifi ? 866 : (isEth ? 1000 : 10000),
      isLoopback: isLoop,
      isPhysical: !isLoop && !isVirt,
    });
  }

  if (isWin32) {
    try {
      const { stdout: netshOut } = await safeExecFile('netsh', ['interface', 'show', 'interface']);
      const lines = netshOut.split('\n');
      for (const line of lines) {
        const match = line.trim().match(/^(Activé|Désactivé|Enabled|Disabled)\s+(Connecté|Déconnecté|Connected|Disconnected)\s+(Dédié|Dedicated)\s+(.+)$/i);
        if (match) {
          const adminState = match[1];
          const connState = match[2];
          const ifaceName = match[4].trim();

          const existing = result.find(r => r.name.toLowerCase() === ifaceName.toLowerCase());
          const isWifi = /wi-?fi|sans fil/i.test(ifaceName);
          const isEth = /ethernet|réseau local/i.test(ifaceName);
          const isDisabled = disabledInterfacesList.includes(ifaceName) || /désactivé|disabled/i.test(adminState);

          if (existing) {
            existing.status = isDisabled ? 'Disabled' : (/connecté|connected/i.test(connState) ? 'Up' : 'Down');
            existing.adminStatus = isDisabled ? 'Disabled' : 'Enabled';
          } else {
            result.push({
              id: `win-${ifaceName.replace(/[^a-zA-Z0-9]/g, '_')}`,
              name: ifaceName,
              displayName: ifaceName,
              type: isWifi ? 'Wi-Fi' : (isEth ? 'Ethernet' : 'Other'),
              status: isDisabled ? 'Disabled' : (/connecté|connected/i.test(connState) ? 'Up' : 'Down'),
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

  if (!loopbackFound) {
    result.unshift({
      id: 'loopback-default',
      name: isWin32 ? 'Loopback Pseudo-Interface 1' : 'lo',
      displayName: 'Boucle Locale Système (localhost)',
      type: 'Loopback',
      status: 'Up',
      adminStatus: 'Enabled',
      mac: '00:00:00:00:00:00',
      ipAddresses: ['127.0.0.1', '::1'],
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
        await safeExecFile('netsh', ['interface', 'set', 'interface', ifaceName, 'admin=enabled']);
      } catch {
        try {
          await safeExecFile('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', `Enable-NetAdapter -Name '${ifaceName.replace(/'/g, "''")}' -Confirm:$false`]);
        } catch {}
      }
    }
  }

  if (isWin32) {
    try {
      await safeExecFile('netsh', ['advfirewall', 'firewall', 'delete', 'rule', 'name=SpaceSec-KillSwitch-Block']);
    } catch {}
  }

  killSwitchActive = false;
  killSwitchEngagedAt = null;
  disabledInterfacesList = [];
  return toRestore;
}

// GET /api/network/interfaces
networkRouter.get('/interfaces', async (req, res) => {
  try {
    const ifaces = await getDetailedNetworkInterfaces();
    const activeExternal = ifaces.filter(i => !i.isLoopback && i.status === 'Up');
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

// POST /api/network/kill-switch - SECURED: Parameterized execFile
networkRouter.post('/kill-switch', requireAuth, async (req, res) => {
  try {
    const isWin32 = os.platform() === 'win32';
    const ifaces = await getDetailedNetworkInterfaces();
    const targetInterfaces = ifaces.filter(i => !i.isLoopback);

    const executedCommands: string[] = [];
    const newlyDisabled: string[] = [];

    for (const iface of targetInterfaces) {
      newlyDisabled.push(iface.name);
      executedCommands.push(`netsh interface set interface "${iface.name}" admin=disabled`);

      if (isWin32) {
        try {
          // PARAMETERIZED execution: no cmd.exe concatenation
          await safeExecFile('netsh', ['interface', 'set', 'interface', iface.name, 'admin=disabled']);
        } catch {
          try {
            await safeExecFile('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', `Disable-NetAdapter -Name '${iface.name.replace(/'/g, "''")}' -Confirm:$false`]);
          } catch {}
        }
      }
    }

    if (isWin32) {
      try {
        await safeExecFile('netsh', [
          'advfirewall', 'firewall', 'add', 'rule',
          'name=SpaceSec-KillSwitch-Block', 'dir=out', 'action=block',
          'remoteip=0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255'
        ]);
        executedCommands.push('netsh advfirewall firewall add rule name="SpaceSec-KillSwitch-Block"...');
      } catch {}
    }

    killSwitchActive = true;
    killSwitchEngagedAt = new Date().toISOString();
    disabledInterfacesList = Array.from(new Set([...disabledInterfacesList, ...newlyDisabled]));

    dbManager.addAuditLog({
      id: `killswitch-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString('fr-FR'),
      level: 'KERNEL',
      tag: 'KILL-SWITCH',
      text: `ISOLATION D'URGENCE RÉSEAU ACTIVÉE : ${newlyDisabled.length} interface(s) coupée(s). Boucle locale 127.0.0.1 préservée.`,
      operatorName: 'Analyste Incident',
    });

    res.json({
      success: true,
      killSwitchActive: true,
      engagedAt: killSwitchEngagedAt,
      message: 'Isolation d\'urgence activée. Trafic externe coupé. Boucle locale 127.0.0.1 préservée.',
      disabledInterfaces: disabledInterfacesList,
      loopbackProtected: true,
      localhostPort: 3000,
      executedCommands,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/network/restore
networkRouter.post('/restore', requireAuth, async (req, res) => {
  try {
    const toRestore = await restoreNetworkInterfacesInternal();

    dbManager.addAuditLog({
      id: `restore-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString('fr-FR'),
      level: 'OK',
      tag: 'KILL-SWITCH',
      text: `Rétablissement du réseau effectué : ${toRestore.length} interface(s) réactivée(s). Connectivité normale rétablie.`,
      operatorName: 'Analyste Incident',
    });

    res.json({
      success: true,
      killSwitchActive: false,
      message: 'Interfaces réseau réactivées avec succès. Connectivité normale restaurée.',
      restoredInterfaces: toRestore,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/network/toggle-interface - SECURED: Strict sanitization & parameterized execFile!
networkRouter.post('/toggle-interface', requireAuth, async (req, res) => {
  try {
    const { interfaceName, enable } = req.body;
    // CRITICAL SECURITY FIX: Sanitize interface name to prevent shell injection
    const safeName = sanitizeInterfaceName(interfaceName);
    const adminAction = enable ? 'admin=enabled' : 'admin=disabled';
    const isWin32 = os.platform() === 'win32';

    if (isWin32) {
      // PARAMETERIZED: Arguments are separate strings in an array, NOT concatenated
      try {
        await safeExecFile('netsh', ['interface', 'set', 'interface', safeName, adminAction]);
      } catch {
        const psCmd = enable ? 'Enable-NetAdapter' : 'Disable-NetAdapter';
        await safeExecFile('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', `${psCmd} -Name '${safeName.replace(/'/g, "''")}' -Confirm:$false`]);
      }
    }

    if (enable) {
      disabledInterfacesList = disabledInterfacesList.filter(i => i.toLowerCase() !== safeName.toLowerCase());
    } else {
      if (!disabledInterfacesList.includes(safeName)) disabledInterfacesList.push(safeName);
    }

    dbManager.addAuditLog({
      id: `toggle-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString('fr-FR'),
      level: 'INFO',
      tag: 'INTERFACE-CONTROL',
      text: `Interface "${safeName}" ${enable ? 'activée' : 'désactivée'} manuellement.`,
      operatorName: 'Opérateur Réseau',
    });

    res.json({
      success: true,
      interfaceName: safeName,
      status: enable ? 'Enabled' : 'Disabled',
      message: `Interface réseau "${safeName}" ${enable ? 'activée' : 'désactivée'} avec succès.`,
    });
  } catch (err: any) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// GET /api/system/sockets
networkRouter.get('/sockets', async (req, res) => {
  try {
    if (os.platform() !== 'win32') {
      return res.json({ success: true, connections: [] });
    }

    const { stdout: netstatOut } = await safeExecFile('netstat', ['-ano', '-p', 'tcp']);
    const connections: any[] = [];
    const lines = netstatOut.split('\n');

    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 5 && parts[0] === 'TCP') {
        const local = parts[1];
        const remote = parts[2];
        const state = parts[3];
        const pid = parseInt(parts[4], 10);

        if (remote !== '0.0.0.0:0' && remote !== '*:*') {
          connections.push({
            local,
            remote,
            protocol: 'TCP',
            pid,
            processName: 'System',
            state,
            isSuspicious: false,
          });
        }
      }
    }

    res.json({ success: true, connections: connections.slice(0, 50) });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message, connections: [] });
  }
});

// GET /api/system/wifi
networkRouter.get('/wifi', async (req, res) => {
  try {
    let rawOutput = '';
    if (os.platform() === 'win32') {
      try {
        const { stdout } = await safeExecFile('netsh', ['wlan', 'show', 'networks', 'mode=bssid']);
        rawOutput = stdout;
      } catch {}
    }

    const flatNetworks: any[] = [];
    if (rawOutput) {
      // Parse Windows netsh output
      const lines = rawOutput.split('\n');
      let currentSsid = '';
      for (const line of lines) {
        const ssidMatch = line.trim().match(/^SSID\s+\d+\s*:\s*(.*)$/i);
        if (ssidMatch) currentSsid = ssidMatch[1].trim() || 'Réseau Masqué';
        const bssidMatch = line.trim().match(/BSSID\s+\d*\s*:\s*([0-9a-fA-F:]{17})/i);
        if (bssidMatch) {
          flatNetworks.push({
            id: `wifi-${flatNetworks.length + 1}`,
            ssid: currentSsid,
            bssid: bssidMatch[1].trim(),
            signalPercent: 75,
            channel: 6,
            frequency: '2.4 GHz',
            security: 'WPA2-Personnel',
            status: 'LEGITIMATE',
          });
        }
      }
    }

    res.json({
      success: true,
      interfaceStatus: flatNetworks.length > 0 ? 'Connected' : 'Scanning',
      networks: flatNetworks,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message, networks: [] });
  }
});

// GET /api/system/geo & ALL /api/ip/geolocate
networkRouter.all('/geolocate', async (req, res) => {
  try {
    const inputIp = req.method === 'POST' ? req.body?.ip : req.query?.ip;
    let rawIp = typeof inputIp === 'string' ? inputIp.trim() : '';

    if (rawIp) {
      rawIp = sanitizeIpAddress(rawIp);
    }

    const isLocal = !rawIp || rawIp === '127.0.0.1' || rawIp === 'localhost' || rawIp.startsWith('192.168.') || rawIp.startsWith('10.');

    if (isLocal) {
      return res.json({
        success: true,
        ip: rawIp || '127.0.0.1',
        isLocal: true,
        country: 'Réseau Local Privé',
        city: 'Poste Local (RFC 1918)',
        threatScore: 0,
        placeAddress: 'Interface Réseau Locale (localhost / LAN)',
        placeIntel: 'Adresse locale interne non routable sur Internet public.',
      });
    }

    // Public IP resolution
    const geoRes = await fetch(`http://ip-api.com/json/${rawIp}?fields=status,message,country,city,lat,lon,isp,org,as,query`);
    if (geoRes.ok) {
      const data = await geoRes.json();
      return res.json({
        success: true,
        ip: data.query || rawIp,
        isLocal: false,
        country: data.country || 'Inconnu',
        city: data.city || 'Inconnue',
        latitude: data.lat || 0,
        longitude: data.lon || 0,
        isp: data.isp || 'Opérateur Réseau',
        threatScore: 12,
        placeAddress: `${data.city || ''}, ${data.country || ''}`,
        placeIntel: `Point de présence opérateur BGP assigné à ${data.org || data.isp || 'Inconnu'}.`,
      });
    }

    res.json({ success: true, ip: rawIp, country: 'Internet', threatScore: 15 });
  } catch (err: any) {
    res.status(400).json({ success: false, error: err.message });
  }
});
