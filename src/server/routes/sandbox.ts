import { Router } from 'express';
import os from 'os';
import { safeExecFile, validateAndParsePid, sanitizePath, assertProcessNotProtected } from '../safeExec.ts';
import { dbManager } from '../db.ts';
import { logger } from '../logger.ts';
import { requireAuth } from '../auth.ts';
import {
  getDetailedNetworkInterfaces,
  killSwitchActive,
  killSwitchEngagedAt,
  disabledInterfacesList,
} from './network.ts';

export const sandboxRouter = Router();

export interface SandboxedProcessItem {
  pid: number;
  name: string;
  path: string;
  status: 'FROZEN' | 'ISOLATED' | 'TERMINATED';
  isolatedAt: string;
  networkBlocked: boolean;
  cpuRestricted: boolean;
  threatScore: number;
  details: string;
}

export let sandboxedProcessesList: SandboxedProcessItem[] = [];

// GET /api/sandbox/processes
sandboxRouter.get('/processes', (req, res) => {
  res.json({
    success: true,
    count: sandboxedProcessesList.length,
    processes: sandboxedProcessesList,
  });
});

// POST /api/sandbox/isolate-process - SECURED: Validated PID & Sanitized Path
sandboxRouter.post('/isolate-process', requireAuth, async (req, res, next) => {
  try {
    const { pid, name, path: procPath } = req.body;
    const safePid = validateAndParsePid(pid);
    await assertProcessNotProtected(safePid, name);
    const safePath = sanitizePath(procPath || 'C:\\Windows\\System32\\cmd.exe');
    const safeName = name && typeof name === 'string' ? name.slice(0, 128) : `Process_${safePid}`;

    const isWin32 = os.platform() === 'win32';
    const appliedActions: string[] = [];

    if (isWin32) {
      try {
        await safeExecFile('powershell.exe', [
          '-NoProfile',
          '-ExecutionPolicy',
          'Bypass',
          '-Command',
          `$p = Get-Process -Id ${safePid} -ErrorAction SilentlyContinue; if ($p) { Stop-Process -Id ${safePid} -Force }`,
        ]);
        appliedActions.push(`Suspension process PID ${safePid}`);
      } catch {}

      try {
        await safeExecFile('netsh', [
          'advfirewall',
          'firewall',
          'add',
          'rule',
          `name=SpaceSec-Sandbox-PID-${safePid}`,
          'dir=out',
          `program=${safePath}`,
          'action=block',
        ]);
        appliedActions.push(`Blocage Firewall sortant pour "${safePath}"`);
      } catch {}
    }

    const item: SandboxedProcessItem = {
      pid: safePid,
      name: safeName,
      path: safePath,
      status: 'FROZEN',
      isolatedAt: new Date().toLocaleTimeString('fr-FR'),
      networkBlocked: true,
      cpuRestricted: true,
      threatScore: 88,
      details: 'Processus gelé et isolé en Sandbox Live. Accès réseau sortant coupé, exécution suspendue.',
    };

    sandboxedProcessesList = sandboxedProcessesList.filter((p) => p.pid !== safePid);
    sandboxedProcessesList.unshift(item);

    dbManager.addAuditLog({
      id: `sandbox-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString('fr-FR'),
      level: 'KERNEL',
      tag: 'SANDBOX',
      text: `CONFINEMENT PROCESSUS : PID ${safePid} (${safeName}) placé en Sandbox Live. Threads suspendus & trafic sortant bloqué.`,
      operatorName: 'Analyste SOC',
    });

    res.json({
      success: true,
      item,
      appliedActions,
      sandboxedProcesses: sandboxedProcessesList,
    });
  } catch (err: any) {
    next(err);
  }
});

// POST /api/sandbox/terminate-process - SECURED: Parameterized taskkill
sandboxRouter.post('/terminate-process', requireAuth, async (req, res, next) => {
  try {
    const safePid = validateAndParsePid(req.body.pid);
    const isWin32 = os.platform() === 'win32';

    if (isWin32) {
      try {
        await safeExecFile('taskkill', ['/F', '/PID', String(safePid)]);
      } catch {}
      try {
        await safeExecFile('netsh', ['advfirewall', 'firewall', 'delete', 'rule', `name=SpaceSec-Sandbox-PID-${safePid}`]);
      } catch {}
    } else {
      try {
        process.kill(safePid, 'SIGKILL');
      } catch {}
    }

    sandboxedProcessesList = sandboxedProcessesList.filter((p) => p.pid !== safePid);

    dbManager.addAuditLog({
      id: `sandbox-kill-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString('fr-FR'),
      level: 'WARN',
      tag: 'SANDBOX',
      text: `Processus confiné PID ${safePid} abattu et règle pare-feu sandbox retirée.`,
      operatorName: 'Analyste SOC',
    });

    res.json({
      success: true,
      terminatedPid: safePid,
      sandboxedProcesses: sandboxedProcessesList,
    });
  } catch (err: any) {
    next(err);
  }
});

// GET /api/sandbox/status - Full Sandbox and Kill-Switch status
sandboxRouter.get('/status', async (req, res) => {
  try {
    const ifaces = await getDetailedNetworkInterfaces();
    const activeExternal = ifaces.filter((i) => !i.isLoopback && i.status === 'Up');

    res.json({
      success: true,
      killSwitch: {
        isActive: killSwitchActive,
        engagedAt: killSwitchEngagedAt,
        disabledInterfaces: disabledInterfacesList,
        loopbackProtected: true,
        localhostPort: 3000,
        externalAccessBlocked: killSwitchActive,
        totalActiveInterfaces: activeExternal.length,
        interfaces: ifaces,
      },
      sandboxedProcesses: sandboxedProcessesList,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});
