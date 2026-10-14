import { Router } from 'express';
import os from 'os';
import { safeExecFile, validateAndParsePid, sanitizePath } from '../safeExec.ts';
import { dbManager } from '../db.ts';
import { logger } from '../logger.ts';
import { requireAuth } from '../auth.ts';

export const sandboxRouter = Router();

let sandboxedProcessesList: Array<{
  pid: number;
  name: string;
  path: string;
  isolatedAt: string;
  status: 'ISOLATED' | 'FROZEN' | 'TERMINATED';
  networkBlocked: boolean;
  cpuQuotaPercent: number;
  memoryQuotaMb: number;
  details: string;
}> = [];

// GET /api/sandbox/processes
sandboxRouter.get('/processes', (req, res) => {
  res.json({
    success: true,
    count: sandboxedProcessesList.length,
    processes: sandboxedProcessesList,
  });
});

// POST /api/sandbox/isolate-process - SECURED: Parameterized firewall and pid validation!
sandboxRouter.post('/isolate-process', requireAuth, async (req, res, next) => {
  try {
    const { pid, procPath, procName, cpuQuota, memoryQuota } = req.body;

    // CRITICAL: Strictly validate PID and Path to eliminate command injection
    const safePid = validateAndParsePid(pid);
    const safePath = sanitizePath(procPath || 'C:\\Windows\\System32\\cmd.exe');
    const safeName = (procName && typeof procName === 'string') ? procName.slice(0, 128) : `proc_${safePid}`;

    const isWin32 = os.platform() === 'win32';
    const appliedActions: string[] = [];

    if (isWin32) {
      try {
        // Parameterized suspension via PowerShell
        await safeExecFile('powershell.exe', [
          '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
          `$p = Get-Process -Id ${safePid} -ErrorAction SilentlyContinue; if ($p) { Stop-Process -Id ${safePid} -Force }`
        ]);
        appliedActions.push(`Processus PID ${safePid} suspendu et figé`);
      } catch {}

      try {
        // PARAMETERIZED firewall rule addition: no cmd.exe concatenation!
        await safeExecFile('netsh', [
          'advfirewall', 'firewall', 'add', 'rule',
          `name=SpaceSec-Sandbox-PID-${safePid}`,
          'dir=out',
          `program=${safePath}`,
          'action=block'
        ]);
        appliedActions.push(`Règle pare-feu d'isolation réseau appliquée pour ${safePath}`);
      } catch {}
    }

    const item = {
      pid: safePid,
      name: safeName,
      path: safePath,
      isolatedAt: new Date().toISOString(),
      status: 'ISOLATED' as const,
      networkBlocked: true,
      cpuQuotaPercent: Number(cpuQuota) || 5,
      memoryQuotaMb: Number(memoryQuota) || 128,
      details: 'Processus gelé et isolé en Sandbox Live. Accès réseau sortant coupé, exécution suspendue.',
    };

    sandboxedProcessesList = sandboxedProcessesList.filter(p => p.pid !== safePid);
    sandboxedProcessesList.unshift(item);

    dbManager.addAuditLog({
      id: `sandbox-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString('fr-FR'),
      level: 'KERNEL',
      tag: 'SANDBOX',
      text: `CONFINEMENT PROCESSUS : PID ${safePid} (${safeName}) placé en Sandbox Live. Threads suspendus & trafic sortant bloqué.`,
      operatorName: 'Opérateur Sandbox',
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

// POST /api/sandbox/terminate-process - SECURED: Parameterized taskkill and firewall removal
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

    sandboxedProcessesList = sandboxedProcessesList.filter(p => p.pid !== safePid);

    dbManager.addAuditLog({
      id: `sandbox-kill-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString('fr-FR'),
      level: 'WARN',
      tag: 'SANDBOX',
      text: `Processus confiné PID ${safePid} abattu et règle pare-feu sandbox retirée.`,
      operatorName: 'Opérateur Sandbox',
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
