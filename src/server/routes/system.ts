import { Router } from 'express';
import os from 'os';
import { safeExecFile, validateAndParsePid, assertProcessNotProtected } from '../safeExec.ts';
import { dbManager } from '../db.ts';
import { logger } from '../logger.ts';
import { requireAuth } from '../auth.ts';
import { killProcessSchema, validateBody } from '../validators.ts';
import { nativeEngine } from '../native/nativeEngine.ts';

export const systemRouter = Router();

// Helper for CPU calculation across ticks
let prevCpuTimes = os.cpus().map(c => c.times);

export function getCpuUsage(): number {
  const currentCpus = os.cpus();
  let totalDiff = 0;
  let idleDiff = 0;

  currentCpus.forEach((cpu, i) => {
    const prev = prevCpuTimes[i] || cpu.times;
    const current = cpu.times;
    const prevTotal = Object.values(prev).reduce((acc, v) => acc + v, 0);
    const currTotal = Object.values(current).reduce((acc, v) => acc + v, 0);
    totalDiff += currTotal - prevTotal;
    idleDiff += current.idle - prev.idle;
  });

  prevCpuTimes = currentCpus.map(c => c.times);
  if (totalDiff === 0) return 0;
  return Math.max(0, Math.min(100, Math.round(((totalDiff - idleDiff) / totalDiff) * 100)));
}

let customHardwareSpecs: {
  hostname?: string;
  osName?: string;
  cpuModel?: string;
  totalRamGb?: string;
  totalRamBytes?: number;
  cores?: number;
  manufacturer?: string;
} = {};

export async function getWindowsHardwareSpecs(clientTelemetry?: any) {
  let hostname = customHardwareSpecs.hostname || process.env.COMPUTERNAME || '';
  let osName = customHardwareSpecs.osName || (os.platform() === 'win32' ? 'Microsoft Windows 11 Pro 64-bit' : `${os.type()} ${os.release()}`);
  let cpuModel = customHardwareSpecs.cpuModel || '';
  const cores = customHardwareSpecs.cores || clientTelemetry?.cores || os.cpus().length || 4;
  let totalRamBytes = customHardwareSpecs.totalRamBytes || os.totalmem();
  let manufacturer = customHardwareSpecs.manufacturer || (os.platform() === 'win32' ? 'PC Platform' : 'Linux / Virtualized Container');
  const isWin32Native = os.platform() === 'win32';

  if (isWin32Native) {
    if (!hostname || hostname === 'localhost') {
      try {
        const { stdout } = await safeExecFile('hostname', []);
        if (stdout.trim()) hostname = stdout.trim();
      } catch {}
    }

    try {
      const { stdout } = await safeExecFile('reg', ['query', 'HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0', '/v', 'ProcessorNameString']);
      const match = stdout.match(/ProcessorNameString\s+REG_SZ\s+(.+)/i);
      if (match && match[1]?.trim() && !match[1].toLowerCase().includes('unknown')) {
        cpuModel = match[1].trim();
      }
    } catch {}
  } else {
    if (clientTelemetry?.hostname && clientTelemetry.hostname !== 'localhost') {
      hostname = clientTelemetry.hostname;
    } else if (!hostname || hostname === 'localhost') {
      hostname = os.hostname() || 'Poste-Local';
    }

    if (clientTelemetry?.cpuModel && !clientTelemetry.cpuModel.toLowerCase().includes('unknown')) {
      cpuModel = clientTelemetry.cpuModel;
    }

    if (!cpuModel) {
      const nodeCpu = os.cpus()[0]?.model;
      cpuModel = (nodeCpu && nodeCpu !== 'unknown') ? nodeCpu : `Processeur ${cores} cœurs`;
    }

    if (clientTelemetry?.osName) {
      osName = clientTelemetry.osName;
    }
  }

  if (!cpuModel) cpuModel = `Processeur ${cores} cœurs`;
  if (!hostname) hostname = os.hostname() || 'Poste-Local';

  return {
    hostname,
    osName,
    platform: isWin32Native ? 'Microsoft Windows' : 'Linux Kernel',
    kernelRelease: os.release(),
    arch: os.arch(),
    cpuModel,
    cores,
    totalRamBytes,
    totalRamGb: (totalRamBytes / (1024 ** 3)).toFixed(2),
    manufacturer,
    isWin32Native,
  };
}

// GET /api/system/taskmanager
systemRouter.get('/taskmanager', async (req, res) => {
  try {
    const cpus = os.cpus();
    const cpuUsage = getCpuUsage();
    const hwSpecs = await getWindowsHardwareSpecs(req.query);

    const totalMem = hwSpecs.totalRamBytes;
    const freeMem = os.freemem();
    const usedMem = Math.max(0, totalMem - freeMem);
    const memUsagePercent = Math.max(10, Math.min(95, Math.round((usedMem / totalMem) * 100)));

    let processes: any[] = [];
    if (os.platform() === 'win32') {
      try {
        const { stdout } = await safeExecFile('tasklist', ['/fo', 'csv', '/nh']);
        const lines = stdout.split('\n');
        for (const line of lines) {
          const clean = line.replace(/\"/g, '').trim();
          const parts = clean.split(',');
          if (parts.length >= 5) {
            const name = parts[0];
            const pid = parseInt(parts[1], 10);
            const memStr = parts[4].replace(/[^0-9]/g, '');
            const ramMb = Math.round((parseInt(memStr, 10) || 0) / 1024);
            if (!isNaN(pid) && pid > 0) {
              processes.push({
                pid,
                name,
                cpu: 0.0,
                ramMb,
                status: 'Running',
                user: parts[2] || 'SYSTEM',
                isSuspicious: ['mimikatz', 'xmrig', 'c2_beacon', 'darkcomet'].some(k => name.toLowerCase().includes(k)),
              });
            }
          }
        }
      } catch {}
    } else {
      try {
        const { stdout } = await safeExecFile('ps', ['-eo', 'pid,ppid,%cpu,%mem,comm,args', '--sort=-%cpu']);
        const lines = stdout.trim().split('\n').slice(1, 35);
        processes = lines.map(line => {
          const parts = line.trim().split(/\s+/);
          const pid = parseInt(parts[0], 10) || 0;
          const cpu = parseFloat(parts[2]) || 0.0;
          const memPercent = parseFloat(parts[3]) || 0.0;
          const comm = parts[4] || 'app';
          const ramMb = Math.round((memPercent / 100) * (totalMem / (1024 * 1024)));
          return {
            pid,
            name: comm,
            cpu,
            ramMb,
            status: 'Running',
            user: pid < 100 ? 'root' : 'app-user',
            isSuspicious: ['nc', 'miner', 'xmrig', 'swisyn'].some(k => comm.toLowerCase().includes(k)),
          };
        });
      } catch {}
    }

    if (processes.length === 0) {
      processes = [
        { pid: process.pid, name: 'node (SpaceSec Engine)', cpu: cpuUsage, ramMb: 68, status: 'Running', user: 'system' },
      ];
    }

    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      host: hwSpecs,
      cpu: {
        usagePercent: cpuUsage,
        model: hwSpecs.cpuModel,
        cores: hwSpecs.cores,
        speedMhz: cpus[0]?.speed || 3400,
        loadAvg: os.loadavg(),
      },
      memory: {
        totalBytes: totalMem,
        usedBytes: usedMem,
        freeBytes: freeMem,
        totalGb: hwSpecs.totalRamGb,
        usedGb: (usedMem / (1024 ** 3)).toFixed(2),
        freeGb: (freeMem / (1024 ** 3)).toFixed(2),
        usagePercent: memUsagePercent,
      },
      processes: processes.slice(0, 40),
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/system/specs
systemRouter.all('/specs', async (req, res) => {
  try {
    const clientPayload = req.method === 'POST' ? req.body : req.query;
    const specs = await getWindowsHardwareSpecs(clientPayload);
    const cpuUsage = getCpuUsage();
    const freeMem = os.freemem();
    const usedMem = Math.max(0, specs.totalRamBytes - freeMem);

    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      specs: {
        ...specs,
        cpuUsagePercent: cpuUsage,
        ramUsedGb: (usedMem / (1024 ** 3)).toFixed(2),
        ramFreeGb: (freeMem / (1024 ** 3)).toFixed(2),
        ramUsagePercent: Math.round((usedMem / specs.totalRamBytes) * 100),
        uptimeSec: os.uptime(),
      },
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/system/specs/sync
systemRouter.post('/specs/sync', async (req, res) => {
  try {
    const payload = req.body || {};
    if (payload.hostname && payload.hostname !== 'localhost') customHardwareSpecs.hostname = String(payload.hostname).trim();
    if (payload.osName) customHardwareSpecs.osName = String(payload.osName).trim();
    if (payload.cpuModel) customHardwareSpecs.cpuModel = String(payload.cpuModel).trim();
    if (payload.cores) customHardwareSpecs.cores = Number(payload.cores);
    if (payload.totalRamGb) {
      const gb = Number(payload.totalRamGb);
      if (!isNaN(gb) && gb > 0) {
        customHardwareSpecs.totalRamBytes = gb * (1024 ** 3);
        customHardwareSpecs.totalRamGb = gb.toFixed(2);
      }
    }
    const updated = await getWindowsHardwareSpecs(customHardwareSpecs);
    res.json({ success: true, message: 'Spécifications synchronisées.', specs: updated });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/system/kill - SECURED: Parameterized execFile without shell injection!
systemRouter.post('/kill', requireAuth, validateBody(killProcessSchema), async (req, res, next) => {
  try {
    const safePid = validateAndParsePid(req.body.pid);
    const procName = await assertProcessNotProtected(safePid, req.body.name);

    logger.warn({ pid: safePid, procName, ip: req.ip }, '[SystemControl] Ordre sécurisé de fin de tâche (taskkill)');

    if (os.platform() === 'win32') {
      // PARAMETERIZED: No cmd.exe shell invocation, impossible to inject & calc.exe!
      await safeExecFile('taskkill.exe', ['/F', '/PID', String(safePid)]);
    } else {
      process.kill(safePid, 'SIGTERM');
    }

    dbManager.addAuditLog({
      id: `log-kill-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString('fr-FR'),
      level: 'WARN',
      tag: 'TASKKILL',
      text: `Processus ${procName} (PID ${safePid}) neutralisé avec succès (paramétré taskkill /F /PID ${safePid}).`,
      operatorName: 'Analyste SOC',
    });

    res.json({ success: true, message: `Processus ${procName} (PID ${safePid}) terminé avec succès.` });
  } catch (err: any) {
    if (err.message && (err.message.includes('protégé') || err.message.includes('critique'))) {
      return res.status(403).json({ success: false, error: err.message });
    }
    next(err);
  }
});

// GET /api/system/memory/vad (or /api/memory/vad)
systemRouter.get('/memory/vad', async (req, res, next) => {
  try {
    const memAudit = await nativeEngine.auditInjectedMemory();
    const regions = memAudit.inspectedRegionsSample || [];
    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      regions,
      totalRegionsCount: memAudit.scannedRegionsCount || regions.length,
      unbackedModules: memAudit.unbackedModules || [],
      rwxPagesFound: memAudit.rwxPagesFound || 0,
      scannedProcessesCount: memAudit.scannedProcessesCount || 0,
    });
  } catch (err) {
    next(err);
  }
});
