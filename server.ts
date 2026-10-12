import express from 'express';
import os from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';

const execAsync = promisify(exec);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Helper for CPU calculation across ticks
let prevCpuTimes = os.cpus().map(c => c.times);

function getCpuUsage(): number {
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
  const usage = Math.max(0, Math.min(100, Math.round(((totalDiff - idleDiff) / totalDiff) * 100)));
  return usage;
}

// Initial calculation to seed previous CPU times
getCpuUsage();

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API 1: Live Machine Stats (Task Manager Performance)
  app.get('/api/system/taskmanager', async (req, res) => {
    try {
      const cpus = os.cpus();
      const cpuUsage = getCpuUsage();
      const totalMem = os.totalmem();
      const freeMem = os.freemem();
      const usedMem = totalMem - freeMem;
      const memUsagePercent = Math.round((usedMem / totalMem) * 100);

      const uptimeSec = os.uptime();
      const loadAvg = os.loadavg();

      // Gather live processes
      let processes: any[] = [];
      try {
        if (os.platform() === 'win32') {
          const { stdout } = await execAsync('powershell.exe "Get-Process | Select-Object -First 30 Id, ProcessName, CPU, WorkingSet | ConvertTo-Json"');
          const parsed = JSON.parse(stdout);
          const list = Array.isArray(parsed) ? parsed : [parsed];
          processes = list.map((p: any) => ({
            pid: p.Id,
            name: p.ProcessName || 'Process',
            cpu: Math.round((p.CPU || 0) * 10) / 10,
            ramMb: Math.round((p.WorkingSet || 0) / (1024 * 1024)),
            status: 'Running',
            user: 'SYSTEM',
            isSuspicious: ['mimikatz', 'xmrig', 'swisyn', 'nc', 'meterpreter'].some(k => (p.ProcessName || '').toLowerCase().includes(k)),
          }));
        } else {
          // Linux / Container host
          const { stdout } = await execAsync('ps -eo pid,ppid,%cpu,%mem,comm,args --sort=-%cpu 2>/dev/null | head -n 35');
          const lines = stdout.trim().split('\n').slice(1);
          processes = lines.map(line => {
            const parts = line.trim().split(/\s+/);
            const pid = parseInt(parts[0], 10) || 0;
            const ppid = parseInt(parts[1], 10) || 0;
            const cpu = parseFloat(parts[2]) || 0.0;
            const memPercent = parseFloat(parts[3]) || 0.0;
            const comm = parts[4] || 'app';
            const cmd = parts.slice(5).join(' ') || comm;
            const ramMb = Math.round((memPercent / 100) * (totalMem / (1024 * 1024)));

            return {
              pid,
              ppid,
              name: comm,
              cmd,
              cpu,
              ramMb,
              status: 'Running',
              user: pid < 100 ? 'root' : 'app-user',
              isSuspicious: ['nc', 'miner', 'xmrig', 'swisyn', 'metasploit'].some(k => comm.toLowerCase().includes(k)),
            };
          });
        }
      } catch (procErr) {
        // Fallback simulated list if ps/tasklist fails in restricted environments
        processes = [
          { pid: 1, name: 'systemd / init', cpu: 0.1, ramMb: 12, status: 'Running', user: 'root' },
          { pid: process.pid, name: 'node (SpaceSec Engine)', cpu: Math.round(cpuUsage / 2), ramMb: Math.round(usedMem / (1024 * 1024 * 8)), status: 'Running', user: 'system' },
          { pid: 48, name: 'kthreadd', cpu: 0.0, ramMb: 2, status: 'Running', user: 'kernel' },
        ];
      }

      res.json({
        success: true,
        timestamp: new Date().toISOString(),
        host: {
          hostname: os.hostname(),
          platform: os.platform(),
          release: os.release(),
          arch: os.arch(),
          uptimeSec,
        },
        cpu: {
          usagePercent: cpuUsage,
          model: cpus[0]?.model || 'Processor',
          cores: cpus.length,
          speedMhz: cpus[0]?.speed || 2400,
          loadAvg,
        },
        memory: {
          totalBytes: totalMem,
          usedBytes: usedMem,
          freeBytes: freeMem,
          totalGb: (totalMem / (1024 ** 3)).toFixed(2),
          usedGb: (usedMem / (1024 ** 3)).toFixed(2),
          freeGb: (freeMem / (1024 ** 3)).toFixed(2),
          usagePercent: memUsagePercent,
        },
        processes,
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // API 2: Kill Process (Fin de tâche)
  app.post('/api/system/kill', async (req, res) => {
    const { pid } = req.body;
    if (!pid) {
      return res.status(400).json({ success: false, error: 'PID is required' });
    }

    try {
      if (pid === 1 || pid === process.pid) {
        return res.status(403).json({ success: false, error: 'Impossible de terminer un processus système racine.' });
      }

      if (os.platform() === 'win32') {
        await execAsync(`taskkill /F /PID ${pid}`);
      } else {
        process.kill(Number(pid), 'SIGTERM');
      }

      res.json({ success: true, message: `Processus ${pid} terminé avec succès.` });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Mount Vite middleware in development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[SpaceSec Live Server] Running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
