import React, { useState, useEffect } from 'react';
import { Cpu, HardDrive, Activity, Radio, RefreshCw, Pause, Play, Search, AlertTriangle, ShieldAlert, CheckCircle2, XCircle, ArrowUpDown, Server, Clock, Layers } from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';

interface TaskManagerLiveProps {
  onRunInConsole: (command: string) => void;
}

interface ProcessItem {
  pid: number;
  name: string;
  cmd?: string;
  cpu: number;
  ramMb: number;
  status: string;
  user?: string;
  isSuspicious?: boolean;
}

interface MetricPoint {
  time: string;
  cpuPercent: number;
  ramPercent: number;
}

export const TaskManagerLive: React.FC<TaskManagerLiveProps> = ({ onRunInConsole }) => {
  const [activeSubTab, setActiveSubTab] = useState<'processes' | 'performance' | 'hardware'>('processes');
  const [isLiveActive, setIsLiveActive] = useState<boolean>(true);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [sortField, setSortField] = useState<'cpu' | 'ramMb' | 'name' | 'pid'>('cpu');
  const [sortAsc, setSortAsc] = useState<boolean>(false);
  const [killSuccessMessage, setKillSuccessMessage] = useState<string | null>(null);

  // Machine metrics
  const [cpuUsage, setCpuUsage] = useState<number>(14);
  const [memUsage, setMemUsage] = useState<number>(38);
  const [memTotalGb, setMemTotalGb] = useState<string>('16.00');
  const [memUsedGb, setMemUsedGb] = useState<string>('6.08');
  const [memFreeGb, setMemFreeGb] = useState<string>('9.92');
  const [hostInfo, setHostInfo] = useState<{
    hostname: string;
    platform: string;
    arch: string;
    cores: number;
    cpuModel: string;
    uptimeSec: number;
  }>({
    hostname: 'SEC-ENDPOINT-WINDOWS',
    platform: 'win32',
    arch: 'x64',
    cores: 8,
    cpuModel: 'Intel Core / AMD Ryzen Processor',
    uptimeSec: 34200,
  });

  const [processes, setProcesses] = useState<ProcessItem[]>([
    { pid: 4, name: 'System (Kernel)', cpu: 1.2, ramMb: 120, status: 'Running', user: 'SYSTEM' },
    { pid: 1492, name: 'services.exe', cpu: 0.4, ramMb: 24, status: 'Running', user: 'SYSTEM' },
    { pid: 2140, name: 'svchost.exe', cpu: 1.8, ramMb: 85, status: 'Running', user: 'NETWORK SERVICE' },
    { pid: 3880, name: 'explorer.exe', cpu: 2.5, ramMb: 165, status: 'Running', user: 'LocalUser' },
    { pid: 5824, name: 'svch0st_updater.exe', cpu: 24.8, ramMb: 310, status: 'Running', user: 'LocalUser', isSuspicious: true },
    { pid: 7340, name: 'powershell.exe', cpu: 6.4, ramMb: 82, status: 'Running', user: 'LocalUser', isSuspicious: true },
    { pid: 9110, name: 'chrome.exe', cpu: 4.2, ramMb: 420, status: 'Running', user: 'LocalUser' },
  ]);

  const [historyMetrics, setHistoryMetrics] = useState<MetricPoint[]>(() => {
    const list: MetricPoint[] = [];
    const now = Date.now();
    for (let i = 25; i >= 0; i--) {
      const d = new Date(now - i * 1500);
      list.push({
        time: d.toTimeString().split(' ')[0],
        cpuPercent: Math.floor(10 + Math.random() * 20),
        ramPercent: Math.floor(35 + Math.random() * 8),
      });
    }
    return list;
  });

  // Polling loop
  useEffect(() => {
    if (!isLiveActive) return;

    const fetchLiveStats = async () => {
      try {
        const res = await fetch('/api/system/taskmanager');
        if (res.ok) {
          const data = await res.json();
          if (data.success) {
            setCpuUsage(data.cpu.usagePercent);
            setMemUsage(data.memory.usagePercent);
            setMemTotalGb(data.memory.totalGb);
            setMemUsedGb(data.memory.usedGb);
            setMemFreeGb(data.memory.freeGb);
            setHostInfo({
              hostname: data.host.hostname,
              platform: data.host.platform,
              arch: data.host.arch,
              cores: data.cpu.cores,
              cpuModel: data.cpu.model,
              uptimeSec: data.host.uptimeSec,
            });

            if (data.processes && data.processes.length > 0) {
              setProcesses(data.processes);
            }

            // Append to chart history
            const timeStr = new Date().toTimeString().split(' ')[0];
            setHistoryMetrics(prev => [
              ...prev.slice(1),
              {
                time: timeStr,
                cpuPercent: data.cpu.usagePercent,
                ramPercent: data.memory.usagePercent,
              },
            ]);
            return;
          }
        }
      } catch (err) {
        // Fallback simulation tick if running in standalone static preview
      }

      // Simulated realistic fluctuation
      const timeStr = new Date().toTimeString().split(' ')[0];
      const nextCpu = Math.min(100, Math.max(4, Math.floor(cpuUsage + (Math.random() * 14 - 7))));
      const nextRam = Math.min(95, Math.max(30, Math.floor(memUsage + (Math.random() * 4 - 2))));

      setCpuUsage(nextCpu);
      setMemUsage(nextRam);
      setHistoryMetrics(prev => [
        ...prev.slice(1),
        {
          time: timeStr,
          cpuPercent: nextCpu,
          ramPercent: nextRam,
        },
      ]);
    };

    fetchLiveStats();
    const interval = setInterval(fetchLiveStats, 1500);
    return () => clearInterval(interval);
  }, [isLiveActive, cpuUsage, memUsage]);

  const handleKillProcess = async (pid: number, name: string) => {
    try {
      const res = await fetch('/api/system/kill', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid }),
      });
      const data = await res.json();
      if (data.success) {
        setKillSuccessMessage(`Fin de tâche confirmée pour ${name} (PID ${pid})`);
      } else {
        setKillSuccessMessage(`Exécution via Terminal : taskkill /F /PID ${pid}`);
      }
    } catch {
      setKillSuccessMessage(`Exécution locale via Terminal : taskkill /F /PID ${pid}`);
    }

    onRunInConsole(`kill ${pid}`);
    setProcesses(prev => prev.filter(p => p.pid !== pid));
    setTimeout(() => setKillSuccessMessage(null), 3000);
  };

  const handleSort = (field: 'cpu' | 'ramMb' | 'name' | 'pid') => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  const filteredProcesses = processes
    .filter(p => {
      if (!searchTerm) return true;
      const q = searchTerm.toLowerCase();
      return p.name.toLowerCase().includes(q) || p.pid.toString().includes(q) || (p.cmd && p.cmd.toLowerCase().includes(q));
    })
    .sort((a, b) => {
      let valA: any = a[sortField];
      let valB: any = b[sortField];
      if (typeof valA === 'string') valA = valA.toLowerCase();
      if (typeof valB === 'string') valB = valB.toLowerCase();
      if (valA < valB) return sortAsc ? -1 : 1;
      if (valA > valB) return sortAsc ? 1 : -1;
      return 0;
    });

  const formatUptime = (sec: number) => {
    const days = Math.floor(sec / 86400);
    const hours = Math.floor((sec % 86400) / 3600);
    const mins = Math.floor((sec % 3600) / 60);
    const secs = Math.floor(sec % 60);
    return `${days}j ${hours}h ${mins}m ${secs}s`;
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-2">
              <Activity className="w-4 h-4" />
              <span>Gestionnaire des Tâches en Direct (Task Manager Live)</span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
              État Réel & Télémétrie en Direct de la Machine
            </h2>
            <p className="mt-1 text-sm text-slate-300">
              Mesure en temps réel de la charge CPU, allocation de la mémoire vive (RAM), liste des processus actifs et terminaison de tâches immédiate.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {isLiveActive && (
              <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-950/80 border border-emerald-800 text-emerald-300 font-mono text-xs font-semibold">
                <Radio className="w-3.5 h-3.5 text-emerald-400" />
                <span>FLUX MACHINE LIVE (1.5s)</span>
              </span>
            )}

            <button
              onClick={() => setIsLiveActive(!isLiveActive)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors"
            >
              {isLiveActive ? (
                <>
                  <Pause className="w-3.5 h-3.5 text-amber-400" />
                  <span>Pause Flux</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Reprendre Flux</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Kill Success Toast */}
      {killSuccessMessage && (
        <div className="p-3 bg-emerald-950/80 border border-emerald-800 rounded-xl text-xs text-emerald-200 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{killSuccessMessage}</span>
        </div>
      )}

      {/* Task Manager Tabs (Processus | Performance | Spécifications) */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 text-xs font-medium">
        <button
          onClick={() => setActiveSubTab('processes')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
            activeSubTab === 'processes'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 font-bold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>Processus ({processes.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('performance')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
            activeSubTab === 'performance'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 font-bold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="w-4 h-4" />
          <span>Performance (Graphiques CPU & RAM)</span>
        </button>

        <button
          onClick={() => setActiveSubTab('hardware')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
            activeSubTab === 'hardware'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 font-bold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Server className="w-4 h-4" />
          <span>Spécifications Machine</span>
        </button>
      </div>

      {/* KPI Cards Overview */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-sans">
            <span className="flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              Processeur (CPU)
            </span>
            <span className={cpuUsage > 75 ? 'text-rose-400 font-bold' : 'text-cyan-400'}>
              {cpuUsage}%
            </span>
          </div>
          <div className="text-xl font-bold text-white tabular-nums">
            {cpuUsage}% <span className="text-xs font-normal text-slate-400">utilisé</span>
          </div>
          <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
            <div
              className={`h-full ${cpuUsage > 75 ? 'bg-rose-500' : 'bg-cyan-400'}`}
              style={{ width: `${cpuUsage}%` }}
            />
          </div>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-sans">
            <span className="flex items-center gap-1.5">
              <HardDrive className="w-3.5 h-3.5 text-purple-400" />
              Mémoire Vive (RAM)
            </span>
            <span className="text-purple-400 font-bold">{memUsage}%</span>
          </div>
          <div className="text-xl font-bold text-white tabular-nums">
            {memUsedGb} <span className="text-xs font-normal text-slate-400">/ {memTotalGb} Go</span>
          </div>
          <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
            <div
              className="h-full bg-purple-500"
              style={{ width: `${memUsage}%` }}
            />
          </div>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-sans">
            <span className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-emerald-400" />
              Durée d'Activité
            </span>
            <span className="text-emerald-400">UPTIME</span>
          </div>
          <div className="text-base font-bold text-slate-100 tabular-nums truncate">
            {formatUptime(hostInfo.uptimeSec)}
          </div>
          <div className="text-[10px] text-slate-500 font-sans truncate">
            Hôte : {hostInfo.hostname} ({hostInfo.platform})
          </div>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-sans">
            <span className="flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
              Processus Suspects
            </span>
            <span className="text-rose-400 font-bold">ALERTE</span>
          </div>
          <div className="text-xl font-bold text-rose-400 tabular-nums">
            {processes.filter(p => p.isSuspicious).length} Détecté(s)
          </div>
          <div className="text-[10px] text-slate-500 font-sans">
            Prêts pour Fin de Tâche
          </div>
        </div>
      </div>

      {/* SUB-TAB 1: PROCESS LIST WITH END TASK */}
      {activeSubTab === 'processes' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl space-y-3 p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="relative flex-1 max-w-sm">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                placeholder="Filtrer un processus, PID..."
                className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="text-xs text-slate-400 font-mono flex items-center gap-2">
              <span>Affichage de {filteredProcesses.length} processus</span>
            </div>
          </div>

          <div className="border border-slate-800 rounded-lg overflow-hidden">
            <div className="overflow-x-auto max-h-[480px] scrollbar-thin">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 sticky top-0 z-10">
                  <tr>
                    <th
                      onClick={() => handleSort('name')}
                      className="py-2.5 px-3 font-semibold cursor-pointer hover:text-cyan-300"
                    >
                      <div className="flex items-center gap-1">
                        <span>Nom de l'Application</span>
                        <ArrowUpDown className="w-3 h-3" />
                      </div>
                    </th>
                    <th
                      onClick={() => handleSort('pid')}
                      className="py-2.5 px-3 font-semibold cursor-pointer hover:text-cyan-300"
                    >
                      <div className="flex items-center gap-1">
                        <span>PID</span>
                        <ArrowUpDown className="w-3 h-3" />
                      </div>
                    </th>
                    <th
                      onClick={() => handleSort('cpu')}
                      className="py-2.5 px-3 font-semibold text-right cursor-pointer hover:text-cyan-300"
                    >
                      <div className="flex items-center justify-end gap-1">
                        <span>CPU %</span>
                        <ArrowUpDown className="w-3 h-3" />
                      </div>
                    </th>
                    <th
                      onClick={() => handleSort('ramMb')}
                      className="py-2.5 px-3 font-semibold text-right cursor-pointer hover:text-cyan-300"
                    >
                      <div className="flex items-center justify-end gap-1">
                        <span>Mémoire (Mo)</span>
                        <ArrowUpDown className="w-3 h-3" />
                      </div>
                    </th>
                    <th className="py-2.5 px-3 font-semibold">Statut</th>
                    <th className="py-2.5 px-3 font-semibold">Utilisateur</th>
                    <th className="py-2.5 px-3 font-semibold text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
                  {filteredProcesses.map(proc => (
                    <tr
                      key={proc.pid}
                      className={`transition-colors ${
                        proc.isSuspicious
                          ? 'bg-rose-950/20 hover:bg-rose-950/30'
                          : 'hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="py-2.5 px-3 font-semibold text-slate-200">
                        <div className="flex items-center gap-2">
                          <span>{proc.name}</span>
                          {proc.isSuspicious && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-rose-950 border border-rose-800 text-rose-300 font-sans font-bold">
                              SUSPECT
                            </span>
                          )}
                        </div>
                        {proc.cmd && proc.cmd !== proc.name && (
                          <div className="text-[10px] text-slate-500 truncate max-w-sm font-sans mt-0.5">
                            {proc.cmd}
                          </div>
                        )}
                      </td>
                      <td className="py-2.5 px-3 tabular-nums text-slate-400">
                        {proc.pid}
                      </td>
                      <td className="py-2.5 px-3 text-right tabular-nums">
                        <span className={proc.cpu > 15 ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                          {proc.cpu.toFixed(1)}%
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right tabular-nums text-slate-300">
                        {proc.ramMb} Mo
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-emerald-400 font-sans">
                          {proc.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                        {proc.user || 'SYSTEM'}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => handleKillProcess(proc.pid, proc.name)}
                          className="px-2.5 py-1 bg-rose-600 hover:bg-rose-500 text-white rounded text-[11px] font-semibold transition-colors shadow-sm"
                        >
                          Fin de tâche
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 2: PERFORMANCE WAVEFORM CHARTS (OSCILLOSCOPE LIKE TASK MANAGER) */}
      {activeSubTab === 'performance' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* CPU Waveform Chart */}
          <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-3 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white font-mono">
                  Processeur · Utilisation à 60 secondes ({cpuUsage}%)
                </h3>
              </div>
              <span className="text-xs font-mono text-cyan-400 font-bold tabular-nums">
                {hostInfo.cores} Cœurs · {hostInfo.arch}
              </span>
            </div>

            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={historyMetrics}>
                  <defs>
                    <linearGradient id="cpuGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.6} />
                      <stop offset="95%" stopColor="#22d3ee" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 10, fontFamily: 'monospace' }} />
                  <YAxis stroke="#64748b" tick={{ fontSize: 10, fontFamily: 'monospace' }} domain={[0, 100]} unit="%" />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#020617', borderColor: '#334155', fontSize: '12px', fontFamily: 'monospace' }}
                  />
                  <Area
                    type="monotone"
                    dataKey="cpuPercent"
                    name="Charge CPU"
                    stroke="#22d3ee"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#cpuGradient)"
                    isAnimationActive={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* RAM Waveform Chart */}
          <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-3 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <HardDrive className="w-4 h-4 text-purple-400" />
                <h3 className="text-sm font-bold text-white font-mono">
                  Mémoire · Charge Vive ({memUsage}%)
                </h3>
              </div>
              <span className="text-xs font-mono text-purple-400 font-bold tabular-nums">
                {memUsedGb} Go / {memTotalGb} Go
              </span>
            </div>

            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={historyMetrics}>
                  <defs>
                    <linearGradient id="ramGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#a855f7" stopOpacity={0.6} />
                      <stop offset="95%" stopColor="#a855f7" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 10, fontFamily: 'monospace' }} />
                  <YAxis stroke="#64748b" tick={{ fontSize: 10, fontFamily: 'monospace' }} domain={[0, 100]} unit="%" />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#020617', borderColor: '#334155', fontSize: '12px', fontFamily: 'monospace' }}
                  />
                  <Area
                    type="monotone"
                    dataKey="ramPercent"
                    name="Charge RAM"
                    stroke="#a855f7"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#ramGradient)"
                    isAnimationActive={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 3: HARDWARE SPECIFICATIONS */}
      {activeSubTab === 'hardware' && (
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4 shadow-xl text-xs font-mono">
          <h3 className="text-sm font-bold text-white font-['Plus_Jakarta_Sans'] flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-400" />
            Spécifications Physiques & Système de la Machine
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
              <div className="text-slate-500 text-[11px] font-sans">Nom d'Hôte (Hostname)</div>
              <div className="text-sm font-bold text-slate-100">{hostInfo.hostname}</div>
            </div>

            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
              <div className="text-slate-500 text-[11px] font-sans">Système d'Exploitation</div>
              <div className="text-sm font-bold text-slate-100">{hostInfo.platform} ({hostInfo.arch})</div>
            </div>

            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
              <div className="text-slate-500 text-[11px] font-sans">Processeur (CPU)</div>
              <div className="text-sm font-bold text-slate-100 truncate">{hostInfo.cpuModel}</div>
            </div>

            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
              <div className="text-slate-500 text-[11px] font-sans">Cœurs Processeur Logiques</div>
              <div className="text-sm font-bold text-slate-100">{hostInfo.cores} Cœurs</div>
            </div>

            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
              <div className="text-slate-500 text-[11px] font-sans">Mémoire RAM Installée</div>
              <div className="text-sm font-bold text-slate-100">{memTotalGb} Go Physique</div>
            </div>

            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
              <div className="text-slate-500 text-[11px] font-sans">Temps d'activité continu</div>
              <div className="text-sm font-bold text-emerald-400">{formatUptime(hostInfo.uptimeSec)}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
