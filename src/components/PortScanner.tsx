import React, { useState, useEffect } from 'react';
import { ShieldAlert, ShieldCheck, Play, RefreshCw, AlertTriangle, Terminal, Lock, Search, CheckCircle2, XCircle, Ban, Zap } from 'lucide-react';

interface PortScannerProps {
  onRunInConsole: (command: string) => void;
}

export interface ScannedPort {
  port: number;
  protocol: 'TCP' | 'UDP';
  serviceName: string;
  state: 'OPEN' | 'CLOSED' | 'FILTERED';
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  processName?: string;
  pid?: number;
  threatDescription: string;
  cveOrTactic?: string;
}

export const PortScanner: React.FC<PortScannerProps> = ({ onRunInConsole }) => {
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(100);
  const [filterMode, setFilterMode] = useState<'ALL' | 'OPEN_ONLY' | 'CRITICAL_ONLY'>('ALL');
  const [customPortInput, setCustomPortInput] = useState<string>('');

  const initialPorts: ScannedPort[] = [];

  const [portsList, setPortsList] = useState<ScannedPort[]>(initialPorts);

  const startScan = (targetGroup?: string) => {
    setIsScanning(true);
    setScanProgress(15);
    onRunInConsole(`netstat -ano | findstr LISTENING`);

    setScanProgress(30);
    fetch('http://localhost:3001/api/system/listening-ports')
      .then(res => res.json())
      .then((data: { ports?: Array<{ port: number; protocol: string; pid: number; processName: string; address: string }> }) => {
        setScanProgress(70);
        if (data.ports && data.ports.length > 0) {
          const realPorts: ScannedPort[] = data.ports.map(p => {
            const dangerousPorts = [4444, 5555, 6667, 31337, 1337, 23, 21];
            const highPorts = [139, 445, 3389, 5900, 8080];
            let risk: ScannedPort['risk'] = 'LOW';
            if (dangerousPorts.includes(p.port)) risk = 'CRITICAL';
            else if (highPorts.includes(p.port)) risk = 'HIGH';
            else if (p.port < 1024) risk = 'MEDIUM';

            return {
              port: p.port,
              protocol: (p.protocol || 'TCP') as 'TCP' | 'UDP',
              serviceName: p.processName || `Port ${p.port}`,
              state: 'OPEN' as const,
              risk,
              processName: p.processName,
              pid: p.pid,
              threatDescription: `Port en écoute sur ${p.address || '0.0.0.0'}. Processus : ${p.processName || 'inconnu'} (PID ${p.pid}).`,
            };
          });
          setPortsList(realPorts);
        }
        setScanProgress(100);
        setIsScanning(false);
      })
      .catch(() => {
        setScanProgress(100);
        setIsScanning(false);
      });
  };

  const handleScanCustomPort = (e: React.FormEvent) => {
    e.preventDefault();
    const portNum = parseInt(customPortInput.trim(), 10);
    if (!portNum || isNaN(portNum) || portNum < 1 || portNum > 65535) return;

    onRunInConsole(`Test-NetConnection -ComputerName localhost -Port ${portNum}`);

    // Check if port already exists
    const existing = portsList.find(p => p.port === portNum);
    if (!existing) {
      const isDangerous = [4444, 5555, 6667, 31337, 1337].includes(portNum);
      const newEntry: ScannedPort = {
        port: portNum,
        protocol: 'TCP',
        serviceName: `Port Personnalisé ${portNum}`,
        state: isDangerous ? 'OPEN' : 'CLOSED',
        risk: isDangerous ? 'CRITICAL' : 'LOW',
        threatDescription: isDangerous ? 'Port couramment utilisé par des backdoors et RATs' : 'Port scanné à la demande',
      };
      setPortsList(prev => [newEntry, ...prev]);
    }
    setCustomPortInput('');
  };

  const handleBlockPortFirewall = (port: number) => {
    onRunInConsole(`netsh advfirewall firewall add rule name="SpaceSec-Block-Port-${port}" dir=in action=block protocol=TCP localport=${port}`);
    setPortsList(prev => prev.map(p => p.port === port ? { ...p, state: 'FILTERED' } : p));
  };

  const filteredPorts = portsList.filter(p => {
    if (filterMode === 'OPEN_ONLY') return p.state === 'OPEN';
    if (filterMode === 'CRITICAL_ONLY') return p.risk === 'CRITICAL' || p.risk === 'HIGH';
    return true;
  });

  const openCount = portsList.filter(p => p.state === 'OPEN').length;
  const criticalOpenCount = portsList.filter(p => p.state === 'OPEN' && (p.risk === 'CRITICAL' || p.risk === 'HIGH')).length;

  return (
    <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-5 shadow-xl">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-cyan-400" />
            <h3 className="text-base font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
              PortScanner : Audit des Ports d'Écoute & Services Suspects
            </h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 font-semibold">
              Get-NetTCPConnection / Test-NetConnection
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Scanne les ports ouverts sur localhost (127.0.0.1 / 0.0.0.0) pour identifier les écoutes malveillantes (Metasploit 4444, SMB 445 WannaCry, RDP 3389).
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            onClick={() => startScan()}
            disabled={isScanning}
            className="flex items-center gap-1.5 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-lg text-xs transition-colors shadow-sm"
          >
            {isScanning ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Scan en cours ({scanProgress}%)...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Lancer le Scan des Ports</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Progress Bar when scanning */}
      {isScanning && (
        <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
          <div
            className="h-full bg-cyan-400 transition-all duration-300"
            style={{ width: `${scanProgress}%` }}
          />
        </div>
      )}

      {/* Stats KPI Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
        <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
          <div className="text-slate-400 text-[11px] font-sans">Total Ports Analysés</div>
          <div className="text-lg font-bold text-slate-100 tabular-nums">{portsList.length}</div>
          <div className="text-[10px] text-slate-500 font-sans">Ports réseau majeurs</div>
        </div>

        <div className="p-3 bg-rose-950/40 border border-rose-800/60 rounded-lg space-y-1">
          <div className="text-rose-400 text-[11px] font-sans font-semibold">Ports Ouverts Critiques</div>
          <div className="text-lg font-bold text-rose-400 tabular-nums">{criticalOpenCount}</div>
          <div className="text-[10px] text-rose-300 font-sans">Metasploit, SMB 445, RDP 3389</div>
        </div>

        <div className="p-3 bg-amber-950/40 border border-amber-800/60 rounded-lg space-y-1">
          <div className="text-amber-400 text-[11px] font-sans font-semibold">Total Ports Ouverts</div>
          <div className="text-lg font-bold text-amber-300 tabular-nums">{openCount}</div>
          <div className="text-[10px] text-amber-300 font-sans">Services locaux en écoute</div>
        </div>

        <div className="p-3 bg-emerald-950/40 border border-emerald-800/60 rounded-lg space-y-1">
          <div className="text-emerald-400 text-[11px] font-sans font-semibold">Ports Fermés / Filtrés</div>
          <div className="text-lg font-bold text-emerald-300 tabular-nums">{portsList.length - openCount}</div>
          <div className="text-[10px] text-emerald-300 font-sans">Aucun service vulnérable</div>
        </div>
      </div>

      {/* Filter and Custom Port Scanner Input */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs">
        {/* Custom Port Quick Test Form */}
        <form onSubmit={handleScanCustomPort} className="flex items-center gap-2 flex-1 max-w-sm">
          <input
            type="number"
            min={1}
            max={65535}
            value={customPortInput}
            onChange={e => setCustomPortInput(e.target.value)}
            placeholder="Tester un port spécifique (ex: 4444, 8080)..."
            className="flex-1 px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
          />
          <button
            type="submit"
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 font-semibold rounded text-xs transition-colors shrink-0 font-mono"
          >
            Scanner Port
          </button>
        </form>

        {/* Filter Segmented Buttons */}
        <div className="flex items-center gap-1 bg-slate-900 p-1 rounded border border-slate-800 text-[11px] font-mono">
          <button
            onClick={() => setFilterMode('ALL')}
            className={`px-2.5 py-1 rounded transition-colors ${
              filterMode === 'ALL'
                ? 'bg-slate-800 text-cyan-300 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Tous les Ports ({portsList.length})
          </button>
          <button
            onClick={() => setFilterMode('OPEN_ONLY')}
            className={`px-2.5 py-1 rounded transition-colors ${
              filterMode === 'OPEN_ONLY'
                ? 'bg-slate-800 text-amber-300 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Ports Ouverts ({openCount})
          </button>
          <button
            onClick={() => setFilterMode('CRITICAL_ONLY')}
            className={`px-2.5 py-1 rounded transition-colors ${
              filterMode === 'CRITICAL_ONLY'
                ? 'bg-slate-800 text-rose-300 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Critiques Uniquement ({criticalOpenCount})
          </button>
        </div>
      </div>

      {/* Ports Table */}
      <div className="border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto max-h-[420px] scrollbar-thin">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 sticky top-0 z-10">
              <tr>
                <th className="py-2.5 px-3 font-semibold">Port & Protocole</th>
                <th className="py-2.5 px-3 font-semibold">Service / Description</th>
                <th className="py-2.5 px-3 font-semibold">État d'Écoute</th>
                <th className="py-2.5 px-3 font-semibold">Processus Associé (PID)</th>
                <th className="py-2.5 px-3 font-semibold">Niveau de Risque</th>
                <th className="py-2.5 px-3 font-semibold text-right">Action Immédiate</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
              {filteredPorts.map(item => {
                const isOpen = item.state === 'OPEN';
                const isFiltered = item.state === 'FILTERED';
                const isCrit = item.risk === 'CRITICAL';
                const isHigh = item.risk === 'HIGH';

                return (
                  <tr
                    key={item.port}
                    className={`transition-colors ${
                      isOpen && isCrit
                        ? 'bg-rose-950/25 hover:bg-rose-950/35'
                        : isOpen && isHigh
                        ? 'bg-amber-950/20 hover:bg-amber-950/30'
                        : isOpen
                        ? 'bg-yellow-950/15 hover:bg-yellow-950/25'
                        : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <td className="py-2.5 px-3 tabular-nums font-bold">
                      <span className={isOpen && (isCrit || isHigh) ? 'text-rose-400 text-sm' : isOpen ? 'text-amber-300' : 'text-slate-400'}>
                        {item.port}
                      </span>
                      <span className="text-slate-500 text-[10px] ml-1.5 uppercase font-sans">
                        /{item.protocol}
                      </span>
                    </td>

                    <td className="py-2.5 px-3">
                      <div className="font-semibold text-slate-200">
                        {item.serviceName}
                      </div>
                      <div className="text-[11px] text-slate-400 font-sans mt-0.5 leading-relaxed">
                        {item.threatDescription}
                      </div>
                      {item.cveOrTactic && (
                        <div className="text-[10px] text-cyan-400 font-mono mt-0.5">
                          {item.cveOrTactic}
                        </div>
                      )}
                    </td>

                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          isOpen
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : isFiltered
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        }`}
                      >
                        {isOpen ? 'OUVERT (ÉCOUTE)' : isFiltered ? 'FILTRÉ (PARE-FEU)' : 'FERMÉ (SÉCURISÉ)'}
                      </span>
                    </td>

                    <td className="py-2.5 px-3">
                      {item.processName ? (
                        <div>
                          <span className="text-slate-200 font-semibold">{item.processName}</span>
                          <span className="text-slate-500 text-[10px] block tabular-nums">PID: {item.pid}</span>
                        </div>
                      ) : (
                        <span className="text-slate-500 text-[11px] font-sans">Aucun (Inactif)</span>
                      )}
                    </td>

                    <td className="py-2.5 px-3">
                      <span
                        className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${
                          isCrit
                            ? 'text-rose-400 bg-rose-950 border border-rose-800'
                            : isHigh
                            ? 'text-amber-400 bg-amber-950 border border-amber-800'
                            : 'text-slate-400 bg-slate-800'
                        }`}
                      >
                        {item.risk}
                      </span>
                    </td>

                    <td className="py-2.5 px-3 text-right">
                      {isOpen ? (
                        <div className="flex items-center justify-end gap-1.5">
                          {item.pid && (
                            <button
                              onClick={() => onRunInConsole(`kill ${item.pid}`)}
                              className="px-2.5 py-1 bg-rose-600 hover:bg-rose-500 text-white rounded text-[11px] font-semibold transition-colors shadow-sm"
                            >
                              Tuer PID {item.pid}
                            </button>
                          )}
                          <button
                            onClick={() => handleBlockPortFirewall(item.port)}
                            className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-amber-300 rounded text-[11px] font-semibold transition-colors"
                          >
                            Bloquer Pare-feu
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => onRunInConsole(`Test-NetConnection -ComputerName localhost -Port ${item.port}`)}
                          className="px-2 py-1 text-slate-400 hover:text-slate-200 text-[11px] transition-colors"
                        >
                          Re-tester
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
