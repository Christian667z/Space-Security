import React, { useState, useEffect } from 'react';
import { Network, ShieldAlert, Globe, Server, AlertTriangle, ShieldCheck, RefreshCw, Activity, ArrowUpRight, ArrowDownLeft, Pause, Play, Radio, Lock } from 'lucide-react';
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';
import { NetworkConnectionItem } from '../types/cyberdefense';
import { PortScanner } from './PortScanner';
import { WiFiScanner } from './WiFiScanner';

interface NetworkC2PanelProps {
  onRunInConsole: (command: string) => void;
}

interface TrafficDataPoint {
  time: string;
  inboundBeacon: number;     // KB/s from 185.220.101.4
  outboundExfil: number;     // KB/s to 185.220.101.4
  inboundPowerShell: number; // KB/s from 45.154.255.89
  outboundPowerShell: number;// KB/s to 45.154.255.89
  totalExfiltration: number; // Sum outbound
  isSpike: boolean;
}

export const NetworkC2Panel: React.FC<NetworkC2PanelProps> = ({ onRunInConsole }) => {
  const [connections] = useState<NetworkConnectionItem[]>([
    {
      local: '192.168.1.42:52110',
      remote: '142.250.190.46:443',
      protocol: 'TCP',
      pid: 3880,
      processName: 'chrome.exe',
      state: 'ESTABLISHED',
      isSuspicious: false,
      country: 'US',
      intel: 'Google Services (HTTPS)',
    },
    {
      local: '192.168.1.42:52314',
      remote: '185.220.101.4:4444',
      protocol: 'TCP',
      pid: 5824,
      processName: 'svch0st_updater.exe',
      state: 'ESTABLISHED',
      isSuspicious: true,
      country: 'RU/Tor Exit Node',
      intel: 'Port 4444 typique Metasploit / C2 Cobalt Strike Beaconing',
    },
    {
      local: '192.168.1.42:52410',
      remote: '45.154.255.89:8080',
      protocol: 'TCP',
      pid: 7340,
      processName: 'powershell.exe',
      state: 'ESTABLISHED',
      isSuspicious: true,
      country: 'BG',
      intel: 'Connexion sortante PowerShell vers IP sous surveillance Threat Intel',
    },
    {
      local: '0.0.0.0:135',
      remote: '0.0.0.0:0',
      protocol: 'TCP',
      pid: 1044,
      processName: 'svchost.exe',
      state: 'LISTENING',
      isSuspicious: false,
      intel: 'RPC Endpoint Mapper (Local)',
    },
    {
      local: '0.0.0.0:445',
      remote: '0.0.0.0:0',
      protocol: 'TCP',
      pid: 4,
      processName: 'System',
      state: 'LISTENING',
      isSuspicious: true,
      intel: 'Port SMB 445 ouvert (Risque propagation WannaCry / EternalBlue si SMBv1 actif)',
    },
  ]);

  const namedPipes = [
    { name: '\\\\.\\pipe\\msagent_6812', isSuspicious: true, description: 'Format type Cobalt Strike Beacon Named Pipe' },
    { name: '\\\\.\\pipe\\postex_ssh_412', isSuspicious: true, description: 'Format post-exploitation Metasploit' },
    { name: '\\\\.\\pipe\\lsass', isSuspicious: false, description: 'Tuyau système légitime Local Security Authority' },
    { name: '\\\\.\\pipe\\spoolss', isSuspicious: false, description: 'Spooler d\'impression Windows' },
  ];

  // Real-time Traffic Simulator for Malicious IPs
  const [isLiveActive, setIsLiveActive] = useState<boolean>(true);
  const [selectedTargetIP, setSelectedTargetIP] = useState<string>('all');
  const [trafficHistory, setTrafficHistory] = useState<TrafficDataPoint[]>(() => {
    const initial: TrafficDataPoint[] = [];
    const now = Date.now();
    for (let i = 20; i >= 0; i--) {
      const d = new Date(now - i * 2000);
      const timeStr = d.toTimeString().split(' ')[0];
      const hasSpike = i === 12 || i === 4;
      const outbound = hasSpike ? 240 + Math.floor(Math.random() * 80) : 12 + Math.floor(Math.random() * 25);
      const inbound = hasSpike ? 60 + Math.floor(Math.random() * 30) : 4 + Math.floor(Math.random() * 8);
      const psOut = hasSpike ? 140 + Math.floor(Math.random() * 40) : 5 + Math.floor(Math.random() * 10);
      const psIn = hasSpike ? 35 + Math.floor(Math.random() * 15) : 2 + Math.floor(Math.random() * 6);

      initial.push({
        time: timeStr,
        inboundBeacon: inbound,
        outboundExfil: outbound,
        inboundPowerShell: psIn,
        outboundPowerShell: psOut,
        totalExfiltration: outbound + psOut,
        isSpike: hasSpike,
      });
    }
    return initial;
  });

  // Streaming effect
  useEffect(() => {
    if (!isLiveActive) return;

    const interval = setInterval(() => {
      const now = new Date();
      const timeStr = now.toTimeString().split(' ')[0];

      // Simulate occasional beacon spikes or exfiltration bursts
      const randomSeed = Math.random();
      const isSpike = randomSeed > 0.82;

      const outbound = isSpike
        ? Math.floor(220 + Math.random() * 120)
        : Math.floor(10 + Math.random() * 28);
      const inbound = isSpike
        ? Math.floor(55 + Math.random() * 45)
        : Math.floor(3 + Math.random() * 10);

      const psOut = isSpike
        ? Math.floor(130 + Math.random() * 60)
        : Math.floor(4 + Math.random() * 12);
      const psIn = isSpike
        ? Math.floor(30 + Math.random() * 20)
        : Math.floor(1 + Math.random() * 5);

      const newPoint: TrafficDataPoint = {
        time: timeStr,
        inboundBeacon: inbound,
        outboundExfil: outbound,
        inboundPowerShell: psIn,
        outboundPowerShell: psOut,
        totalExfiltration: outbound + psOut,
        isSpike,
      };

      setTrafficHistory(prev => {
        const next = [...prev.slice(1), newPoint];
        return next;
      });
    }, 2000);

    return () => clearInterval(interval);
  }, [isLiveActive]);

  // Current real-time indicators
  const latestPoint = trafficHistory[trafficHistory.length - 1] || {
    inboundBeacon: 0,
    outboundExfil: 0,
    inboundPowerShell: 0,
    outboundPowerShell: 0,
    totalExfiltration: 0,
  };

  const peakOutbound = Math.max(...trafficHistory.map(p => p.totalExfiltration));

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-2">
              <Network className="w-4 h-4" />
              <span>Surveillance Télémétrie Réseau & C2</span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
              Interception des Sockets Command & Control (C2) & Tuyaux Nommés
            </h2>
            <p className="mt-1 text-sm text-slate-300">
              Traque les connexions persistantes vers des serveurs de contrôle distants, ports sensibles (4444, 445, 3389), pics d'exfiltration et proxies Man-in-the-Middle.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={() => onRunInConsole('sockets')}
              className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-semibold rounded-lg text-xs transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
              <span>Actualiser Sockets</span>
            </button>
            <button
              onClick={() => onRunInConsole('dns-test')}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 font-semibold rounded-lg text-xs transition-colors"
            >
              <Globe className="w-3.5 h-3.5" />
              <span>Tester Vitesse DNS</span>
            </button>
          </div>
        </div>
      </div>

      {/* Real-time Line Chart Section */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-5 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-rose-400" />
              <h3 className="text-base font-bold text-slate-100 font-['Plus_Jakarta_Sans']">
                Surveillance du Trafic en Temps Réel vers les IPs Malveillantes C2
              </h3>
              {isLiveActive && (
                <span className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-rose-950/80 border border-rose-800 text-rose-300 font-mono text-[11px] font-semibold">
                  <Radio className="w-3 h-3 text-rose-400" />
                  <span>FLUX LIVE ACTIF</span>
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400">
              Détection en temps réel des pics d'exfiltration sortants (Upload) et de téléchargement de payloads secondaires (Download).
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {/* Target Filter Segmented Button */}
            <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800 text-xs">
              <button
                onClick={() => setSelectedTargetIP('all')}
                className={`px-2.5 py-1 rounded transition-colors ${
                  selectedTargetIP === 'all'
                    ? 'bg-slate-800 text-cyan-300 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Toutes les IPs C2
              </button>
              <button
                onClick={() => setSelectedTargetIP('beacon')}
                className={`px-2.5 py-1 rounded transition-colors ${
                  selectedTargetIP === 'beacon'
                    ? 'bg-slate-800 text-rose-300 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                185.220.101.4:4444
              </button>
              <button
                onClick={() => setSelectedTargetIP('powershell')}
                className={`px-2.5 py-1 rounded transition-colors ${
                  selectedTargetIP === 'powershell'
                    ? 'bg-slate-800 text-amber-300 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                45.154.255.89:8080
              </button>
            </div>

            {/* Pause / Play Toggle */}
            <button
              onClick={() => setIsLiveActive(prev => !prev)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors"
            >
              {isLiveActive ? (
                <>
                  <Pause className="w-3.5 h-3.5 text-amber-400" />
                  <span>Pause</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Reprendre</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Live Traffic KPI Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
            <div className="flex items-center justify-between text-slate-400 text-[11px]">
              <span className="flex items-center gap-1">
                <ArrowUpRight className="w-3.5 h-3.5 text-rose-400" />
                Exfiltration Sortante
              </span>
              <span className="text-rose-400 font-bold">OUTBOUND</span>
            </div>
            <div className="text-lg font-bold text-rose-400 tabular-nums">
              {latestPoint.totalExfiltration} KB/s
            </div>
            <div className="text-[10px] text-slate-500 font-sans">
              Vol de données / flux vers serveur C2
            </div>
          </div>

          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
            <div className="flex items-center justify-between text-slate-400 text-[11px]">
              <span className="flex items-center gap-1">
                <ArrowDownLeft className="w-3.5 h-3.5 text-cyan-400" />
                Payloads Entrants
              </span>
              <span className="text-cyan-400 font-bold">INBOUND</span>
            </div>
            <div className="text-lg font-bold text-cyan-300 tabular-nums">
              {latestPoint.inboundBeacon + latestPoint.inboundPowerShell} KB/s
            </div>
            <div className="text-[10px] text-slate-500 font-sans">
              Commandes C2 & téléchargement de modules
            </div>
          </div>

          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
            <div className="flex items-center justify-between text-slate-400 text-[11px]">
              <span>Pic Maximal Enregistré</span>
              <span className="text-amber-400 font-bold">SPIKE</span>
            </div>
            <div className="text-lg font-bold text-amber-300 tabular-nums">
              {peakOutbound} KB/s
            </div>
            <div className="text-[10px] text-slate-500 font-sans">
              Seuil critique &gt; 150 KB/s déclenché
            </div>
          </div>

          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
            <div className="flex items-center justify-between text-slate-400 text-[11px]">
              <span>Rythme Beaconing</span>
              <span className="text-purple-400 font-bold">HEARTBEAT</span>
            </div>
            <div className="text-lg font-bold text-purple-300 tabular-nums">
              ~2.0s / 18% Jitter
            </div>
            <div className="text-[10px] text-slate-500 font-sans">
              Périodicité caractéristique Cobalt Strike
            </div>
          </div>
        </div>

        {/* Recharts Responsive Line Chart */}
        <div className="h-72 w-full pt-2">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={trafficHistory} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis
                dataKey="time"
                stroke="#64748b"
                tick={{ fontSize: 11, fontFamily: 'monospace' }}
              />
              <YAxis
                stroke="#64748b"
                tick={{ fontSize: 11, fontFamily: 'monospace' }}
                unit=" KB/s"
                width={70}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#020617',
                  borderColor: '#334155',
                  borderRadius: '0.5rem',
                  fontSize: '12px',
                  fontFamily: 'monospace',
                }}
                labelStyle={{ color: '#94a3b8', fontWeight: 'bold' }}
              />
              <Legend
                wrapperStyle={{
                  paddingTop: '8px',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                }}
              />

              {/* Dynamic Line Rendering based on filter */}
              {(selectedTargetIP === 'all' || selectedTargetIP === 'beacon') && (
                <Line
                  type="monotone"
                  dataKey="outboundExfil"
                  name="185.220.101.4:4444 (Sortant - Swisyn / Cobalt)"
                  stroke="#f43f5e"
                  strokeWidth={2.5}
                  dot={false}
                  activeDot={{ r: 5, fill: '#f43f5e' }}
                  isAnimationActive={false}
                />
              )}

              {(selectedTargetIP === 'all' || selectedTargetIP === 'beacon') && (
                <Line
                  type="monotone"
                  dataKey="inboundBeacon"
                  name="185.220.101.4:4444 (Entrant - Instructions C2)"
                  stroke="#38bdf8"
                  strokeWidth={1.8}
                  strokeDasharray="4 2"
                  dot={false}
                  isAnimationActive={false}
                />
              )}

              {(selectedTargetIP === 'all' || selectedTargetIP === 'powershell') && (
                <Line
                  type="monotone"
                  dataKey="outboundPowerShell"
                  name="45.154.255.89:8080 (Sortant - Exfiltration PowerShell)"
                  stroke="#fbbf24"
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 5, fill: '#fbbf24' }}
                  isAnimationActive={false}
                />
              )}

              {(selectedTargetIP === 'all' || selectedTargetIP === 'powershell') && (
                <Line
                  type="monotone"
                  dataKey="inboundPowerShell"
                  name="45.154.255.89:8080 (Entrant - Script Download)"
                  stroke="#a855f7"
                  strokeWidth={1.5}
                  strokeDasharray="3 3"
                  dot={false}
                  isAnimationActive={false}
                />
              )}
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Spike Warning Bar */}
        {latestPoint.isSpike && (
          <div className="p-3 bg-rose-950/60 border border-rose-800 rounded-lg flex items-center justify-between text-xs text-rose-200">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>
                <strong>Pic d'exfiltration anormal détecté :</strong> Transfert de données volumineux vers l'hôte distant C2 185.220.101.4 ({latestPoint.outboundExfil} KB/s).
              </span>
            </div>
            <button
              onClick={() => onRunInConsole('kill 5824')}
              className="px-3 py-1 bg-rose-600 hover:bg-rose-500 text-white font-semibold rounded text-xs transition-colors shrink-0"
            >
              Couper PID 5824
            </button>
          </div>
        )}
      </div>

      {/* Active Connections Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-400" />
            Connexions Réseau Établies (Get-NetTCPConnection)
          </h3>
          <span className="text-xs text-slate-400">
            {connections.filter(c => c.isSuspicious).length} alerte(s) de sécurité détectée(s)
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4 font-semibold">Processus (PID)</th>
                <th className="py-3 px-4 font-semibold">Adresse Locale</th>
                <th className="py-3 px-4 font-semibold">Adresse Distante (C2)</th>
                <th className="py-3 px-4 font-semibold">État</th>
                <th className="py-3 px-4 font-semibold">Pays / Renseignement Menace</th>
                <th className="py-3 px-4 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {connections.map((conn, idx) => (
                <tr
                  key={idx}
                  className={`transition-colors ${
                    conn.isSuspicious
                      ? 'bg-rose-950/20 hover:bg-rose-950/30'
                      : 'hover:bg-slate-800/40'
                  }`}
                >
                  <td className="py-3 px-4">
                    <div className="font-semibold text-slate-200">
                      {conn.processName}
                    </div>
                    <div className="text-[11px] text-slate-500 tabular-nums">
                      PID: {conn.pid}
                    </div>
                  </td>
                  <td className="py-3 px-4 tabular-nums text-slate-300">
                    {conn.local}
                  </td>
                  <td className="py-3 px-4 tabular-nums">
                    <span className={conn.isSuspicious ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                      {conn.remote}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-sans">
                      {conn.state}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className={conn.isSuspicious ? 'text-rose-300 font-sans' : 'text-slate-400 font-sans'}>
                      {conn.intel}
                    </div>
                    {conn.country && (
                      <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                        Origine: {conn.country}
                      </div>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right">
                    {conn.isSuspicious ? (
                      <button
                        onClick={() => onRunInConsole(`kill ${conn.pid}`)}
                        className="px-2.5 py-1 bg-rose-600 hover:bg-rose-500 text-white rounded text-[11px] font-semibold transition-colors"
                      >
                        Couper Socket
                      </button>
                    ) : (
                      <span className="text-slate-500 text-[11px] font-sans">Normal</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* PortScanner Module: Local Open Ports & Listening Malicious Services */}
      <PortScanner onRunInConsole={onRunInConsole} />

      {/* WiFi Scanner Module: Surrounding Wireless Networks, Unsecured APs & Evil Twin Detection */}
      <WiFiScanner onRunInConsole={onRunInConsole} />

      {/* Lower Row: Named Pipes & HOSTS / Proxy Audit */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Named Pipes */}
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              Named Pipes (Canaux Cobalt Strike)
            </h3>
            <button
              onClick={() => onRunInConsole('pipes-audit')}
              className="text-xs px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded transition-colors"
            >
              Auditer \\.\pipe
            </button>
          </div>
          <p className="text-xs text-slate-400">
            Les frameworks offensifs comme Cobalt Strike et Metasploit communiquent entre processus via des tuyaux nommés :
          </p>
          <div className="space-y-2 text-xs font-mono">
            {namedPipes.map((p, i) => (
              <div
                key={i}
                className={`p-2.5 rounded-lg border flex items-center justify-between ${
                  p.isSuspicious
                    ? 'border-rose-800/60 bg-rose-950/30 text-rose-300'
                    : 'border-slate-800 bg-slate-950/60 text-slate-300'
                }`}
              >
                <div>
                  <div className="font-semibold">{p.name}</div>
                  <div className="text-[11px] font-sans text-slate-400 mt-0.5">{p.description}</div>
                </div>
                {p.isSuspicious && (
                  <span className="text-[10px] uppercase font-bold text-rose-400 bg-rose-950 border border-rose-800 px-1.5 py-0.5 rounded">
                    Menace C2
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* HOSTS & Proxy Integrity */}
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Intégrité Fichier HOSTS & Proxy Système
          </h3>
          <p className="text-xs text-slate-400">
            Certains virus redirigent les domaines d'antivirus vers 127.0.0.1 ou configurent un serveur proxy local pour intercepter tout le trafic chiffré (Man-in-the-Middle) :
          </p>

          <div className="space-y-3 text-xs">
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-200">Fichier C:\Windows\System32\drivers\etc\hosts</div>
                <div className="text-[11px] text-slate-500 mt-0.5">Aucune redirection de virusTotal, Microsoft ou Kaspersky détectée</div>
              </div>
              <span className="text-emerald-400 font-semibold">Propre</span>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-200">Proxy Système (WinHTTP & Internet Settings)</div>
                <div className="text-[11px] text-slate-500 mt-0.5">ProxyEnable = 0, aucun script PAC malveillant</div>
              </div>
              <span className="text-emerald-400 font-semibold">Désactivé (Sûr)</span>
            </div>

            <button
              onClick={() => onRunInConsole('hosts-check')}
              className="w-full text-center py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded font-semibold transition-colors text-xs"
            >
              Exécuter l'analyse d'intégrité HOSTS & Proxy
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
