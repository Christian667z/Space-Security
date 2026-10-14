/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import {
  Shield,
  Server,
  Laptop,
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  HardDrive,
  Copy,
  Check,
  Download,
  Terminal,
  RefreshCw,
  Search,
  Filter,
  WifiOff,
  Wifi,
  Trash2,
  X,
  Play,
  Clock,
  Layers,
  ArrowUpRight,
  Radio,
  FileCode,
  Zap,
} from 'lucide-react';
import { EdrEndpoint, EdrTelemetryEvent, EdrCommand } from '../types/cyberdefense';
import { apiFetch } from '../utils/api';

interface EdrFleetManagerProps {
  onRunInConsole?: (cmd: string) => void;
  onAddLog?: (level: 'INFO' | 'WARN' | 'ERROR' | 'OK', text: string, tag?: string) => void;
}

export const EdrFleetManager: React.FC<EdrFleetManagerProps> = ({ onRunInConsole, onAddLog }) => {
  const [endpoints, setEndpoints] = useState<EdrEndpoint[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [selectedEndpointId, setSelectedEndpointId] = useState<string | null>(null);
  const [endpointEvents, setEndpointEvents] = useState<EdrTelemetryEvent[]>([]);
  const [endpointCommands, setEndpointCommands] = useState<EdrCommand[]>([]);
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'CRITICAL' | 'WARNING' | 'ONLINE' | 'ISOLATED'>('ALL');
  
  // Deployment One-Liner state
  const [oneLinerCommand, setOneLinerCommand] = useState<string>('');
  const [copiedOneLiner, setCopiedOneLiner] = useState<boolean>(false);
  const [isDeployModalOpen, setIsDeployModalOpen] = useState<boolean>(false);

  // Command Form State
  const [remotePidToKill, setRemotePidToKill] = useState<string>('');
  const [customPsCommand, setCustomPsCommand] = useState<string>('');
  const [actionSuccessMessage, setActionSuccessMessage] = useState<string>('');
  const [isExecutingAction, setIsExecutingAction] = useState<boolean>(false);

  // Load Endpoints from API
  const fetchEndpoints = async () => {
    try {
      const res = await apiFetch('/api/edr/endpoints');
      if (res.ok) {
        const data = await res.json();
        if (data && data.success && Array.isArray(data.endpoints)) {
          setEndpoints(data.endpoints);
          if (!selectedEndpointId && data.endpoints.length > 0) {
            setSelectedEndpointId(data.endpoints[0].id);
          }
        }
      }
    } catch (err: any) {
      console.warn('[EDR Fleet] Failed to fetch endpoints:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // Load One-Liner deployment command
  const fetchOneLiner = async () => {
    try {
      const res = await apiFetch('/api/edr/oneliner');
      if (res.ok) {
        const data = await res.json();
        if (data && data.success && data.oneLiner) {
          setOneLinerCommand(data.oneLiner);
        }
      }
    } catch {
      const host = window.location.host;
      const proto = window.location.protocol;
      setOneLinerCommand(`powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "irm ${proto}//${host}/api/edr/agent-script | iex"`);
    }
  };

  // Load Single Endpoint Details (Events & Commands)
  const fetchEndpointDetails = async (id: string) => {
    try {
      const res = await apiFetch(`/api/edr/endpoints/${id}`);
      if (res.ok) {
        const data = await res.json();
        if (data && data.success) {
          setEndpointEvents(data.events || []);
          setEndpointCommands(data.commands || []);
        }
      }
    } catch (err) {
      console.warn('[EDR Fleet] Failed to fetch endpoint details:', err);
    }
  };

  useEffect(() => {
    fetchEndpoints();
    fetchOneLiner();
    const interval = setInterval(fetchEndpoints, 8000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (selectedEndpointId) {
      fetchEndpointDetails(selectedEndpointId);
      const detailInterval = setInterval(() => fetchEndpointDetails(selectedEndpointId), 5000);
      return () => clearInterval(detailInterval);
    }
  }, [selectedEndpointId]);

  const handleCopyOneLiner = () => {
    navigator.clipboard.writeText(oneLinerCommand);
    setCopiedOneLiner(true);
    setTimeout(() => setCopiedOneLiner(false), 3000);
  };

  const handleDownloadScript = () => {
    window.open('/api/edr/agent-script?download=true', '_blank');
  };

  const selectedEndpoint = endpoints.find(e => e.id === selectedEndpointId);

  // Toggle Isolation
  const handleToggleIsolate = async (epId: string) => {
    try {
      setIsExecutingAction(true);
      const res = await apiFetch(`/api/edr/endpoints/${epId}/isolate`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        if (data && data.success) {
          setActionSuccessMessage(data.message);
          setTimeout(() => setActionSuccessMessage(''), 4000);
          fetchEndpoints();
          if (selectedEndpointId === epId) fetchEndpointDetails(epId);
          if (onAddLog) onAddLog('WARN', data.message, 'EDR-ISOLATION');
        }
      }
    } catch (err: any) {
      console.error(err);
    } finally {
      setIsExecutingAction(false);
    }
  };

  // Send Remote Command
  const handleSendCommand = async (type: EdrCommand['type'], payload?: any) => {
    if (!selectedEndpointId) return;
    try {
      setIsExecutingAction(true);
      const res = await apiFetch('/api/edr/commands', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          endpointId: selectedEndpointId,
          type,
          payload,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        if (data && data.success) {
          setActionSuccessMessage(`Ordre ${type} émis avec succès.`);
          setTimeout(() => setActionSuccessMessage(''), 4000);
          setRemotePidToKill('');
          setCustomPsCommand('');
          fetchEndpointDetails(selectedEndpointId);
          if (onAddLog) onAddLog('INFO', `Ordre ${type} transmis à l'agent ${selectedEndpoint?.hostname}`, 'EDR-COMMAND');
        }
      }
    } catch (err: any) {
      console.error(err);
    } finally {
      setIsExecutingAction(false);
    }
  };

  // Delete Endpoint
  const handleDeleteEndpoint = async (epId: string) => {
    if (!window.confirm('Confirmer le décommissionnement de cet endpoint de la console SOC ?')) return;
    try {
      await apiFetch(`/api/edr/endpoints/${epId}`, { method: 'DELETE' });
      setEndpoints(prev => prev.filter(e => e.id !== epId));
      if (selectedEndpointId === epId) {
        const remaining = endpoints.filter(e => e.id !== epId);
        setSelectedEndpointId(remaining.length > 0 ? remaining[0].id : null);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Filtered Endpoints
  const filteredEndpoints = endpoints.filter(ep => {
    const matchesSearch =
      ep.hostname.toLowerCase().includes(searchFilter.toLowerCase()) ||
      ep.ipAddress.includes(searchFilter) ||
      ep.osVersion.toLowerCase().includes(searchFilter.toLowerCase());

    if (!matchesSearch) return false;

    if (statusFilter === 'ALL') return true;
    if (statusFilter === 'ISOLATED') return ep.networkIsolated;
    return ep.status === statusFilter;
  });

  // Calculate fleet stats
  const totalFleet = endpoints.length;
  const onlineCount = endpoints.filter(e => e.status === 'ONLINE').length;
  const criticalCount = endpoints.filter(e => e.status === 'CRITICAL').length;
  const warningCount = endpoints.filter(e => e.status === 'WARNING').length;
  const isolatedCount = endpoints.filter(e => e.networkIsolated).length;
  const avgHealthScore = totalFleet > 0
    ? Math.round(endpoints.reduce((acc, e) => acc + e.healthScore, 0) / totalFleet)
    : 100;

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* ========================================================================= */}
      {/* 1. HERO & TOP FLEET KPIs */}
      {/* ========================================================================= */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900/90 to-indigo-950/40 border border-slate-800 p-6 shadow-xl">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-mono font-medium">
              <Radio className="w-3.5 h-3.5 animate-pulse text-cyan-400" />
              CONSOLE DE COMMANDE EDR DISTANTE & GESTION DE FLOTTE
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Flotte Endpoints & Agents de Collecte
            </h1>
            <p className="text-slate-400 text-sm leading-relaxed">
              Surveillance continue en temps réel des postes Windows distants. Ingestion autonome des anomalies de processus,
              sockets C2, altérations de registre et exécution d'ordres de remédiation à distance.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => setIsDeployModalOpen(true)}
              className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-sm flex items-center gap-2 shadow-lg shadow-cyan-900/20 transition-all cursor-pointer"
            >
              <Zap className="w-4 h-4 text-cyan-200" />
              Déployer un Agent Windows
            </button>
            <button
              onClick={handleDownloadScript}
              className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-sm font-medium flex items-center gap-2 transition-all cursor-pointer"
            >
              <Download className="w-4 h-4 text-slate-400" />
              Script Agent .ps1
            </button>
          </div>
        </div>

        {/* Fleet KPI Metric Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mt-6 pt-6 border-t border-slate-800/80">
          <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800/80 flex flex-col">
            <span className="text-xs text-slate-400 uppercase tracking-wider font-mono">Parc Total</span>
            <span className="text-2xl font-bold text-white mt-1">{totalFleet}</span>
            <span className="text-[11px] text-slate-500 mt-0.5">Machines enregistrées</span>
          </div>

          <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800/80 flex flex-col">
            <span className="text-xs text-emerald-400 uppercase tracking-wider font-mono">En Ligne</span>
            <span className="text-2xl font-bold text-emerald-400 mt-1">{onlineCount}</span>
            <span className="text-[11px] text-slate-500 mt-0.5">Connectés & sains</span>
          </div>

          <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800/80 flex flex-col">
            <span className="text-xs text-red-400 uppercase tracking-wider font-mono">Critiques</span>
            <span className="text-2xl font-bold text-red-400 mt-1">{criticalCount}</span>
            <span className="text-[11px] text-red-500/80 mt-0.5">Menaces actives</span>
          </div>

          <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800/80 flex flex-col">
            <span className="text-xs text-amber-400 uppercase tracking-wider font-mono">Avertissements</span>
            <span className="text-2xl font-bold text-amber-400 mt-1">{warningCount}</span>
            <span className="text-[11px] text-slate-500 mt-0.5">Anomalies détectées</span>
          </div>

          <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800/80 flex flex-col">
            <span className="text-xs text-purple-400 uppercase tracking-wider font-mono">Isolés Réseau</span>
            <span className="text-2xl font-bold text-purple-400 mt-1">{isolatedCount}</span>
            <span className="text-[11px] text-slate-500 mt-0.5">Confinements actifs</span>
          </div>

          <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800/80 flex flex-col">
            <span className="text-xs text-cyan-400 uppercase tracking-wider font-mono">Score Posture</span>
            <div className="flex items-baseline gap-1 mt-1">
              <span className={`text-2xl font-bold ${avgHealthScore > 80 ? 'text-emerald-400' : avgHealthScore > 50 ? 'text-amber-400' : 'text-red-400'}`}>
                {avgHealthScore}%
              </span>
            </div>
            <span className="text-[11px] text-slate-500 mt-0.5">Moyenne du parc</span>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 2. QUICK DEPLOYMENT ONE-LINER BANNER */}
      {/* ========================================================================= */}
      <div className="bg-slate-900/80 border border-cyan-900/40 rounded-xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-cyan-950 border border-cyan-800/60 flex items-center justify-center shrink-0">
            <Terminal className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h4 className="text-sm font-semibold text-white flex items-center gap-2">
              Commande de Déploiement Immédiat (PowerShell One-Liner)
              <span className="text-[10px] bg-cyan-950 text-cyan-400 px-2 py-0.5 rounded font-mono border border-cyan-800/40">Windows 10/11 & Server</span>
            </h4>
            <p className="text-xs text-slate-400">
              Copiez et collez cette commande dans une invite PowerShell Administrateur sur n'importe quel poste Windows du réseau d'entreprise.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <div className="bg-slate-950 px-3 py-2 rounded-lg border border-slate-800 font-mono text-xs text-cyan-300 truncate max-w-full md:max-w-md select-all">
            {oneLinerCommand || 'Chargement de la commande...'}
          </div>
          <button
            onClick={handleCopyOneLiner}
            className={`px-3 py-2 rounded-lg font-medium text-xs flex items-center gap-1.5 transition-colors shrink-0 cursor-pointer ${
              copiedOneLiner
                ? 'bg-emerald-600 text-white'
                : 'bg-cyan-600 hover:bg-cyan-500 text-white'
            }`}
          >
            {copiedOneLiner ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            {copiedOneLiner ? 'Copié !' : 'Copier'}
          </button>
        </div>
      </div>

      {/* Action feedback toast */}
      {actionSuccessMessage && (
        <div className="p-3 bg-emerald-950/80 border border-emerald-800/60 rounded-xl text-emerald-300 text-sm flex items-center gap-2 animate-fadeIn">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{actionSuccessMessage}</span>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 3. MAIN WORKSPACE: FLEET LIST (LEFT) & ENDPOINT INSPECTOR (RIGHT) */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Fleet Endpoints Table (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {/* Controls: Search and Filter Tabs */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 flex flex-col sm:flex-row gap-3 items-center justify-between">
            <div className="relative w-full sm:w-64">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchFilter}
                onChange={e => setSearchFilter(e.target.value)}
                placeholder="Filtrer par nom, IP, OS..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Filter Pills */}
            <div className="flex items-center gap-1 overflow-x-auto w-full sm:w-auto">
              {(['ALL', 'CRITICAL', 'WARNING', 'ONLINE', 'ISOLATED'] as const).map(tab => (
                <button
                  key={tab}
                  onClick={() => setStatusFilter(tab)}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium whitespace-nowrap transition-colors cursor-pointer ${
                    statusFilter === tab
                      ? 'bg-slate-800 text-cyan-400 border border-cyan-800/50'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab === 'ALL' && 'Tous'}
                  {tab === 'CRITICAL' && 'Critiques'}
                  {tab === 'WARNING' && 'Alertes'}
                  {tab === 'ONLINE' && 'En ligne'}
                  {tab === 'ISOLATED' && 'Isolés'}
                </button>
              ))}
              <button
                onClick={fetchEndpoints}
                title="Actualiser la liste"
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors ml-1 cursor-pointer"
              >
                <RefreshCw className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Endpoints Cards */}
          <div className="space-y-3">
            {filteredEndpoints.length === 0 ? (
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400 space-y-2">
                <Laptop className="w-10 h-10 mx-auto text-slate-600 mb-2" />
                <p className="font-medium text-slate-300">Aucun endpoint ne correspond aux critères.</p>
                <p className="text-xs text-slate-500">
                  Déployez l'agent sur vos machines Windows via le bouton « Déployer un Agent ».
                </p>
              </div>
            ) : (
              filteredEndpoints.map(ep => {
                const isSelected = ep.id === selectedEndpointId;
                const statusColor =
                  ep.status === 'CRITICAL'
                    ? 'text-red-400 border-red-800/50 bg-red-950/40'
                    : ep.status === 'WARNING'
                    ? 'text-amber-400 border-amber-800/50 bg-amber-950/40'
                    : 'text-emerald-400 border-emerald-800/50 bg-emerald-950/40';

                return (
                  <div
                    key={ep.id}
                    onClick={() => setSelectedEndpointId(ep.id)}
                    className={`rounded-xl border p-4 transition-all cursor-pointer relative ${
                      isSelected
                        ? 'bg-slate-900/95 border-cyan-500/80 shadow-lg shadow-cyan-950/20 ring-1 ring-cyan-500/40'
                        : 'bg-slate-900/60 border-slate-800/80 hover:border-slate-700 hover:bg-slate-900'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-start gap-3">
                        <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 border ${
                          ep.networkIsolated
                            ? 'bg-purple-950 border-purple-800 text-purple-400'
                            : ep.osVersion.toLowerCase().includes('server')
                            ? 'bg-slate-800 border-slate-700 text-slate-300'
                            : 'bg-blue-950 border-blue-800 text-blue-400'
                        }`}>
                          {ep.networkIsolated ? (
                            <WifiOff className="w-5 h-5 text-purple-400" />
                          ) : ep.osVersion.toLowerCase().includes('server') ? (
                            <Server className="w-5 h-5" />
                          ) : (
                            <Laptop className="w-5 h-5" />
                          )}
                        </div>

                        <div>
                          <div className="flex items-center gap-2">
                            <h3 className="font-bold text-white text-base tracking-tight">{ep.hostname}</h3>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium border ${statusColor}`}>
                              {ep.status}
                            </span>
                            {ep.networkIsolated && (
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium border border-purple-800 text-purple-300 bg-purple-950/60 flex items-center gap-1">
                                <WifiOff className="w-2.5 h-2.5" /> ISOLÉ DU RÉSEAU
                              </span>
                            )}
                          </div>

                          <div className="text-xs text-slate-400 mt-1 flex flex-wrap items-center gap-x-3 gap-y-1">
                            <span className="font-mono text-cyan-400">{ep.ipAddress}</span>
                            {ep.publicIp && <span className="font-mono text-slate-500">WAN: {ep.publicIp}</span>}
                            <span>{ep.osVersion}</span>
                          </div>
                        </div>
                      </div>

                      {/* Health Score Badge */}
                      <div className="text-right shrink-0">
                        <div className="text-xs text-slate-400 font-mono">Score Santé</div>
                        <div className={`text-xl font-bold font-mono ${
                          ep.healthScore > 80 ? 'text-emerald-400' : ep.healthScore > 50 ? 'text-amber-400' : 'text-red-400'
                        }`}>
                          {ep.healthScore}/100
                        </div>
                      </div>
                    </div>

                    {/* Performance & Threats Metrics Bar */}
                    <div className="grid grid-cols-3 gap-2 mt-4 pt-3 border-t border-slate-800/60 text-xs">
                      <div className="flex items-center gap-1.5 text-slate-400">
                        <Cpu className="w-3.5 h-3.5 text-slate-500" />
                        <span>CPU : <strong className="text-slate-200">{ep.cpuUsagePercent}%</strong></span>
                      </div>
                      <div className="flex items-center gap-1.5 text-slate-400">
                        <HardDrive className="w-3.5 h-3.5 text-slate-500" />
                        <span>RAM : <strong className="text-slate-200">{ep.ramUsagePercent}%</strong></span>
                      </div>
                      <div className="flex items-center gap-1.5 justify-end">
                        <AlertTriangle className={`w-3.5 h-3.5 ${ep.activeThreatsCount > 0 ? 'text-red-400 animate-pulse' : 'text-slate-500'}`} />
                        <span className={ep.activeThreatsCount > 0 ? 'text-red-400 font-bold' : 'text-slate-400'}>
                          {ep.activeThreatsCount} alerte{ep.activeThreatsCount > 1 ? 's' : ''}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Endpoint Live Telemetry & Remote Remediation Controls (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          {selectedEndpoint ? (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-6 shadow-xl sticky top-20">
              {/* Header with Title and Quick Actions */}
              <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-lg font-bold text-white">{selectedEndpoint.hostname}</h2>
                    <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40">
                      {selectedEndpoint.agentVersion}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Dernier contact : {new Date(selectedEndpoint.lastSeen).toLocaleTimeString('fr-FR')} (Heartbeat OK)
                  </p>
                </div>

                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => handleToggleIsolate(selectedEndpoint.id)}
                    disabled={isExecutingAction}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer ${
                      selectedEndpoint.networkIsolated
                        ? 'bg-purple-900/60 hover:bg-purple-800 text-purple-200 border border-purple-700'
                        : 'bg-red-950/80 hover:bg-red-900 text-red-200 border border-red-800'
                    }`}
                  >
                    {selectedEndpoint.networkIsolated ? <Wifi className="w-3.5 h-3.5" /> : <WifiOff className="w-3.5 h-3.5" />}
                    {selectedEndpoint.networkIsolated ? 'Rétablir Réseau' : 'Isoler Poste'}
                  </button>

                  <button
                    onClick={() => handleDeleteEndpoint(selectedEndpoint.id)}
                    title="Supprimer l'endpoint"
                    className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Remote Remediation Actions Panel */}
              <div className="space-y-3">
                <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5 text-amber-400" />
                  Actions de Remédiation à Distance
                </h3>

                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => handleSendCommand('REPAIR_THEMES')}
                    disabled={isExecutingAction}
                    className="p-2.5 rounded-xl bg-slate-950 hover:bg-slate-800 border border-slate-800 text-left text-xs text-slate-200 transition-colors flex items-center gap-2 cursor-pointer"
                  >
                    <Shield className="w-4 h-4 text-cyan-400 shrink-0" />
                    <div>
                      <div className="font-semibold text-white">Nettoyer Dossier Thèmes</div>
                      <div className="text-[11px] text-slate-400">Purge explorer.exe suspect</div>
                    </div>
                  </button>

                  <button
                    onClick={() => handleSendCommand('SCAN_DEEP')}
                    disabled={isExecutingAction}
                    className="p-2.5 rounded-xl bg-slate-950 hover:bg-slate-800 border border-slate-800 text-left text-xs text-slate-200 transition-colors flex items-center gap-2 cursor-pointer"
                  >
                    <RefreshCw className="w-4 h-4 text-emerald-400 shrink-0" />
                    <div>
                      <div className="font-semibold text-white">Scan Profond EDR</div>
                      <div className="text-[11px] text-slate-400">Audit noyau & registre</div>
                    </div>
                  </button>
                </div>

                {/* Kill PID Input */}
                <div className="flex gap-2">
                  <input
                    type="number"
                    value={remotePidToKill}
                    onChange={e => setRemotePidToKill(e.target.value)}
                    placeholder="Abattre PID distant..."
                    className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 font-mono focus:outline-none focus:border-red-500"
                  />
                  <button
                    onClick={() => {
                      const pid = parseInt(remotePidToKill, 10);
                      if (pid > 0) handleSendCommand('KILL_PROCESS', { pid });
                    }}
                    disabled={!remotePidToKill || isExecutingAction}
                    className="px-3 py-1.5 rounded-lg bg-red-900/60 hover:bg-red-800 text-red-200 text-xs font-medium border border-red-700/60 disabled:opacity-50 transition-colors cursor-pointer"
                  >
                    Kill Process
                  </button>
                </div>

                {/* Custom PowerShell Code */}
                <div className="space-y-1.5 pt-2">
                  <div className="text-[11px] font-mono text-slate-400">Exécuter commande PowerShell distante :</div>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={customPsCommand}
                      onChange={e => setCustomPsCommand(e.target.value)}
                      placeholder='ex: Get-Process | Stop-Service...'
                      className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 font-mono focus:outline-none focus:border-cyan-500"
                    />
                    <button
                      onClick={() => {
                        if (customPsCommand.trim()) {
                          handleSendCommand('CUSTOM_PS', { command: customPsCommand.trim() });
                        }
                      }}
                      disabled={!customPsCommand.trim() || isExecutingAction}
                      className="px-3 py-1.5 rounded-lg bg-cyan-700 hover:bg-cyan-600 text-white text-xs font-medium transition-colors cursor-pointer disabled:opacity-50"
                    >
                      Exécuter
                    </button>
                  </div>
                </div>
              </div>

              {/* Real-time Ingested Telemetry Feed */}
              <div className="space-y-3 pt-2 border-t border-slate-800">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Activity className="w-3.5 h-3.5 text-cyan-400" />
                    Flux de Télémétrie Ingéré ({endpointEvents.length})
                  </h3>
                  <button
                    onClick={() => fetchEndpointDetails(selectedEndpoint.id)}
                    className="text-[11px] text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
                  >
                    <RefreshCw className="w-3 h-3" /> Rafraîchir
                  </button>
                </div>

                <div className="max-h-64 overflow-y-auto space-y-2 pr-1">
                  {endpointEvents.length === 0 ? (
                    <div className="p-4 bg-slate-950/60 rounded-xl text-center text-xs text-slate-500">
                      Aucune alerte de télémétrie reçue pour cet endpoint. La machine est saine.
                    </div>
                  ) : (
                    endpointEvents.map(evt => {
                      const sevColor =
                        evt.severity === 'CRITICAL'
                          ? 'border-red-900/60 bg-red-950/30 text-red-300'
                          : evt.severity === 'HIGH'
                          ? 'border-amber-900/60 bg-amber-950/30 text-amber-300'
                          : 'border-slate-800 bg-slate-950/40 text-slate-300';

                      return (
                        <div key={evt.id} className={`p-2.5 rounded-lg border text-xs space-y-1 ${sevColor}`}>
                          <div className="flex items-center justify-between text-[11px] font-mono">
                            <span className="font-bold flex items-center gap-1.5">
                              <span className={`w-1.5 h-1.5 rounded-full ${evt.severity === 'CRITICAL' ? 'bg-red-400' : 'bg-amber-400'}`} />
                              [{evt.category}]
                            </span>
                            <span className="text-slate-500">{new Date(evt.timestamp).toLocaleTimeString('fr-FR')}</span>
                          </div>
                          <p className="text-slate-200 leading-snug">{evt.summary}</p>
                          {evt.mitreTechnique && (
                            <div className="text-[10px] font-mono text-cyan-400/90">{evt.mitreTechnique}</div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              </div>

              {/* Commands History & Agent Acks */}
              {endpointCommands.length > 0 && (
                <div className="space-y-2 pt-2 border-t border-slate-800">
                  <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                    Ordres Émis & Acquittements ({endpointCommands.length})
                  </h4>
                  <div className="max-h-36 overflow-y-auto space-y-1.5 pr-1 font-mono text-[11px]">
                    {endpointCommands.map(cmd => (
                      <div key={cmd.id} className="p-2 rounded bg-slate-950 border border-slate-800/80 flex items-center justify-between">
                        <div>
                          <span className="text-cyan-400 font-bold">{cmd.type}</span>
                          <span className="text-slate-500 ml-2">ID: {cmd.id.slice(-6)}</span>
                          {cmd.result && <div className="text-slate-400 text-[10px] mt-0.5 truncate max-w-xs">{cmd.result}</div>}
                        </div>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          cmd.status === 'EXECUTED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/40' :
                          cmd.status === 'FAILED' ? 'bg-red-950 text-red-400 border border-red-800/40' :
                          'bg-amber-950 text-amber-400 border border-amber-800/40 animate-pulse'
                        }`}>
                          {cmd.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 text-center text-slate-400">
              <Laptop className="w-12 h-12 mx-auto text-slate-600 mb-2" />
              <p>Sélectionnez un endpoint pour consulter la télémétrie et émettre des ordres de remédiation.</p>
            </div>
          )}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 4. MODAL DE DÉPLOIEMENT D'AGENT EDR */}
      {/* ========================================================================= */}
      {isDeployModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-5 shadow-2xl">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-xl font-bold text-white flex items-center gap-2">
                  <Zap className="w-5 h-5 text-cyan-400" />
                  Déploiement de l'Agent EDR Windows
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Connectez un nouveau poste ou serveur Windows au centre de commande SOC Space Security en 10 secondes.
                </p>
              </div>
              <button
                onClick={() => setIsDeployModalOpen(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Step 1: One Liner */}
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                <span className="w-6 h-6 rounded-full bg-cyan-600 text-white flex items-center justify-center text-xs">1</span>
                Option Recommandée : Commande Immédiate (PowerShell Administrateur)
              </div>
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-cyan-300 break-all select-all flex items-center justify-between gap-3">
                <span>{oneLinerCommand}</span>
                <button
                  onClick={handleCopyOneLiner}
                  className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-sans shrink-0 cursor-pointer"
                >
                  {copiedOneLiner ? 'Copié !' : 'Copier'}
                </button>
              </div>
            </div>

            {/* Step 2: Download file */}
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                <span className="w-6 h-6 rounded-full bg-slate-700 text-white flex items-center justify-center text-xs">2</span>
                Option Script Standalone (.ps1 pour GPO, Intune ou Clé USB)
              </div>
              <p className="text-xs text-slate-400">
                Téléchargez le fichier <code className="text-cyan-300">SpaceSec-Agent.ps1</code> contenant l'agent autonome préconfiguré avec les clés d'ingestion de ce serveur.
              </p>
              <button
                onClick={handleDownloadScript}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-xl text-slate-200 text-xs font-medium flex items-center gap-2 cursor-pointer"
              >
                <Download className="w-4 h-4 text-cyan-400" /> Télécharger SpaceSec-Agent.ps1
              </button>
            </div>

            {/* Security notice */}
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-xl text-[11px] text-slate-400 space-y-1">
              <div className="font-semibold text-slate-300">Notes d'architecture de sécurité :</div>
              <ul className="list-disc list-inside space-y-0.5">
                <li>L'agent fonctionne en mémoire sans installation de pilote tiers instable.</li>
                <li>Toutes les communications vers l'API d'ingestion sont chiffrées HTTPS avec jeton d'authentification Bearer.</li>
                <li>L'agent surveille activement les exclusions Defender illégitimes, le spoofing dans Themes et les balises C2.</li>
              </ul>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setIsDeployModalOpen(false)}
                className="px-5 py-2 bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium rounded-xl transition-colors cursor-pointer"
              >
                Fermer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
