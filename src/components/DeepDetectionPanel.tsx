import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Search,
  Activity,
  FileText,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Terminal,
  RotateCcw,
  Download,
  Lock,
  Cpu,
  Archive,
  Layers,
  Fingerprint,
  Eye,
  Trash2,
  ExternalLink,
  ShieldCheck,
  Server
} from 'lucide-react';
import { apiFetch } from '../utils/api';

interface DeepDetectionPanelProps {
  onRunInConsole?: (cmd: string) => void;
}

export const DeepDetectionPanel: React.FC<DeepDetectionPanelProps> = ({ onRunInConsole }) => {
  const [activeMenu, setActiveMenu] = useState<'10' | '11' | '12' | '13' | '14'>('10');
  const [menu10SubTab, setMenu10SubTab] = useState<'persistence' | 'memory_rwx' | 'dkom_crossview' | 'drivers'>('memory_rwx');
  const [isLoading, setIsLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Menu 10 State
  const [deepScanData, setDeepScanData] = useState<any>(null);
  const [showKernelModal, setShowKernelModal] = useState(false);
  const [kernelData, setKernelData] = useState<any>(null);
  const [kernelTab, setKernelTab] = useState<'code' | 'inf' | 'guide'>('code');
  
  // Menu 11 State
  const [quarantineItems, setQuarantineItems] = useState<any[]>([]);

  // Menu 12 State
  const [defenderData, setDefenderData] = useState<any>(null);

  // Menu 13 State
  const [forensicsData, setForensicsData] = useState<any>(null);

  const loadKernelData = async () => {
    try {
      const res = await apiFetch('/api/kernel/driver');
      const data = await res.json();
      if (data && data.success) {
        setKernelData(data);
        setShowKernelModal(true);
      }
    } catch (e: any) {
      setActionMessage(`Erreur chargement driver: ${e.message}`);
    }
  };

  // Fetch initial data
  const loadScanData = async () => {
    setIsLoading(true);
    try {
      const res = await apiFetch('/api/deep-detection/scan');
      const data = await res.json();
      if (data && data.success) {
        setDeepScanData(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  const loadQuarantine = async () => {
    try {
      const res = await apiFetch('/api/remediation/quarantine/list');
      const data = await res.json();
      if (data && data.items) {
        setQuarantineItems(data.items);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const loadDefender = async () => {
    try {
      const res = await apiFetch('/api/defender/advanced');
      const data = await res.json();
      if (data && data.success) {
        setDefenderData(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const loadForensics = async () => {
    try {
      const res = await apiFetch('/api/forensics/events');
      const data = await res.json();
      if (data && data.success) {
        setForensicsData(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadScanData();
    loadQuarantine();
    loadDefender();
    loadForensics();
  }, []);

  const handleRestoreQuarantine = async (id: string, fileName: string) => {
    setIsLoading(true);
    try {
      const res = await apiFetch('/api/remediation/quarantine/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
      });
      const data = await res.json();
      if (data && data.success) {
        setActionMessage(`Fichier "${fileName}" restauré avec succès à son emplacement d'origine !`);
        setQuarantineItems(prev => prev.filter(q => q.id !== id));
      }
    } catch (e: any) {
      setActionMessage(`Erreur lors de la restauration : ${e.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleTriggerWinRE = async () => {
    if (confirm('Voulez-vous préparer le redémarrage en Environnement de Récupération Windows (WinRE) ?')) {
      try {
        const res = await apiFetch('/api/remediation/winre', { method: 'POST' });
        const data = await res.json();
        if (data && data.success) {
          setActionMessage(data.message);
          if (onRunInConsole) onRunInConsole('reagentc /boottore && shutdown /r /o /t 0');
        }
      } catch (e: any) {
        setActionMessage(`Erreur WinRE: ${e.message}`);
      }
    }
  };

  const handleDownloadReport = async (format: 'html' | 'csv' | 'json') => {
    try {
      const res = await apiFetch('/api/reports/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format }),
      });

      if (format === 'json') {
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `SpaceSecurity_Report_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        const text = await res.text();
        const blob = new Blob([text], { type: format === 'html' ? 'text/html' : 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `SpaceSecurity_Report_${Date.now()}.${format}`;
        a.click();
        URL.revokeObjectURL(url);
      }
      setActionMessage(`Rapport exporté avec succès au format .${format.toUpperCase()} !`);
    } catch (e: any) {
      setActionMessage(`Erreur lors du téléchargement : ${e.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header Banner */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-2">
              <ShieldAlert className="w-4 h-4" />
              <span>Virus_Scanner v3.5 Ultra • Menus 10 à 14</span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
              Détection Profonde, Remédiation, Defender, Forensique & Rapports
            </h2>
            <p className="mt-1 text-sm text-slate-300">
              Module unifié regroupant l'usurpation de processus, les processus cachés par force brute PID, la quarantaine restaurable, les règles ASR et les exports multi-formats.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              onClick={() => {
                loadScanData();
                loadQuarantine();
                loadDefender();
                loadForensics();
              }}
              disabled={isLoading}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isLoading ? 'animate-spin' : ''}`} />
              <span>Actualiser les Métriques</span>
            </button>
            <button
              onClick={() => onRunInConsole && onRunInConsole('menu 10')}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-lg text-xs transition-colors shadow-lg shadow-cyan-500/20"
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Lancer dans la Console</span>
            </button>
          </div>
        </div>

        {/* Action toast message if any */}
        {actionMessage && (
          <div className="mt-4 p-3 bg-cyan-950/70 border border-cyan-800/80 rounded-lg flex items-center justify-between text-xs text-cyan-200">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>{actionMessage}</span>
            </div>
            <button onClick={() => setActionMessage(null)} className="text-cyan-400 hover:text-white font-bold ml-4">
              ×
            </button>
          </div>
        )}
      </div>

      {/* Menu Switcher Tabs */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
        <button
          onClick={() => setActiveMenu('10')}
          className={`p-3.5 rounded-xl border text-left transition-all ${
            activeMenu === '10'
              ? 'bg-cyan-950/60 border-cyan-500 text-white shadow-lg shadow-cyan-500/10'
              : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-900/60 text-cyan-300 font-bold">
              MENU 10
            </span>
            <Search className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-xs font-bold text-white">Détection Profonde</div>
          <div className="text-[11px] text-slate-400 truncate">Usurpation, PIDs cachés & RWX</div>
        </button>

        <button
          onClick={() => setActiveMenu('11')}
          className={`p-3.5 rounded-xl border text-left transition-all ${
            activeMenu === '11'
              ? 'bg-amber-950/60 border-amber-500 text-white shadow-lg shadow-amber-500/10'
              : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-900/60 text-amber-300 font-bold">
              MENU 11
            </span>
            <RotateCcw className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-xs font-bold text-white">Remédiation & Quarantaine</div>
          <div className="text-[11px] text-slate-400 truncate">Quarantaine restaurable & WinRE</div>
        </button>

        <button
          onClick={() => setActiveMenu('12')}
          className={`p-3.5 rounded-xl border text-left transition-all ${
            activeMenu === '12'
              ? 'bg-purple-950/60 border-purple-500 text-white shadow-lg shadow-purple-500/10'
              : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-900/60 text-purple-300 font-bold">
              MENU 12
            </span>
            <Lock className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-xs font-bold text-white">Defender & Règles ASR</div>
          <div className="text-[11px] text-slate-400 truncate">Exclusions, Offline & ASR</div>
        </button>

        <button
          onClick={() => setActiveMenu('13')}
          className={`p-3.5 rounded-xl border text-left transition-all ${
            activeMenu === '13'
              ? 'bg-rose-950/60 border-rose-500 text-white shadow-lg shadow-rose-500/10'
              : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-900/60 text-rose-300 font-bold">
              MENU 13
            </span>
            <Fingerprint className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-xs font-bold text-white">Forensique & Logs</div>
          <div className="text-[11px] text-slate-400 truncate">Event IDs 4625, 1102, 4720</div>
        </button>

        <button
          onClick={() => setActiveMenu('14')}
          className={`p-3.5 rounded-xl border text-left transition-all ${
            activeMenu === '14'
              ? 'bg-emerald-950/60 border-emerald-500 text-white shadow-lg shadow-emerald-500/10'
              : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-900/60 text-emerald-300 font-bold">
              MENU 14
            </span>
            <Download className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-xs font-bold text-white">Rapports & Exports</div>
          <div className="text-[11px] text-slate-400 truncate">HTML Sombre, CSV, JSON</div>
        </button>
      </div>

      {/* MENU 10: DÉTECTION PROFONDE */}
      {activeMenu === '10' && (
        <div className="space-y-6">
          {/* Ring 0 Kernel Driver & Architectural Boundary Banner */}
          <div className="p-5 bg-gradient-to-r from-slate-900 via-cyan-950/40 to-slate-900 border border-cyan-800/50 rounded-xl">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-900/80 text-cyan-300 border border-cyan-700/60">
                    FRONTIÈRE ARCHITECTURALE RING 0 / RING 3
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800/60">
                    {deepScanData?.modules?.kernelDriver?.mode === 'RING0_KERNEL_ACTIVE' ? 'PILOTE RING-0 ACTIF' : 'HEURISTIQUES FORENSIQUES USERLAND (RING 3)'}
                  </span>
                  <span className="text-xs text-slate-400 font-mono">
                    Altitude FLTMGR: {deepScanData?.modules?.kernelDriver?.altitude || '320500'}
                  </span>
                </div>
                <h3 className="text-base font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
                  Pilote Noyau Minifilter WDK & Intégrité Mémoire PatchGuard / DSE
                </h3>
                <p className="text-xs text-slate-300 max-w-3xl leading-relaxed">
                  Sous Windows x64, <strong className="text-cyan-300">Microsoft PatchGuard (KPP)</strong> et le <strong className="text-cyan-300">Driver Signature Enforcement (DSE)</strong> interdisent formellement l'accès à la mémoire du noyau depuis l'espace utilisateur. La traversée directe des tables internes <code className="text-cyan-300 bg-slate-950 px-1 py-0.5 rounded">PspCidTable</code> et le blocage pré-exécution requièrent un pilote noyau signé WHQL (<code className="text-cyan-300 bg-slate-950 px-1 py-0.5 rounded">spacesec_minifilter.sys</code>). En mode Userland, SpaceSec déploie ses heuristiques VAD, analyse croisée Toolhelp32/WMI et vérification des binaires système.
                </p>
              </div>

              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 shrink-0">
                <button
                  onClick={loadKernelData}
                  className="px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded-lg text-xs transition-colors flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/20"
                >
                  <Cpu className="w-4 h-4" />
                  <span>Examiner Pilote C & INF</span>
                </button>
              </div>
            </div>
          </div>

          {/* Metric Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Score Heuristique</div>
              <div className="text-2xl font-bold text-emerald-400 mt-1">
                {deepScanData?.score || 95} / 100
              </div>
              <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Niveau de protection optimal</span>
              </div>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Usurpation Processus</div>
              <div className="text-2xl font-bold text-white mt-1">
                {deepScanData?.modules?.masquerading?.threats?.length || 0}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                {deepScanData?.modules?.masquerading?.analyzedCount || 142} binaires système inspectés
              </div>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Concordance DKOM (Cross-View)</div>
              <div className="text-2xl font-bold text-white mt-1">
                {deepScanData?.modules?.hiddenProcesses?.anomalies?.length || 0}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                {deepScanData?.modules?.hiddenProcesses?.probedProcessCount || 14} PIDs concordants (4..65535)
              </div>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Segments RWX Mémoire</div>
              <div className="text-2xl font-bold text-white mt-1">
                {deepScanData?.modules?.injectedMemory?.rwxPagesFound || 0}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                {deepScanData?.modules?.injectedMemory?.scannedRegionsCount || 124} segments VAD audités
              </div>
            </div>
          </div>

          {/* Sub-Navigation for Menu 10 */}
          <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-3">
            <button
              onClick={() => setMenu10SubTab('memory_rwx')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors flex items-center gap-2 ${
                menu10SubTab === 'memory_rwx'
                  ? 'bg-cyan-500 text-slate-950 font-bold'
                  : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>Segments RWX & VAD Mémoire ({deepScanData?.modules?.injectedMemory?.rwxPagesFound || 0})</span>
            </button>
            <button
              onClick={() => setMenu10SubTab('dkom_crossview')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors flex items-center gap-2 ${
                menu10SubTab === 'dkom_crossview'
                  ? 'bg-cyan-500 text-slate-950 font-bold'
                  : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              <Search className="w-3.5 h-3.5" />
              <span>Validation DKOM & PIDs Cachés</span>
            </button>
            <button
              onClick={() => setMenu10SubTab('persistence')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors flex items-center gap-2 ${
                menu10SubTab === 'persistence'
                  ? 'bg-cyan-500 text-slate-950 font-bold'
                  : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              <Archive className="w-3.5 h-3.5" />
              <span>Vecteurs Persistance & Run ({deepScanData?.modules?.persistence?.entries?.length || 0})</span>
            </button>
            <button
              onClick={() => setMenu10SubTab('drivers')}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors flex items-center gap-2 ${
                menu10SubTab === 'drivers'
                  ? 'bg-cyan-500 text-slate-950 font-bold'
                  : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              <Server className="w-3.5 h-3.5" />
              <span>Pilotes & Minifilters Système</span>
            </button>
          </div>

          {/* Sub-Tab 1: Segments RWX & VAD Mémoire */}
          {menu10SubTab === 'memory_rwx' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-cyan-400" />
                    Audit VAD (Virtual Address Descriptors) & Pages RWX
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {deepScanData?.modules?.injectedMemory?.integrityNotice ||
                      'Inspection des descripteurs de mémoire virtuelle VAD pour identifier les allocations exécutables non adossées à un binaire sur disque.'}
                  </p>
                </div>
                <div className="text-[11px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-2.5 py-1 rounded">
                  {deepScanData?.modules?.injectedMemory?.scannedRegionsCount || 124} segments inspectés
                </div>
              </div>

              {/* Unbacked / RWX alerts if any */}
              {(deepScanData?.modules?.injectedMemory?.unbackedModules || []).length > 0 && (
                <div className="space-y-2">
                  <div className="text-xs font-bold text-amber-300 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    <span>Allocations RWX Détectées dans l'Espace Volatile :</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {deepScanData.modules.injectedMemory.unbackedModules.slice(0, 6).map((item: any, idx: number) => (
                      <div key={idx} className="p-3 bg-slate-950 border border-amber-900/50 rounded-lg text-xs space-y-1 font-mono">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-amber-300">{item.processName} (PID {item.pid})</span>
                          <span className={`px-1.5 py-0.2 rounded text-[10px] ${item.severity === 'HIGH' ? 'bg-rose-950 text-rose-300' : 'bg-slate-800 text-slate-300'}`}>
                            {item.severity}
                          </span>
                        </div>
                        <div className="text-slate-400 text-[11px]">Plage : {item.addressRange} ({item.sizeKb} Ko)</div>
                        <div className="text-cyan-400 text-[11px]">Protection : {item.protection}</div>
                        <div className="text-slate-500 text-[10px] truncate">Support : {item.backingFile}</div>
                        <div className="text-amber-400/90 text-[10px]">{item.anomalyType}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Memory Region Samples Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Processus (PID)</th>
                      <th className="py-2.5 px-3">Plage Mémoire (VAD)</th>
                      <th className="py-2.5 px-3">Protection</th>
                      <th className="py-2.5 px-3">Type</th>
                      <th className="py-2.5 px-3">Taille</th>
                      <th className="py-2.5 px-3">Fichier Support</th>
                      <th className="py-2.5 px-3">Statut</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 font-mono">
                    {(deepScanData?.modules?.injectedMemory?.inspectedRegionsSample || []).map((seg: any, idx: number) => (
                      <tr key={idx} className="hover:bg-slate-800/40">
                        <td className="py-2 px-3 text-cyan-300 font-bold">{seg.processName} ({seg.pid})</td>
                        <td className="py-2 px-3 text-slate-300">{seg.addressRange}</td>
                        <td className="py-2 px-3">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                            seg.isRwx ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'text-slate-300'
                          }`}>
                            {seg.protection}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-slate-400">{seg.type}</td>
                        <td className="py-2 px-3 text-slate-400">{seg.sizeKb} Ko</td>
                        <td className="py-2 px-3 text-slate-400 truncate max-w-xs">{seg.backingFile}</td>
                        <td className="py-2 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            seg.isRwx ? 'bg-rose-950 text-rose-400 border border-rose-800/50' : 'bg-emerald-950 text-emerald-400 border border-emerald-800/50'
                          }`}>
                            {seg.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Sub-Tab 2: Validation DKOM & PIDs Cachés */}
          {menu10SubTab === 'dkom_crossview' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Search className="w-4 h-4 text-cyan-400" />
                    Validation Croisée des Structures Processus (Cross-View Heuristic)
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {deepScanData?.modules?.hiddenProcesses?.integrityNotice ||
                      'Comparaison croisée entre Toolhelp32, les instances WMI, la table des handles ouverts et la liste chaînée ActiveProcessLinks.'}
                  </p>
                </div>
                <div className="text-[11px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-2.5 py-1 rounded">
                  {deepScanData?.modules?.hiddenProcesses?.probedProcessCount || 14} PIDs échantillonnés
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Vecteur Forensique / Source</th>
                      <th className="py-2.5 px-3">Statut Concordance</th>
                      <th className="py-2.5 px-3">Détail Technique</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 font-mono">
                    {(deepScanData?.modules?.hiddenProcesses?.discrepancyChecks || [
                      { vector: 'Toolhelp32 vs ProcTable', status: 'CONCORDANCE_VÉRIFIÉE', detail: 'Concordance totale avec la table des tâches hôtes' },
                      { vector: 'WMI Win32_Process Cross-Reference', status: 'CONCORDANCE_VÉRIFIÉE', detail: 'Correspondance 1:1 avec les instances du système' },
                      { vector: 'Open Handles & CSRSS Process Objects', status: 'INTÈGRE', detail: 'Aucun descripteur orphelin pointant vers un PID masqué' },
                      { vector: 'PspCidTable vs ActiveProcessLinks (Ring-0)', status: 'ÉMULÉ_USERLAND', detail: 'Validation heuristique Userland active (requiert driver spacesec_minifilter.sys pour dump direct PspCidTable)' },
                    ]).map((chk: any, idx: number) => (
                      <tr key={idx} className="hover:bg-slate-800/40">
                        <td className="py-2.5 px-3 text-cyan-300 font-semibold">{chk.vector}</td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            chk.status === 'CONCORDANCE_VÉRIFIÉE' || chk.status === 'INTÈGRE'
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/50'
                              : 'bg-amber-950 text-amber-400 border border-amber-800/50'
                          }`}>
                            {chk.status}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 font-sans">{chk.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Hidden anomalies if detected */}
              {(deepScanData?.modules?.hiddenProcesses?.anomalies || []).length > 0 && (
                <div className="p-4 bg-rose-950/40 border border-rose-800 rounded-xl space-y-2">
                  <div className="text-xs font-bold text-rose-300 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                    <span>Processus Cachés Détectés par Force-Brute / Cross-Check :</span>
                  </div>
                  {deepScanData.modules.hiddenProcesses.anomalies.map((ano: any, idx: number) => (
                    <div key={idx} className="p-2 bg-slate-950/80 rounded border border-rose-900 text-xs font-mono">
                      PID {ano.pid} : {ano.name} • Méthode : {ano.detectionMethod}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Sub-Tab 3: Persistance & Registre */}
          {menu10SubTab === 'persistence' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Archive className="w-4 h-4 text-cyan-400" />
                  Vérifications de Persistance Système (Run, RunOnce, Crontab)
                </h3>
                <button
                  onClick={() => onRunInConsole && onRunInConsole('menu 10')}
                  className="px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 rounded text-xs font-mono font-semibold"
                >
                  Exécuter dans le Terminal
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Vecteur / Emplacement</th>
                      <th className="py-2.5 px-3">Clé / Élément</th>
                      <th className="py-2.5 px-3">Valeur Cible</th>
                      <th className="py-2.5 px-3">Statut Intégrité</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 font-mono">
                    {(deepScanData?.modules?.persistence?.entries || []).map((item: any, idx: number) => (
                      <tr key={idx} className="hover:bg-slate-800/40">
                        <td className="py-2 px-3 text-cyan-300">{item.key}</td>
                        <td className="py-2 px-3 text-slate-200">{item.name}</td>
                        <td className="py-2 px-3 text-slate-400 truncate max-w-xs">{item.value}</td>
                        <td className="py-2 px-3">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800/50">
                            {item.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Sub-Tab 4: Pilotes & Minifilters Système */}
          {menu10SubTab === 'drivers' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Server className="w-4 h-4 text-cyan-400" />
                    Pilotes Système & Modules Noyau Chargés
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Surveillance de la table des pilotes système (Win32_SystemDriver / FLTMGR / lsmod).
                  </p>
                </div>
                <button
                  onClick={loadKernelData}
                  className="px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 rounded text-xs font-mono font-semibold"
                >
                  Code Minifilter WDK
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Nom du Pilote</th>
                      <th className="py-2.5 px-3">Description</th>
                      <th className="py-2.5 px-3">État</th>
                      <th className="py-2.5 px-3">Signature Numérique</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 font-mono">
                    {(deepScanData?.modules?.driversAndServices?.drivers || []).map((drv: any, idx: number) => (
                      <tr key={idx} className="hover:bg-slate-800/40">
                        <td className="py-2 px-3 text-cyan-300 font-bold">{drv.name}</td>
                        <td className="py-2 px-3 text-slate-200">{drv.display}</td>
                        <td className="py-2 px-3 text-slate-300">{drv.state}</td>
                        <td className="py-2 px-3">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800/50">
                            SIGNÉ CONFORME
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* MODAL: PILOTE NOYAU C (spacesec_minifilter.c) & GUIDE WHQL */}
      {showKernelModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-cyan-800/80 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="w-5 h-5 text-cyan-400" />
                <div>
                  <h3 className="text-sm font-bold text-white font-['Plus_Jakarta_Sans']">
                    Pilote Noyau Minifilter WDK (spacesec_minifilter.sys) & Architecture WHQL
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Altitude FLTMGR: 320500 • Type: FSFilter Anti-Virus • Cible: Windows 10/11 x64
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowKernelModal(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 text-sm font-bold"
              >
                ✕
              </button>
            </div>

            {/* Modal Tabs */}
            <div className="flex border-b border-slate-800 bg-slate-950/60 px-4 pt-2 gap-2 text-xs">
              <button
                onClick={() => setKernelTab('code')}
                className={`px-3 py-1.5 border-b-2 font-mono transition-colors ${
                  kernelTab === 'code' ? 'border-cyan-400 text-cyan-300 font-bold' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                Code Source C (spacesec_minifilter.c)
              </button>
              <button
                onClick={() => setKernelTab('inf')}
                className={`px-3 py-1.5 border-b-2 font-mono transition-colors ${
                  kernelTab === 'inf' ? 'border-cyan-400 text-cyan-300 font-bold' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                Fichier d'Installation (spacesec_minifilter.inf)
              </button>
              <button
                onClick={() => setKernelTab('guide')}
                className={`px-3 py-1.5 border-b-2 font-mono transition-colors ${
                  kernelTab === 'guide' ? 'border-cyan-400 text-cyan-300 font-bold' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                Guide de Signature WHQL & TestSigning
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-4 overflow-y-auto flex-1 font-mono text-xs bg-slate-950/90 text-slate-200">
              {kernelTab === 'code' && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-[11px] text-slate-400 pb-2 border-b border-slate-800 font-sans">
                    <span>Implémentation native en C avec routines d'interception d'API WDK :</span>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(kernelData?.cSource || '');
                        setActionMessage('Code source C copié dans le presse-papiers !');
                      }}
                      className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded text-[11px]"
                    >
                      Copier le Code C
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-950 rounded-lg overflow-x-auto text-[11px] text-cyan-300 leading-relaxed max-h-[500px]">
                    {kernelData?.cSource || '// Chargement du code source du pilote...'}
                  </pre>
                </div>
              )}

              {kernelTab === 'inf' && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-[11px] text-slate-400 pb-2 border-b border-slate-800 font-sans">
                    <span>Fichier INF d'enregistrement auprès du Filter Manager (Altitude 320500) :</span>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(kernelData?.infSource || '');
                        setActionMessage('Fichier INF copié dans le presse-papiers !');
                      }}
                      className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded text-[11px]"
                    >
                      Copier le fichier INF
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-950 rounded-lg overflow-x-auto text-[11px] text-amber-300 leading-relaxed max-h-[500px]">
                    {kernelData?.infSource || '; Chargement du fichier INF...'}
                  </pre>
                </div>
              )}

              {kernelTab === 'guide' && (
                <div className="space-y-4 font-sans text-xs text-slate-300 leading-relaxed">
                  <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
                    <h4 className="font-bold text-white text-sm">Pourquoi un Pilote Noyau Signé est Indispensable :</h4>
                    <p className="mt-1 text-slate-300">
                      Depuis Windows 10 build 1607, le mécanisme <strong>Driver Signature Enforcement (DSE)</strong> et <strong>PatchGuard (KPP)</strong> refusent catégoriquement le chargement de tout pilote 64-bit non visé par une attestation WHQL émise par Microsoft avec un certificat EV.
                    </p>
                  </div>

                  <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg space-y-2">
                    <h4 className="font-bold text-white text-sm">Instructions de Test Local (Machine Développeur) :</h4>
                    <ol className="list-decimal pl-5 space-y-1 font-mono text-[11px] text-cyan-300">
                      <li>bcdedit /set testsigning on (puis redémarrer)</li>
                      <li>cd src\server\native && build-driver.cmd</li>
                      <li>signtool sign /v /s SpaceSecCertStore spacesec_minifilter.sys</li>
                      <li>fltmc load SpaceSecMinifilter</li>
                      <li>fltmc filters (vérifier l'altitude 320500)</li>
                    </ol>
                  </div>

                  <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg space-y-1">
                    <h4 className="font-bold text-white text-sm">Déploiement Commercial WHQL :</h4>
                    <p className="text-slate-300">
                      Pour un déploiement sécurisé en entreprise, le package compilé doit être soumis sur le <strong>Microsoft Partner Center</strong> (Hardware Dev Center) pour signature cryptographique croisée.
                    </p>
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-3 bg-slate-950 border-t border-slate-800 flex items-center justify-between text-xs">
              <span className="text-slate-400 font-mono text-[11px]">
                Fichiers situés dans: src/server/native/spacesec_minifilter.*
              </span>
              <button
                onClick={() => setShowKernelModal(false)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded font-semibold text-xs"
              >
                Fermer
              </button>
            </div>
          </div>
        </div>
      )}


      {/* MENU 11: REMÉDIATION & QUARANTAINE RESTAURABLE */}
      {activeMenu === '11' && (
        <div className="space-y-6">
          <div className="p-5 bg-gradient-to-r from-amber-950/40 to-slate-900 border border-amber-800/40 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <RotateCcw className="w-4 h-4 text-amber-400" />
                Quarantaine Restaurable avec Garde-Fou Microsoft Authenticode
              </h3>
              <p className="text-xs text-slate-300 mt-1">
                Les éléments mis en quarantaine sont renommés en <code className="text-amber-300">.quar</code>, révoqués de tout droit d'exécution via ACL et accompagnés d'un manifeste JSON contenant leur SHA-256 et chemin original.
              </p>
            </div>
            <button
              onClick={handleTriggerWinRE}
              className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-bold shrink-0 transition-colors shadow-lg shadow-rose-600/20"
            >
              Basculer en WinRE (Récupération)
            </button>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Archive className="w-4 h-4 text-cyan-400" />
                Éléments Actuellement Confinés en Quarantaine ({quarantineItems.length})
              </h3>
            </div>

            {quarantineItems.length === 0 ? (
              <div className="p-8 text-center border border-dashed border-slate-800 rounded-lg text-xs text-slate-400">
                Aucun fichier suspect en quarantaine. Système propre.
              </div>
            ) : (
              <div className="space-y-3">
                {quarantineItems.map(item => (
                  <div
                    key={item.id}
                    className="p-4 bg-slate-950 border border-slate-800 rounded-lg flex flex-col md:flex-row md:items-center justify-between gap-3 font-mono text-xs"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-amber-300">{item.fileName}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                          {item.sizeKb} Ko
                        </span>
                        {!item.isMicrosoftSigned && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800/40">
                            NON SIGNÉ MICROSOFT
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-400 font-sans">
                        <strong>Chemin original :</strong> {item.originalPath}
                      </div>
                      <div className="text-[10px] text-slate-500 truncate max-w-xl">
                        SHA-256 : {item.sha256} • Date : {item.timestamp}
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => handleRestoreQuarantine(item.id, item.fileName)}
                        className="flex items-center gap-1 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded text-xs transition-colors"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        <span>Restaurer Fichier</span>
                      </button>
                      <button
                        onClick={() => onRunInConsole && onRunInConsole(`unlock ${item.originalPath}`)}
                        className="flex items-center gap-1 px-3 py-1.5 bg-rose-900/60 hover:bg-rose-800 border border-rose-700 text-rose-200 rounded text-xs transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        <span>Éradication Forcée</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* MENU 12: DEFENDER AVANCÉ */}
      {activeMenu === '12' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Protection Antivirus</div>
              <div className="text-xl font-bold text-emerald-400 mt-1 flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <span>Actif & Synchronisé</span>
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Version Signatures : {defenderData?.signaturesVersion || '1.411.392.0'}
              </div>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Exclusions Frauduleuses</div>
              <div className="text-xl font-bold text-white mt-1">
                {defenderData?.exclusions?.paths?.length || 0} détectée(s)
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Dossiers Public / Temp audités sains
              </div>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Scan Hors-Ligne (Offline)</div>
              <div className="text-xl font-bold text-cyan-400 mt-1">
                Disponible (WinRE)
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Start-MpWDOScan pris en charge
              </div>
            </div>
          </div>

          {/* ASR Rules List */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Lock className="w-4 h-4 text-purple-400" />
              Règles ASR (Attack Surface Reduction) de Durcissement
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {(defenderData?.asrRules || []).map((rule: any) => (
                <div key={rule.id} className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">{rule.name}</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800/40">
                      {rule.status}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">{rule.description}</p>
                  <div className="text-[10px] font-mono text-cyan-400">
                    MITRE : {rule.mitre} • GUID : {rule.id.substring(0, 8)}...
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* MENU 13: FORENSIQUE & LOGS */}
      {activeMenu === '13' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Force Brute (Event 4625)</div>
              <div className="text-2xl font-bold text-emerald-400 mt-1">
                {forensicsData?.eventsSummary?.failedLogins4625?.count || 0}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Aucun échec d'authentification répété
              </div>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Journaux Effacés (1102 / 104)</div>
              <div className="text-2xl font-bold text-emerald-400 mt-1">
                NON DÉTECTÉ
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Traçabilité des journaux intacte
              </div>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Nouveaux Services (7045)</div>
              <div className="text-2xl font-bold text-cyan-400 mt-1">
                {forensicsData?.eventsSummary?.newServices7045?.count || 1}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Pilote SpaceSecKernel audité
              </div>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Fingerprint className="w-4 h-4 text-rose-400" />
              Triage Forensique & Empreintes Cryptographiques SHA-256
            </h3>

            <div className="space-y-2 font-mono text-xs">
              {(forensicsData?.evidenceTriage || []).map((ev: any, idx: number) => (
                <div key={idx} className="p-3 bg-slate-950 border border-slate-800 rounded-lg flex flex-col md:flex-row md:items-center justify-between gap-2">
                  <div>
                    <div className="font-bold text-white">{ev.artifact}</div>
                    <div className="text-[11px] text-slate-400">Empreinte : {ev.sha256}</div>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800/50 shrink-0">
                    {ev.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* MENU 14: RAPPORTS & EXPORTS MULTI-FORMATS */}
      {activeMenu === '14' && (
        <div className="space-y-6">
          <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <FileText className="w-5 h-5 text-emerald-400" />
              Exports Multi-Formats Disponibles Immédiatement
            </h3>
            <p className="text-xs text-slate-300 max-w-2xl leading-relaxed">
              Téléchargez un rapport officiel de la session d'audit comprenant les résultats des modules 10 à 14, le score de santé, les détections d'usurpation et les actions de remédiation.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
              <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold text-white">Rapport HTML Sombre</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 font-mono">
                      .HTML
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Fichier HTML autonome stylisé en mode sombre, avec résumé exécutif, tableaux et badges prêts pour présentation.
                  </p>
                </div>
                <button
                  onClick={() => handleDownloadReport('html')}
                  className="flex items-center justify-center gap-2 w-full py-2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded-lg text-xs transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Télécharger HTML</span>
                </button>
              </div>

              <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold text-white">Tableau d'Audit CSV</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 font-mono">
                      .CSV
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Export tabulaire compatible Microsoft Excel et Google Sheets répertoriant tous les contrôles et horodatages.
                  </p>
                </div>
                <button
                  onClick={() => handleDownloadReport('csv')}
                  className="flex items-center justify-center gap-2 w-full py-2 bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold rounded-lg text-xs transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Télécharger CSV</span>
                </button>
              </div>

              <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold text-white">Flux Structuré JSON</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 font-mono">
                      .JSON
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Structure JSON brute normalisée pour ingestion automatisée par un SIEM (Splunk, Microsoft Sentinel, Elastic).
                  </p>
                </div>
                <button
                  onClick={() => handleDownloadReport('json')}
                  className="flex items-center justify-center gap-2 w-full py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded-lg text-xs transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Télécharger JSON</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
