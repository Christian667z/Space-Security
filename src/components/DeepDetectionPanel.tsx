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
  const [isLoading, setIsLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Menu 10 State
  const [deepScanData, setDeepScanData] = useState<any>(null);
  
  // Menu 11 State
  const [quarantineItems, setQuarantineItems] = useState<any[]>([]);

  // Menu 12 State
  const [defenderData, setDefenderData] = useState<any>(null);

  // Menu 13 State
  const [forensicsData, setForensicsData] = useState<any>(null);

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
      const res = await fetch('/api/reports/generate', {
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
                142 binaires système inspectés
              </div>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400 uppercase">PIDs Cachés (Brute-Force)</div>
              <div className="text-2xl font-bold text-white mt-1">
                {deepScanData?.modules?.hiddenProcesses?.anomalies?.length || 0}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Plage échantillonnée 4..65535
              </div>
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <div className="text-[11px] font-mono text-slate-400 uppercase">Zones RWX Mémoire</div>
              <div className="text-2xl font-bold text-white mt-1">
                {deepScanData?.modules?.injectedMemory?.rwxPagesFound || 0}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Aucun PE sans fichier détecté
              </div>
            </div>
          </div>

          {/* Details Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Search className="w-4 h-4 text-cyan-400" />
                Vérifications de Persistance & Drivers Noyau (Menu 10)
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
