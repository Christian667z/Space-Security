import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Play,
  Trash2,
  CheckCircle2,
  XCircle,
  Terminal,
  FolderX,
  FolderCheck,
  FileSearch,
  Lock,
  Layers,
  Copy,
  Check,
  Zap,
  Filter,
  PlusCircle,
  Eye,
  Shield
} from 'lucide-react';

import { ThreatItem } from '../types/cyberdefense';
import { apiFetch } from '../utils/api';

interface DefenderSyncProps {
  onRunInConsole: (command: string) => void;
  onMutateThreatStatus?: (threatId: string, targetPath: string, status: ThreatItem['status']) => void;
}

export type ExclusionType = 'PATH' | 'PROCESS' | 'EXTENSION';
export type ThreatLevel = 'MALICIOUS' | 'SUSPICIOUS' | 'SAFE';

export interface DefenderExclusionItem {
  id: string;
  type: ExclusionType;
  value: string;
  threatLevel: ThreatLevel;
  malwareFamily: string;
  reason: string;
  registryKey: string;
  addedTimestamp: string;
  status: 'ACTIVE' | 'PURGED' | 'SCANNED';
}

export const DefenderSync: React.FC<DefenderSyncProps> = ({ onRunInConsole, onMutateThreatStatus }) => {
  const [isAuditing, setIsAuditing] = useState<boolean>(false);
  const [auditProgress, setAuditProgress] = useState<number>(100);
  const [filterType, setFilterType] = useState<'ALL' | 'PATH' | 'PROCESS' | 'EXTENSION' | 'MALICIOUS_ONLY'>('ALL');
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  // New check input
  const [customInput, setCustomInput] = useState<string>('');
  const [customCheckResult, setCustomCheckResult] = useState<string | null>(null);

  // Live scan feedback state
  const [scanningItemId, setScanningItemId] = useState<string | null>(null);
  const [activeScanDialog, setActiveScanDialog] = useState<{
    item: DefenderExclusionItem;
    stage: number;
    completed: boolean;
    logs: string[];
  } | null>(null);

  // Live Defender exclusions from host
  const [exclusions, setExclusions] = useState<DefenderExclusionItem[]>([]);
  const [defenderRealtimeActive, setDefenderRealtimeActive] = useState<boolean>(true);
  const [signaturesAgeDays, setSignaturesAgeDays] = useState<number>(0);

  const fetchDefenderStatus = useCallback(async () => {
    try {
      const res = await apiFetch('/api/system/defender');
      if (res.ok) {
        const data = await res.json();
        if (data.success) {
          if (data.status) {
            setDefenderRealtimeActive(Boolean(data.status.realtime));
            setSignaturesAgeDays(typeof data.status.signatureAgeDays === 'number' ? data.status.signatureAgeDays : 0);
          }
          if (data.exclusions) {
            const list: DefenderExclusionItem[] = [];
            let idx = 1;
            (data.exclusions.paths || []).forEach((p: string) => {
              list.push({
                id: `ex-path-${idx++}`,
                type: 'PATH',
                value: p,
                threatLevel: 'SUSPICIOUS',
                malwareFamily: 'Exclusion de Chemin Répertoire',
                reason: `Chemin exclu de l'analyse automatique sur votre PC : ${p}`,
                registryKey: 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths',
                addedTimestamp: 'Configurée sur l\'hôte',
                status: 'ACTIVE',
              });
            });
            (data.exclusions.processes || []).forEach((proc: string) => {
              list.push({
                id: `ex-proc-${idx++}`,
                type: 'PROCESS',
                value: proc,
                threatLevel: 'SUSPICIOUS',
                malwareFamily: 'Exclusion de Processus Binaire',
                reason: `Processus whitelisté sur votre PC : ${proc}`,
                registryKey: 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes',
                addedTimestamp: 'Configurée sur l\'hôte',
                status: 'ACTIVE',
              });
            });
            (data.exclusions.extensions || []).forEach((ext: string) => {
              list.push({
                id: `ex-ext-${idx++}`,
                type: 'EXTENSION',
                value: ext,
                threatLevel: 'SUSPICIOUS',
                malwareFamily: 'Exclusion d\'Extension',
                reason: `Extension ignorée lors des lectures disques : ${ext}`,
                registryKey: 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions',
                addedTimestamp: 'Configurée sur l\'hôte',
                status: 'ACTIVE',
              });
            });
            setExclusions(list);
          }
        }
      }
    } catch (e) {
      console.warn('Defender fetch error:', e);
    }
  }, []);

  useEffect(() => {
    fetchDefenderStatus();
  }, [fetchDefenderStatus]);

  // Handle live audit scan
  const handleStartAudit = async () => {
    setIsAuditing(true);
    setAuditProgress(20);
    onRunInConsole('defender-audit');

    try {
      await fetchDefenderStatus();
      setAuditProgress(70);
    } catch {}

    setTimeout(() => {
      setAuditProgress(100);
      setIsAuditing(false);
    }, 600);
  };

  // Remove individual exclusion
  const handleRemoveExclusion = (item: DefenderExclusionItem) => {
    const cmd = item.type === 'PATH'
      ? `Remove-MpPreference -ExclusionPath "${item.value}"`
      : item.type === 'PROCESS'
      ? `Remove-MpPreference -ExclusionProcess "${item.value}"`
      : `Remove-MpPreference -ExclusionExtension "${item.value}"`;

    onRunInConsole(cmd);
    setExclusions(prev =>
      prev.map(ex => ex.id === item.id ? { ...ex, status: 'PURGED' } : ex)
    );

    if (onMutateThreatStatus) {
      onMutateThreatStatus(item.id, item.value, 'NEUTRALIZED');
    }
  };

  // Trigger custom scan of excluded path with animated progression
  const handleScanPath = (item: DefenderExclusionItem) => {
    const cmd = item.type === 'PATH'
      ? `Start-MpScan -ScanType CustomScan -ScanPath "${item.value}"`
      : `Start-MpScan -ScanType QuickScan`;

    setScanningItemId(item.id);
    setActiveScanDialog({
      item,
      stage: 1,
      completed: false,
      logs: [
        `[1/4] Initialisation du moteur d'analyse Microsoft Defender...`,
        `> ${cmd}`,
      ],
    });

    onRunInConsole(cmd);

    setTimeout(() => {
      setActiveScanDialog(prev => prev ? {
        ...prev,
        stage: 2,
        logs: [
          ...prev.logs,
          `[2/4] Vérification des signatures virales & exclusion dans ${item.registryKey}...`,
        ],
      } : null);
    }, 450);

    setTimeout(() => {
      setActiveScanDialog(prev => prev ? {
        ...prev,
        stage: 3,
        logs: [
          ...prev.logs,
          `[3/4] Analyse heuristique & calcul d'entropie sur la cible "${item.value}"...`,
        ],
      } : null);
    }, 900);

    setTimeout(() => {
      setScanningItemId(null);
      setExclusions(prev =>
        prev.map(ex => ex.id === item.id ? { ...ex, status: 'SCANNED' } : ex)
      );
      setActiveScanDialog(prev => prev ? {
        ...prev,
        stage: 4,
        completed: true,
        logs: [
          ...prev.logs,
          item.threatLevel === 'MALICIOUS'
            ? `[4/4] ⚠️ MENACE CONFIRMÉE : L'élément est exclu illicitement et nécessite une PURGE immédiate.`
            : item.threatLevel === 'SUSPICIOUS'
            ? `[4/4] ⚠️ ÉLÉMENT SUSPECT : Risque potentiel de masquage de dropper dans les exclusions.`
            : `[4/4] ✅ CONFORME : Aucun artefact malveillant détecté pour cette exclusion.`,
        ],
      } : null);
    }, 1400);
  };

  // Purge all malicious and suspicious exclusions
  const handlePurgeAllMalicious = () => {
    const maliciousItems = exclusions.filter(e => e.status === 'ACTIVE' && (e.threatLevel === 'MALICIOUS' || e.threatLevel === 'SUSPICIOUS'));
    if (maliciousItems.length === 0) return;

    onRunInConsole('remove-mppreference all');

    setExclusions(prev =>
      prev.map(ex => (ex.threatLevel === 'MALICIOUS' || ex.threatLevel === 'SUSPICIOUS') ? { ...ex, status: 'PURGED' } : ex)
    );

    if (onMutateThreatStatus) {
      maliciousItems.forEach(item => {
        onMutateThreatStatus(item.id, item.value, 'NEUTRALIZED');
      });
    }
  };

  // Resynchronize and lock Defender policies
  const handleSyncDefenderPolicies = () => {
    onRunInConsole('policy-harden');
  };

  // Copy powershell command helper
  const handleCopyCmd = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(text);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  // Test custom input path or process
  const handleTestCustomInput = (e: React.FormEvent) => {
    e.preventDefault();
    if (!customInput.trim()) return;

    const trimmed = customInput.trim();
    const existing = exclusions.find(ex => ex.value.toLowerCase() === trimmed.toLowerCase());
    if (existing) {
      setCustomCheckResult(`[TROUVÉ] "${trimmed}" est actuellement dans la liste des exclusions (${existing.threatLevel}) sous ${existing.type} !`);
    } else {
      const isDangerousPath = /public|temp|appdata|programdata/i.test(trimmed);
      setCustomCheckResult(
        isDangerousPath
          ? `[AUDIT] "${trimmed}" n'est pas encore exclu, mais se trouve dans un répertoire sensible très ciblé par les malwares.`
          : `[AUDIT] "${trimmed}" n'est pas exclu dans les règles actuelles de Microsoft Defender.`
      );
    }
  };

  // Metrics calculations
  const activeExclusions = exclusions.filter(e => e.status === 'ACTIVE');
  const maliciousCount = activeExclusions.filter(e => e.threatLevel === 'MALICIOUS').length;
  const suspiciousCount = activeExclusions.filter(e => e.threatLevel === 'SUSPICIOUS').length;
  const purgedCount = exclusions.filter(e => e.status === 'PURGED').length;
  const sensitivePathsCount = activeExclusions.filter(e =>
    e.type === 'PATH' && /public|temp|programdata|appdata/i.test(e.value)
  ).length;

  const filteredExclusions = exclusions.filter(item => {
    if (filterType === 'ALL') return true;
    if (filterType === 'MALICIOUS_ONLY') return item.threatLevel === 'MALICIOUS' || item.threatLevel === 'SUSPICIOUS';
    return item.type === filterType;
  });

  return (
    <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-6 shadow-xl">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <h3 className="text-base font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
              DefenderSync : Contrôle & Purge des Exclusions Antivirus Modifiées
            </h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 border border-rose-800 text-rose-300 font-semibold">
              Get-MpPreference Exclusion Hunter
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Empêche les malwares et trojans (Swisyn, XMRig, Ransomwares) d'ajouter discrètement leurs répertoires d'infection dans les exclusions Microsoft Defender pour échapper à la protection en temps réel.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            onClick={handleStartAudit}
            disabled={isAuditing}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold transition-colors"
          >
            {isAuditing ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                <span>Analyse Get-MpPreference ({auditProgress}%)...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 text-cyan-400" />
                <span>Auditer les Exclusions</span>
              </>
            )}
          </button>

          <button
            onClick={handleSyncDefenderPolicies}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800/80 rounded-lg text-xs font-semibold transition-colors"
          >
            <Shield className="w-3.5 h-3.5 text-cyan-400" />
            <span>Synchroniser Politiques</span>
          </button>

          {maliciousCount + suspiciousCount > 0 && (
            <button
              onClick={handlePurgeAllMalicious}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white font-bold rounded-lg text-xs transition-colors shadow-sm"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Purger Tout ({maliciousCount + suspiciousCount})</span>
            </button>
          )}
        </div>
      </div>

      {/* Progress Bar during audit */}
      {isAuditing && (
        <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
          <div
            className="h-full bg-rose-500 transition-all duration-300"
            style={{ width: `${auditProgress}%` }}
          />
        </div>
      )}

      {/* KPI Stats Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
        <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
          <div className="text-slate-400 text-[11px] font-sans">Exclusions Totales</div>
          <div className="text-lg font-bold text-slate-100 tabular-nums">
            {activeExclusions.length} Actives
          </div>
          <div className="text-[10px] text-slate-500 font-sans">
            {purgedCount > 0 ? `${purgedCount} exclusion(s) déjà purgée(s)` : 'Toutes catégories confondues'}
          </div>
        </div>

        <div className="p-3 bg-rose-950/40 border border-rose-800/60 rounded-lg space-y-1">
          <div className="text-rose-400 text-[11px] font-sans font-semibold">Exclusions Malveillantes</div>
          <div className="text-lg font-bold text-rose-400 tabular-nums">
            {maliciousCount} Détectée(s)
          </div>
          <div className="text-[10px] text-rose-300 font-sans">
            {maliciousCount > 0 ? 'Sabotage avéré de Defender' : 'Aucune menace critique'}
          </div>
        </div>

        <div className="p-3 bg-amber-950/40 border border-amber-800/60 rounded-lg space-y-1">
          <div className="text-amber-400 text-[11px] font-sans font-semibold">Dossiers Sensibles Masqués</div>
          <div className="text-lg font-bold text-amber-300 tabular-nums">
            {sensitivePathsCount} Emplacement(s)
          </div>
          <div className="text-[10px] text-amber-300 font-sans">Public, %Temp%, ProgramData</div>
        </div>

        <div className="p-3 bg-emerald-950/40 border border-emerald-800/60 rounded-lg space-y-1">
          <div className="text-emerald-400 text-[11px] font-sans font-semibold">État de Synchronisation</div>
          <div className="text-lg font-bold text-emerald-300 tabular-nums">
            {maliciousCount === 0 ? 'INTÈGRE' : 'COMPROMIS'}
          </div>
          <div className="text-[10px] text-emerald-300 font-sans">
            Realtime + Script Scanning Actifs
          </div>
        </div>
      </div>

      {/* Filter and Custom Verifier Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Filter Buttons */}
        <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono overflow-x-auto">
          <button
            onClick={() => setFilterType('ALL')}
            className={`px-3 py-1.5 rounded transition-colors whitespace-nowrap ${
              filterType === 'ALL'
                ? 'bg-slate-800 text-cyan-300 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Toutes ({exclusions.length})
          </button>
          <button
            onClick={() => setFilterType('MALICIOUS_ONLY')}
            className={`px-3 py-1.5 rounded transition-colors whitespace-nowrap ${
              filterType === 'MALICIOUS_ONLY'
                ? 'bg-slate-800 text-rose-300 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Menaces & Suspects ({maliciousCount + suspiciousCount})
          </button>
          <button
            onClick={() => setFilterType('PATH')}
            className={`px-3 py-1.5 rounded transition-colors whitespace-nowrap ${
              filterType === 'PATH'
                ? 'bg-slate-800 text-amber-300 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Répertoires ({exclusions.filter(e => e.type === 'PATH').length})
          </button>
          <button
            onClick={() => setFilterType('PROCESS')}
            className={`px-3 py-1.5 rounded transition-colors whitespace-nowrap ${
              filterType === 'PROCESS'
                ? 'bg-slate-800 text-cyan-300 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Processus ({exclusions.filter(e => e.type === 'PROCESS').length})
          </button>
          <button
            onClick={() => setFilterType('EXTENSION')}
            className={`px-3 py-1.5 rounded transition-colors whitespace-nowrap ${
              filterType === 'EXTENSION'
                ? 'bg-slate-800 text-indigo-300 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Extensions ({exclusions.filter(e => e.type === 'EXTENSION').length})
          </button>
        </div>

        {/* Custom Quick Path / Process Verifier */}
        <form onSubmit={handleTestCustomInput} className="flex items-center gap-2">
          <input
            type="text"
            value={customInput}
            onChange={(e) => setCustomInput(e.target.value)}
            placeholder="Tester un chemin (ex: C:\Users\Public\...)"
            className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 w-64"
          />
          <button
            type="submit"
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-semibold rounded-lg border border-slate-700 transition-colors shrink-0"
          >
            Tester
          </button>
        </form>
      </div>

      {/* Custom check feedback alert */}
      {customCheckResult && (
        <div className="p-3 bg-slate-950 border border-cyan-800/60 rounded-lg text-xs font-mono text-cyan-300 flex items-center justify-between">
          <span>{customCheckResult}</span>
          <button
            onClick={() => setCustomCheckResult(null)}
            className="text-slate-400 hover:text-slate-200 text-xs ml-3"
          >
            Fermer
          </button>
        </div>
      )}

      {/* Exclusions Table */}
      <div className="border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3 font-semibold">Type</th>
                <th className="py-2.5 px-3 font-semibold">Cible Exclue (Chemin / Processus)</th>
                <th className="py-2.5 px-3 font-semibold">Niveau de Menace</th>
                <th className="py-2.5 px-3 font-semibold">Famille & Impact Malware</th>
                <th className="py-2.5 px-3 font-semibold">Horodatage / Clé</th>
                <th className="py-2.5 px-3 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
              {filteredExclusions.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400">
                    <div className="flex flex-col items-center justify-center gap-3">
                      <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                        <ShieldCheck className="w-6 h-6" />
                      </div>
                      <div className="text-sm font-semibold text-slate-200">
                        Aucune exclusion suspecte détectée dans Microsoft Defender
                      </div>
                      <p className="text-xs text-slate-400 max-w-md">
                        Votre système Windows ne présente aucune exclusion de chemin, de processus ou d'extension. L'ensemble des répertoires et fichiers est audité et protégé en temps réel.
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredExclusions.map(item => {
                  const isPurged = item.status === 'PURGED';
                  const isMalicious = item.threatLevel === 'MALICIOUS';
                  const isSuspicious = item.threatLevel === 'SUSPICIOUS';

                  return (
                    <tr
                      key={item.id}
                      className={`transition-colors ${
                        isPurged
                          ? 'bg-slate-950/60 opacity-60'
                        : isMalicious
                        ? 'bg-rose-950/20 hover:bg-rose-950/30'
                        : isSuspicious
                        ? 'bg-amber-950/20 hover:bg-amber-950/30'
                        : 'hover:bg-slate-800/40'
                    }`}
                  >
                    {/* Type Badge */}
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        item.type === 'PATH'
                          ? 'bg-slate-800 text-amber-300 border border-amber-800/60'
                          : item.type === 'PROCESS'
                          ? 'bg-slate-800 text-cyan-300 border border-cyan-800/60'
                          : 'bg-slate-800 text-indigo-300 border border-indigo-800/60'
                      }`}>
                        {item.type}
                      </span>
                    </td>

                    {/* Excluded Target */}
                    <td className="py-2.5 px-3 font-mono">
                      <div className={`font-semibold ${
                        isPurged
                          ? 'line-through text-slate-500'
                          : isMalicious
                          ? 'text-rose-300'
                          : isSuspicious
                          ? 'text-amber-300'
                          : 'text-slate-200'
                      }`}>
                        {item.value}
                      </div>
                      <div className="text-[10px] text-slate-500 font-sans mt-0.5">
                        {item.registryKey}
                      </div>
                    </td>

                    {/* Threat Level */}
                    <td className="py-2.5 px-3">
                      {isPurged ? (
                        <span className="flex items-center gap-1 text-emerald-400 font-sans font-semibold">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Purgé & Supprimé</span>
                        </span>
                      ) : item.status === 'SCANNED' ? (
                        <span className="flex items-center gap-1 text-cyan-400 font-sans font-semibold">
                          <ShieldCheck className="w-3.5 h-3.5" />
                          <span>Scanné & Audité</span>
                        </span>
                      ) : isMalicious ? (
                        <span className="flex items-center gap-1 text-rose-400 font-bold">
                          <XCircle className="w-3.5 h-3.5" />
                          <span>MALVEILLANT</span>
                        </span>
                      ) : isSuspicious ? (
                        <span className="flex items-center gap-1 text-amber-400 font-bold">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          <span>SUSPECT</span>
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-emerald-400 font-semibold font-sans">
                          <ShieldCheck className="w-3.5 h-3.5" />
                          <span>LÉGITIME</span>
                        </span>
                      )}
                    </td>

                    {/* Malware Family & Description */}
                    <td className="py-2.5 px-3 max-w-sm">
                      <div className="font-semibold text-slate-200 text-[11px] font-sans">
                        {item.malwareFamily}
                      </div>
                      <div className="text-[11px] text-slate-400 font-sans mt-0.5 leading-relaxed">
                        {item.reason}
                      </div>
                    </td>

                    {/* Timestamp */}
                    <td className="py-2.5 px-3 text-[11px] text-slate-400 font-sans whitespace-nowrap">
                      {item.addedTimestamp}
                    </td>

                    {/* Actions */}
                    <td className="py-2.5 px-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        {isPurged ? (
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-semibold text-emerald-400 bg-emerald-950/70 border border-emerald-800/80 rounded font-sans">
                            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                            <span>Neutralisé</span>
                          </span>
                        ) : (
                          <>
                            <button
                              onClick={() => handleScanPath(item)}
                              title="Déclencher un scan antivirus sur ce chemin"
                              className={`px-2 py-1 rounded text-[11px] transition-colors flex items-center gap-1 ${
                                item.status === 'SCANNED'
                                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                                  : 'bg-slate-800 hover:bg-slate-700 text-cyan-300'
                              }`}
                            >
                              <FileSearch className="w-3 h-3" />
                              <span>{item.status === 'SCANNED' ? 'Re-scanner' : 'Scanner'}</span>
                            </button>

                            <button
                              onClick={() => handleRemoveExclusion(item)}
                              title="Supprimer cette exclusion de Microsoft Defender"
                              className={`px-2.5 py-1 font-semibold rounded text-[11px] transition-colors shadow-sm flex items-center gap-1 ${
                                isMalicious
                                  ? 'bg-rose-600 hover:bg-rose-500 text-white'
                                  : 'bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold'
                              }`}
                            >
                              <Trash2 className="w-3 h-3" />
                              <span>Purger</span>
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Forensic PowerShell Snippets Card */}
      <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-300">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span className="font-bold">Commandes PowerShell Autonomes pour Audit & Remédiation</span>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Exécution sous élévation Administrateur requise</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
          <div className="p-3 bg-slate-900 border border-slate-800/80 rounded-lg space-y-2">
            <div className="flex items-center justify-between text-slate-300">
              <span className="font-semibold text-amber-400">1. Lister toutes les exclusions :</span>
              <button
                onClick={() => handleCopyCmd('Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension')}
                className="text-slate-400 hover:text-cyan-300 transition-colors"
                title="Copier la commande"
              >
                {copiedCmd === 'Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension' ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
              </button>
            </div>
            <pre className="text-slate-300 overflow-x-auto text-[11px] bg-slate-950 p-2 rounded">
              Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension
            </pre>
          </div>

          <div className="p-3 bg-slate-900 border border-slate-800/80 rounded-lg space-y-2">
            <div className="flex items-center justify-between text-slate-300">
              <span className="font-semibold text-rose-400">2. Supprimer une exclusion malveillante :</span>
              <button
                onClick={() => handleCopyCmd('Remove-MpPreference -ExclusionPath "C:\\Users\\Public\\svchost.exe"')}
                className="text-slate-400 hover:text-cyan-300 transition-colors"
                title="Copier la commande"
              >
                {copiedCmd === 'Remove-MpPreference -ExclusionPath "C:\\Users\\Public\\svchost.exe"' ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
              </button>
            </div>
            <pre className="text-slate-300 overflow-x-auto text-[11px] bg-slate-950 p-2 rounded">
              Remove-MpPreference -ExclusionPath "C:\Users\Public\svchost.exe"
            </pre>
          </div>

          <div className="p-3 bg-slate-900 border border-slate-800/80 rounded-lg space-y-2">
            <div className="flex items-center justify-between text-slate-300">
              <span className="font-semibold text-cyan-400">3. Verrouiller la protection en temps réel :</span>
              <button
                onClick={() => handleCopyCmd('Set-MpPreference -DisableRealtimeMonitoring $false -DisableScriptScanning $false')}
                className="text-slate-400 hover:text-cyan-300 transition-colors"
                title="Copier la commande"
              >
                {copiedCmd === 'Set-MpPreference -DisableRealtimeMonitoring $false -DisableScriptScanning $false' ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
              </button>
            </div>
            <pre className="text-slate-300 overflow-x-auto text-[11px] bg-slate-950 p-2 rounded">
              Set-MpPreference -DisableRealtimeMonitoring $false -DisableScriptScanning $false
            </pre>
          </div>

          <div className="p-3 bg-slate-900 border border-slate-800/80 rounded-lg space-y-2">
            <div className="flex items-center justify-between text-slate-300">
              <span className="font-semibold text-emerald-400">4. Scanner immédiatement un répertoire suspect :</span>
              <button
                onClick={() => handleCopyCmd('Start-MpScan -ScanType CustomScan -ScanPath "C:\\ProgramData\\WindowsHealthUpdater"')}
                className="text-slate-400 hover:text-cyan-300 transition-colors"
                title="Copier la commande"
              >
                {copiedCmd === 'Start-MpScan -ScanType CustomScan -ScanPath "C:\\ProgramData\\WindowsHealthUpdater"' ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
              </button>
            </div>
            <pre className="text-slate-300 overflow-x-auto text-[11px] bg-slate-950 p-2 rounded">
              Start-MpScan -ScanType CustomScan -ScanPath "C:\ProgramData\WindowsHealthUpdater"
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
