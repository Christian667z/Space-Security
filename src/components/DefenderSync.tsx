import React, { useState } from 'react';
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

interface DefenderSyncProps {
  onRunInConsole: (command: string) => void;
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

export const DefenderSync: React.FC<DefenderSyncProps> = ({ onRunInConsole }) => {
  const [isAuditing, setIsAuditing] = useState<boolean>(false);
  const [auditProgress, setAuditProgress] = useState<number>(100);
  const [filterType, setFilterType] = useState<'ALL' | 'PATH' | 'PROCESS' | 'EXTENSION' | 'MALICIOUS_ONLY'>('ALL');
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  // New check input
  const [customInput, setCustomInput] = useState<string>('');
  const [customCheckResult, setCustomCheckResult] = useState<string | null>(null);

  // Initial exclusions data representing realistic malware hijacking scenarios
  const [exclusions, setExclusions] = useState<DefenderExclusionItem[]>([
    {
      id: 'ex-1',
      type: 'PATH',
      value: 'C:\\Users\\Public\\svchost.exe',
      threatLevel: 'MALICIOUS',
      malwareFamily: 'Trojan.Swisyn / GhostRAT Drop',
      reason: 'Faux processus système placé dans le répertoire Public partagé, exclu de Windows Defender pour éviter la quarantaine lors du dropping.',
      registryKey: 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths',
      addedTimestamp: '2026-10-11 03:22 (Injection silencieuse)',
      status: 'ACTIVE',
    },
    {
      id: 'ex-2',
      type: 'PATH',
      value: 'C:\\ProgramData\\WindowsHealthUpdater\\',
      threatLevel: 'MALICIOUS',
      malwareFamily: 'CryptoMiner.XMRig / Persistence',
      reason: 'Répertoire caché sous un faux nom de composant de santé Windows. Héberge un mineur XMRig tournant en arrière-plan à l\'abri des scans.',
      registryKey: 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths',
      addedTimestamp: '2026-10-09 21:14',
      status: 'ACTIVE',
    },
    {
      id: 'ex-3',
      type: 'PATH',
      value: 'C:\\Windows\\Temp\\payload.bin',
      threatLevel: 'MALICIOUS',
      malwareFamily: 'CobaltStrike Beacon / Stager',
      reason: 'Exclusion ciblée d\'un artefact de staging de charge utile dans le cache temporaire Windows.',
      registryKey: 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths',
      addedTimestamp: '2026-10-12 01:45',
      status: 'ACTIVE',
    },
    {
      id: 'ex-4',
      type: 'PROCESS',
      value: 'powershell.exe',
      threatLevel: 'MALICIOUS',
      malwareFamily: 'Blindfold Execution / AMSI Bypass',
      reason: 'Exclusion du binaire powershell.exe lui-même ! Permet à n\'importe quel script obfusqué encodé en Base64 de s\'exécuter sans analyse heuristique de l\'antivirus.',
      registryKey: 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes',
      addedTimestamp: '2026-10-10 14:02',
      status: 'ACTIVE',
    },
    {
      id: 'ex-5',
      type: 'EXTENSION',
      value: '.ps1',
      threatLevel: 'SUSPICIOUS',
      malwareFamily: 'Script Engine Blindspot',
      reason: 'L\'extension de script PowerShell est exclue globalement. Aucun fichier .ps1 n\'est scanné lors de sa lecture sur le disque.',
      registryKey: 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions',
      addedTimestamp: '2026-10-10 14:03',
      status: 'ACTIVE',
    },
    {
      id: 'ex-6',
      type: 'PATH',
      value: 'C:\\Users\\admin\\AppData\\Local\\Temp\\*.exe',
      threatLevel: 'SUSPICIOUS',
      malwareFamily: 'Dropper Wildcard Masking',
      reason: 'Exclusion avec joker (*) sur tous les exécutables dans %TEMP%, vecteur numéro 1 d\'infection par pièce jointe ou exploit kit.',
      registryKey: 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths',
      addedTimestamp: '2026-10-08 19:30',
      status: 'ACTIVE',
    },
    {
      id: 'ex-7',
      type: 'PATH',
      value: 'C:\\Program Files\\Git\\bin\\git.exe',
      threatLevel: 'SAFE',
      malwareFamily: 'Outil de Développement Authentique',
      reason: 'Binaire officiel signé par Git for Windows. Exclusion de performance standard configurée par l\'administrateur.',
      registryKey: 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths',
      addedTimestamp: '2026-04-12 09:15',
      status: 'ACTIVE',
    },
  ]);

  // Handle live audit scan
  const handleStartAudit = () => {
    setIsAuditing(true);
    setAuditProgress(15);
    onRunInConsole('Get-MpPreference | Select-Object -ExpandProperty ExclusionPath; Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess; Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension');

    setTimeout(() => setAuditProgress(45), 350);
    setTimeout(() => setAuditProgress(80), 750);
    setTimeout(() => {
      setAuditProgress(100);
      setIsAuditing(false);
    }, 1100);
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
  };

  // Trigger custom scan of excluded path
  const handleScanPath = (item: DefenderExclusionItem) => {
    const cmd = item.type === 'PATH'
      ? `Start-MpScan -ScanType CustomScan -ScanPath "${item.value}"`
      : `Start-MpScan -ScanType QuickScan`;

    onRunInConsole(cmd);
    setExclusions(prev =>
      prev.map(ex => ex.id === item.id ? { ...ex, status: 'SCANNED' } : ex)
    );
  };

  // Purge all malicious and suspicious exclusions
  const handlePurgeAllMalicious = () => {
    const maliciousItems = exclusions.filter(e => e.status === 'ACTIVE' && (e.threatLevel === 'MALICIOUS' || e.threatLevel === 'SUSPICIOUS'));
    if (maliciousItems.length === 0) return;

    onRunInConsole(
      '# Purge de toutes les exclusions frauduleuses Defender\n' +
      maliciousItems.map(item => {
        if (item.type === 'PATH') return `Remove-MpPreference -ExclusionPath "${item.value}"`;
        if (item.type === 'PROCESS') return `Remove-MpPreference -ExclusionProcess "${item.value}"`;
        return `Remove-MpPreference -ExclusionExtension "${item.value}"`;
      }).join('; ')
    );

    setExclusions(prev =>
      prev.map(ex => (ex.threatLevel === 'MALICIOUS' || ex.threatLevel === 'SUSPICIOUS') ? { ...ex, status: 'PURGED' } : ex)
    );
  };

  // Resynchronize and lock Defender policies
  const handleSyncDefenderPolicies = () => {
    const syncCmd = 'Set-MpPreference -DisableRealtimeMonitoring $false; Set-MpPreference -DisableScriptScanning $false; Set-MpPreference -DisableBehaviorMonitoring $false; Set-MpPreference -DisableIOAVProtection $false; Update-MpSignature';
    onRunInConsole(syncCmd);
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
              {filteredExclusions.map(item => {
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
                          <span>P квадраt (Plein Scan)</span>
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
                          <span className="text-[11px] text-emerald-400 font-sans">Neutralisé</span>
                        ) : (
                          <>
                            <button
                              onClick={() => handleScanPath(item)}
                              title="Déclencher un scan antivirus sur ce chemin"
                              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded text-[11px] transition-colors flex items-center gap-1"
                            >
                              <FileSearch className="w-3 h-3" />
                              <span>Scanner</span>
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
