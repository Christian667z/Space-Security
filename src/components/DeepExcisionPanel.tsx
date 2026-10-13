import React, { useState, useMemo } from 'react';
import {
  Cpu,
  ShieldAlert,
  Key,
  Unlock,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  Terminal,
  Copy,
  Check,
  RefreshCw,
  Radio,
  ArrowDownLeft,
  ArrowUpRight,
  Ban,
  Zap,
  CheckSquare,
  Square,
  MinusSquare,
  Layers,
  EyeOff,
  RotateCcw,
  X,
  Flame,
  Search,
} from 'lucide-react';
import { ThreatItem } from '../types/cyberdefense';
import { SharedCommandModal } from './SharedCommandModal';

interface DeepExcisionPanelProps {
  onRunInConsole: (command: string) => void;
  threats?: ThreatItem[];
  onBulkMutateThreatStatus?: (threatIds: string[], status: ThreatItem['status'], command?: string) => void;
  onMassDismissThreats?: (threatIds: string[]) => void;
  onRestoreThreats?: (threatIds: string[]) => void;
}

interface BITSJobItem {
  id: string;
  jobName: string;
  owner: string;
  state: 'TRANSFERRING' | 'SUSPENDED' | 'ACKNOWLEDGED' | 'ERROR';
  direction: 'DOWNLOAD' | 'UPLOAD_EXFIL';
  remoteUrl: string;
  localPath: string;
  transferredBytes: string;
  isSuspicious: boolean;
  threatDetails?: string;
}

const DEFAULT_KERNEL_THREATS: ThreatItem[] = [
  {
    id: 't1',
    name: 'Rootkit Driver Hook (Inaccessible aux Admins)',
    category: 'Rootkit',
    severity: 'CRITICAL',
    targetPath: 'C:\\Windows\\System32\\drivers\\suspicious_kernel_hook.sys',
    mitreTechnique: 'T1014 - Rootkit Kernel Driver',
    lockedBySystem: true,
    trustedInstallerLocked: true,
    description: 'Hook noyau IRP_MJ_CREATE interceptant les ouvertures de fichiers et bloquant toute suppression.',
    status: 'ACTIVE',
  },
  {
    id: 't2',
    name: 'Trojan Swisyn Watchdog (Double Processus Verrouillé)',
    category: 'Trojan',
    severity: 'HIGH',
    targetPath: 'C:\\Users\\User\\AppData\\Local\\Temp\\svch0st_updater.exe',
    mitreTechnique: 'T1059.001 - PowerShell / T1071.001 C2',
    lockedBySystem: true,
    trustedInstallerLocked: false,
    description: 'Processus mimant le service hôte Windows, communicant vers 185.220.101.4 avec surveillance mutuelle.',
    status: 'ACTIVE',
  },
  {
    id: 't4',
    name: 'Piège IFEO Debugger sur Taskmgr & Defender',
    category: 'Privilege',
    severity: 'CRITICAL',
    targetPath: 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe',
    mitreTechnique: 'T1546.012 - IFEO Debugger Trap',
    lockedBySystem: false,
    trustedInstallerLocked: true,
    description: 'Détournement du Gestionnaire des Tâches via clé Debugger malveillante interdisant l\'inspection de la mémoire.',
    status: 'ACTIVE',
  },
  {
    id: 't6',
    name: 'Flux NTFS Alternatif Caché (Zone.Identifier ADS)',
    category: 'Memory',
    severity: 'MEDIUM',
    targetPath: 'C:\\Users\\Public\\payload.dll:hidden_stream',
    mitreTechnique: 'T1564.004 - Alternate Data Streams',
    lockedBySystem: false,
    trustedInstallerLocked: false,
    description: 'Binaire DLL dissimulé derrière un flux de données alternatif NTFS pour contourner les contrôles antiviraux superficiels.',
    status: 'ACTIVE',
  },
];

export const DeepExcisionPanel: React.FC<DeepExcisionPanelProps> = ({
  onRunInConsole,
  threats,
  onBulkMutateThreatStatus,
  onMassDismissThreats,
  onRestoreThreats,
}) => {
  const [customPath, setCustomPath] = useState('C:\\Windows\\System32\\drivers\\suspicious_kernel_hook.sys');
  const [copiedSnippet, setCopiedSnippet] = useState(false);
  const [activeStage, setActiveStage] = useState<number | null>(null);

  // Bulk Selection States
  const [selectedThreatIds, setSelectedThreatIds] = useState<Set<string>>(new Set());
  const [isSharedCommandModalOpen, setIsSharedCommandModalOpen] = useState(false);
  const [showDismissed, setShowDismissed] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [bulkFeedbackMessage, setBulkFeedbackMessage] = useState<string | null>(null);
  const [recentlyDismissedIds, setRecentlyDismissedIds] = useState<string[]>([]);

  const allThreats = threats && threats.length > 0 ? threats : DEFAULT_KERNEL_THREATS;

  const kernelThreats = useMemo(() => {
    return allThreats.filter(t => {
      const isKernelRelated =
        t.category === 'Rootkit' ||
        t.category === 'Trojan' ||
        t.category === 'Privilege' ||
        t.trustedInstallerLocked ||
        t.lockedBySystem;
      if (!isKernelRelated) return false;
      if (!showDismissed && t.status === 'DISMISSED') return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          t.name.toLowerCase().includes(q) ||
          Boolean(t.description && t.description.toLowerCase().includes(q)) ||
          t.targetPath.toLowerCase().includes(q) ||
          t.mitreTechnique.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [allThreats, showDismissed, searchQuery]);

  const selectedThreatsList = useMemo(() => {
    return allThreats.filter(t => selectedThreatIds.has(t.id));
  }, [allThreats, selectedThreatIds]);

  const dismissedCount = useMemo(() => {
    return allThreats.filter(t => t.status === 'DISMISSED').length;
  }, [allThreats]);

  // Bulk Selection Handlers
  const toggleSelectThreat = (id: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setSelectedThreatIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleToggleSelectAll = () => {
    if (selectedThreatIds.size === kernelThreats.length && kernelThreats.length > 0) {
      setSelectedThreatIds(new Set());
    } else {
      setSelectedThreatIds(new Set(kernelThreats.map(t => t.id)));
    }
  };

  const handleSelectActiveOnly = () => {
    const active = kernelThreats.filter(t => t.status === 'ACTIVE').map(t => t.id);
    setSelectedThreatIds(new Set(active));
  };

  const handleSelectCriticalOnly = () => {
    const crit = kernelThreats.filter(t => t.severity === 'CRITICAL' && t.status === 'ACTIVE').map(t => t.id);
    setSelectedThreatIds(new Set(crit));
  };

  const handleClearSelection = () => {
    setSelectedThreatIds(new Set());
  };

  // Bulk Action Handlers
  const handleBulkKernelUnlock = () => {
    if (selectedThreatIds.size === 0) return;
    const targetThreats = allThreats.filter(t => selectedThreatIds.has(t.id));
    const ids = targetThreats.map(t => t.id);

    targetThreats.forEach((threat, idx) => {
      setTimeout(() => {
        onRunInConsole(`unlock "${threat.targetPath}"`);
      }, idx * 300);
    });

    if (onBulkMutateThreatStatus) {
      onBulkMutateThreatStatus(ids, 'SCHEDULED_BOOT_DELETE', 'Éradication Kernel');
    }
    setBulkFeedbackMessage(`Éradication noyau programmée sur ${ids.length} menace(s).`);
    setTimeout(() => setBulkFeedbackMessage(null), 4000);
    handleClearSelection();
  };

  const handleBulkQuarantine = () => {
    if (selectedThreatIds.size === 0) return;
    const ids = Array.from(selectedThreatIds);
    onRunInConsole(`bulk-quarantine ${ids.join(',')}`);
    if (onBulkMutateThreatStatus) {
      onBulkMutateThreatStatus(ids, 'QUARANTINED', 'Quarantaine Chiffrée');
    }
    setBulkFeedbackMessage(`${ids.length} menace(s) verrouillée(s) en quarantaine chiffrée.`);
    setTimeout(() => setBulkFeedbackMessage(null), 4000);
    handleClearSelection();
  };

  const handleMassDismiss = () => {
    if (selectedThreatIds.size === 0) return;
    const ids = Array.from(selectedThreatIds);
    setRecentlyDismissedIds(ids);
    if (onMassDismissThreats) {
      onMassDismissThreats(ids);
    } else if (onBulkMutateThreatStatus) {
      onBulkMutateThreatStatus(ids, 'DISMISSED', 'Rejet en masse');
    }
    onRunInConsole(`bulk-dismiss ${ids.join(',')}`);
    setBulkFeedbackMessage(`${ids.length} menace(s) rejetée(s) et archivée(s) de la surveillance.`);
    setTimeout(() => setBulkFeedbackMessage(null), 5000);
    handleClearSelection();
  };

  const handleUndoDismiss = () => {
    if (recentlyDismissedIds.length === 0) return;
    if (onRestoreThreats) {
      onRestoreThreats(recentlyDismissedIds);
    } else if (onBulkMutateThreatStatus) {
      onBulkMutateThreatStatus(recentlyDismissedIds, 'ACTIVE', 'Restauration');
    }
    setBulkFeedbackMessage(`${recentlyDismissedIds.length} menace(s) restaurée(s) dans la liste active.`);
    setRecentlyDismissedIds([]);
    setTimeout(() => setBulkFeedbackMessage(null), 3000);
  };

  const handleRestoreSingle = (threatId: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    if (onRestoreThreats) {
      onRestoreThreats([threatId]);
    }
    setBulkFeedbackMessage(`Menace réactivée dans la liste active.`);
    setTimeout(() => setBulkFeedbackMessage(null), 3000);
  };

  const handleExecuteSharedCommand = (template: string, targets: ThreatItem[]) => {
    targets.forEach((threat, idx) => {
      const fileName = threat.targetPath.split('\\').pop() || threat.name;
      const baseName = fileName.replace(/\.[^/.]+$/, '');
      const instantiated = template
        .replace(/{path}/g, threat.targetPath)
        .replace(/{name}/g, baseName)
        .replace(/{id}/g, threat.id)
        .replace(/{category}/g, threat.category);

      setTimeout(() => {
        onRunInConsole(instantiated);
      }, idx * 350);
    });

    const isUnlock = template.toLowerCase().includes('unlock') || template.toLowerCase().includes('pendingfile');
    const isStop = template.toLowerCase().includes('stop-process') || template.toLowerCase().includes('taskkill');
    if (isUnlock && onBulkMutateThreatStatus) {
      onBulkMutateThreatStatus(targets.map(t => t.id), 'SCHEDULED_BOOT_DELETE', template);
    } else if (isStop && onBulkMutateThreatStatus) {
      onBulkMutateThreatStatus(targets.map(t => t.id), 'NEUTRALIZED', template);
    }

    setBulkFeedbackMessage(`Commande partagée exécutée sur ${targets.length} cibles.`);
    setTimeout(() => setBulkFeedbackMessage(null), 4000);
    handleClearSelection();
  };

  // BITS Jobs State
  const [bitsJobs, setBitsJobs] = useState<BITSJobItem[]>([
    {
      id: '{8F3C-41A9-E20B-78D1}',
      jobName: 'WindowsUpdateHelper',
      owner: 'NT AUTHORITY\\SYSTEM',
      state: 'TRANSFERRING',
      direction: 'DOWNLOAD',
      remoteUrl: 'http://185.220.101.4/payload.bin',
      localPath: 'C:\\Users\\User\\AppData\\Local\\Temp\\stage2.bin',
      transferredBytes: '1.42 MB / 2.80 MB (51%)',
      isSuspicious: true,
      threatDetails: 'Téléchargement furtif d\'un payload C2 en contournant les pare-feux applicatifs',
    },
    {
      id: '{3C7D-90E1-A42F-1197}',
      jobName: 'DiagnosticDataExfil',
      owner: 'SYSTEM',
      state: 'SUSPENDED',
      direction: 'UPLOAD_EXFIL',
      remoteUrl: 'http://45.154.255.89:8080/collect',
      localPath: 'C:\\ProgramData\\loot_archive.zip',
      transferredBytes: '840 KB / 840 KB (100% en attente d\'acquittement)',
      isSuspicious: true,
      threatDetails: 'Exfiltration de données locales via requête HTTP POST asynchrone BITS',
    },
    {
      id: '{D42E-1197-00AA-8812}',
      jobName: 'WU-DefinitionUpdate',
      owner: 'NT AUTHORITY\\NETWORK SERVICE',
      state: 'ACKNOWLEDGED',
      direction: 'DOWNLOAD',
      remoteUrl: 'http://download.windowsupdate.com/msdownload/update/v3/def.cab',
      localPath: 'C:\\Windows\\SoftwareDistribution\\Download\\def.cab',
      transferredBytes: '14.2 MB / 14.2 MB (Terminé)',
      isSuspicious: false,
      threatDetails: 'Tâche système légitime de mise à jour des signatures',
    },
  ]);

  const handleCancelBitsJob = (jobId: string) => {
    onRunInConsole(`bitsadmin /cancel ${jobId}`);
    setBitsJobs(prev => prev.filter(j => j.id !== jobId));
  };

  const handlePurgeAllSuspiciousBits = () => {
    onRunInConsole('bits-clean');
    setBitsJobs(prev => prev.filter(j => !j.isSuspicious));
  };

  // Common stubborn malware presets
  const presets = [
    {
      title: 'Pilote Kernel Rootkit (.sys verrouillé)',
      path: 'C:\\Windows\\System32\\drivers\\suspicious_kernel_hook.sys',
      reason: 'Verrouillé par handle noyau, inaccessible même avec droits Administrateur standards',
    },
    {
      title: 'Trojan Swisyn / Remcos persistant (.exe verrouillé)',
      path: 'C:\\ProgramData\\WindowsUpdateHelper\\svch0st_host.exe',
      reason: 'Watchdog mutuel actif, réapparition instantanée en cas de kill classique',
    },
    {
      title: 'Payload caché dans AppData avec attributs SYSTEM',
      path: 'C:\\Users\\User\\AppData\\Roaming\\Microsoft\\Protect\\updater_core.dll',
      reason: 'Droits ACL restreints à NT SERVICE\\TrustedInstaller avec flux ADS',
    },
  ];

  const generatedScript = `# Protocole d'Eradication Racine SpaceSec
$target = "${customPath}"
# 1. Reset Attributs
Set-ItemProperty -Path $target -Name Attributes -Value Normal -ErrorAction SilentlyContinue
# 2. Appropriation de propriete (Takeown depuis TrustedInstaller)
takeown.exe /F $target /A
takeown.exe /F $target
# 3. Restauration acces total Administrateurs (icacls)
icacls.exe $target /grant *S-1-5-32-544:F /c /q
icacls.exe $target /grant "$env:USERNAME":F /c /q
# 4. Tuer processus verrouillant
$base = [System.IO.Path]::GetFileNameWithoutExtension($target)
Get-Process | Where-Object { $_.Name -match $base } | ForEach-Object { Stop-Process -Id $_.Id -Force; taskkill /F /T /PID $_.Id }
# 5. Suppression ou programmation au boot noyau (PendingFileRenameOperations)
try { [System.IO.File]::Delete($target) } catch {}
if (Test-Path $target) {
    [NativeSecurity]::MoveFileEx($target, $null, 4)
    $native = "\\??\\$target"
    $cur = (Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager").PendingFileRenameOperations
    Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" -Name "PendingFileRenameOperations" -Value (@($cur) + @($native, "")) -Type MultiString
    [System.IO.File]::WriteAllBytes($target, [byte[]]@())
    icacls.exe $target /deny Everyone:(X)
    Write-Host "[OK] Fichier ecrase et programme pour destruction au reboot noyau !" -ForegroundColor Green
} else {
    Write-Host "[OK] Fichier eradiqué immédiatement." -ForegroundColor Green
}`;

  const copyToClipboard = () => {
    navigator.clipboard.writeText(generatedScript);
    setCopiedSnippet(true);
    setTimeout(() => setCopiedSnippet(false), 2000);
  };

  const simulateExcision = () => {
    setActiveStage(1);
    onRunInConsole(`unlock "${customPath}"`);
    let stage = 1;
    const interval = setInterval(() => {
      stage++;
      if (stage > 4) {
        clearInterval(interval);
        setActiveStage(null);
      } else {
        setActiveStage(stage);
      }
    }, 800);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 bg-slate-900/90 border border-slate-800 rounded-xl relative overflow-hidden">
        <div className="max-w-3xl">
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-2">
            <Cpu className="w-4 h-4" />
            <span>Noyau Windows & Privilèges Résiduels</span>
          </div>
          <h2 className="text-xl font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
            Éradication des Virus Indestructibles & Inaccessibles
          </h2>
          <p className="mt-2 text-sm text-slate-300 leading-relaxed">
            Même avec le compte Administrateur, certains malwares (rootkits, trojans Swisyn, verrouilleurs ransomware)
            s'attribuent le propriétaire <strong className="text-cyan-300">NT SERVICE\TrustedInstaller</strong> ou maintiennent des handles exclusifs ouverts par des pilotes kernel.
            Ce module brise ces verrous, prend le contrôle via les privilèges <code className="text-amber-300 font-mono text-xs">SeTakeOwnershipPrivilege</code>,
            et programme la destruction définitive au niveau du gestionnaire de session Windows (<code className="text-amber-300 font-mono text-xs">PendingFileRenameOperations</code>).
          </p>
        </div>
      </div>

      {/* Feedback Toast Notification Banner */}
      {bulkFeedbackMessage && (
        <div className="p-3 bg-cyan-950/80 border border-cyan-800 rounded-xl flex items-center justify-between text-xs text-cyan-200 animate-in fade-in duration-200">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>{bulkFeedbackMessage}</span>
          </div>
          {recentlyDismissedIds.length > 0 && (
            <button
              onClick={handleUndoDismiss}
              className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-semibold text-cyan-300 hover:text-white bg-cyan-900/60 hover:bg-cyan-800 rounded transition-colors"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Annuler</span>
            </button>
          )}
        </div>
      )}

      {/* TACTICAL KERNEL THREATS & BULK SELECTION SECTION */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Key className="w-4 h-4 text-cyan-400" />
              <h3 className="text-base font-bold text-white tracking-tight">
                Menaces Kernel & Fichiers Système Verrouillés
              </h3>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800">
                {kernelThreats.filter(t => t.status === 'ACTIVE').length} Active(s)
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Sélectionnez plusieurs menaces pour exécuter un modèle de commande unifié ou les rejeter en masse.
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Filtrer menaces..."
                className="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono w-48"
              />
            </div>

            <button
              onClick={() => setShowDismissed(!showDismissed)}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors border ${
                showDismissed
                  ? 'bg-slate-800 text-cyan-300 border-cyan-800 font-semibold'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-300 border-slate-800'
              }`}
              title="Afficher ou masquer les menaces rejetées"
            >
              <EyeOff className="w-3.5 h-3.5 text-slate-400" />
              <span>Ignorées ({dismissedCount})</span>
            </button>
          </div>
        </div>

        {/* Selection Preset Selectors */}
        <div className="flex items-center justify-between gap-3 pt-2 border-t border-slate-800 flex-wrap text-xs">
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={handleToggleSelectAll}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg font-mono bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors"
            >
              {selectedThreatIds.size > 0 && selectedThreatIds.size === kernelThreats.length ? (
                <CheckSquare className="w-3.5 h-3.5 text-cyan-400" />
              ) : selectedThreatIds.size > 0 ? (
                <MinusSquare className="w-3.5 h-3.5 text-cyan-400" />
              ) : (
                <Square className="w-3.5 h-3.5 text-slate-500" />
              )}
              <span>Tout ({kernelThreats.length})</span>
            </button>

            <button
              onClick={handleSelectActiveOnly}
              className="px-2.5 py-1.5 rounded-lg font-mono bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors"
            >
              Actives ({kernelThreats.filter(t => t.status === 'ACTIVE').length})
            </button>

            <button
              onClick={handleSelectCriticalOnly}
              className="px-2.5 py-1.5 rounded-lg font-mono bg-slate-950 hover:bg-slate-800 text-rose-400 border border-slate-800 transition-colors"
            >
              Critiques ({kernelThreats.filter(t => t.severity === 'CRITICAL' && t.status === 'ACTIVE').length})
            </button>

            {selectedThreatIds.size > 0 && (
              <button
                onClick={handleClearSelection}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg font-mono text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
              >
                <X className="w-3 h-3" />
                <span>Effacer</span>
              </button>
            )}
          </div>

          <div className="text-xs text-slate-500 font-mono">
            {selectedThreatIds.size} sélectionnée(s) sur {kernelThreats.length}
          </div>
        </div>

        {/* ACTIVE STICKY BULK ACTIONS COMMAND BAR */}
        {selectedThreatIds.size > 0 && (
          <div className="p-3 bg-gradient-to-r from-slate-950 via-slate-900 to-cyan-950/40 rounded-xl border border-cyan-800/80 shadow-lg shadow-cyan-950/30 space-y-2 animate-in slide-in-from-top-2 duration-200">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-lg bg-cyan-950 text-cyan-300 border border-cyan-800">
                  <Layers className="w-4 h-4 text-cyan-400" />
                </div>
                <div>
                  <div className="text-xs font-bold text-white flex items-center gap-1.5">
                    <span>Actions Groupées sur la Sélection</span>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                      {selectedThreatIds.size} cible{selectedThreatIds.size > 1 ? 's' : ''}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Application synchronisée à travers tous les postes d'analyse connectés.
                  </p>
                </div>
              </div>

              {/* Bulk Action Buttons */}
              <div className="flex items-center gap-2 flex-wrap">
                {/* Bulk Kernel Unlock */}
                <button
                  onClick={handleBulkKernelUnlock}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold font-mono text-white bg-rose-600 hover:bg-rose-500 shadow-md shadow-rose-950 transition-all"
                  title="Exécute takeown, icacls et programme la suppression au boot pour toutes les menaces sélectionnées"
                >
                  <Zap className="w-3.5 h-3.5" />
                  <span>Éradication Noyau ({selectedThreatIds.size})</span>
                </button>

                {/* Shared Command Runner */}
                <button
                  onClick={() => setIsSharedCommandModalOpen(true)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold font-mono text-cyan-200 bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 shadow-sm shadow-cyan-950 transition-all"
                  title="Exécute un modèle de commande partagé (SHA256, kill, takeown, etc.) sur toutes les cibles"
                >
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Commande Partagée...</span>
                </button>

                {/* Bulk Quarantine */}
                <button
                  onClick={handleBulkQuarantine}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono text-amber-300 bg-amber-950/80 hover:bg-amber-900/80 border border-amber-800 transition-colors"
                  title="Place les menaces sélectionnées dans le conteneur chiffré de quarantaine"
                >
                  <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                  <span>Quarantaine</span>
                </button>

                {/* Mass Dismiss */}
                <button
                  onClick={handleMassDismiss}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono text-slate-300 bg-slate-800 hover:bg-slate-700 hover:text-slate-100 border border-slate-700 transition-colors"
                  title="Rejeter et marquer comme traitées/fausses alertes en masse"
                >
                  <EyeOff className="w-3.5 h-3.5 text-slate-400" />
                  <span>Rejet en Masse</span>
                </button>

                {/* Cancel Selection */}
                <button
                  onClick={handleClearSelection}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
                  title="Annuler la sélection"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Threat Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {kernelThreats.map(threat => {
            const isSelected = selectedThreatIds.has(threat.id);
            const isDismissed = threat.status === 'DISMISSED';
            const isScheduledDelete = threat.status === 'SCHEDULED_BOOT_DELETE';
            const isCritical = threat.severity === 'CRITICAL';

            return (
              <div
                key={threat.id}
                onClick={() => setCustomPath(threat.targetPath)}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer space-y-2.5 ${
                  isSelected
                    ? 'bg-slate-950/90 border-cyan-500 ring-1 ring-cyan-500/50 shadow-md shadow-cyan-950/40'
                    : isDismissed
                    ? 'bg-slate-950/40 border-slate-800/60 opacity-60'
                    : isCritical
                    ? 'bg-slate-950/80 border-rose-900/60 hover:border-rose-700'
                    : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={(e) => toggleSelectThreat(threat.id, e)}
                      className={`p-1 rounded-md transition-colors ${
                        isSelected
                          ? 'text-cyan-400 bg-cyan-950/80 border border-cyan-700'
                          : 'text-slate-500 hover:text-slate-300 bg-slate-900 border border-slate-800'
                      }`}
                      title={isSelected ? 'Désélectionner' : 'Sélectionner'}
                    >
                      {isSelected ? (
                        <CheckSquare className="w-3.5 h-3.5 text-cyan-400" />
                      ) : (
                        <Square className="w-3.5 h-3.5" />
                      )}
                    </button>

                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className={`text-xs font-bold ${isDismissed ? 'line-through text-slate-500' : 'text-slate-100'}`}>
                        {threat.name}
                      </span>
                      {threat.trustedInstallerLocked && (
                        <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-purple-950 text-purple-300 border border-purple-800">
                          TrustedInstaller
                        </span>
                      )}
                    </div>
                  </div>

                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                    isCritical ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-amber-950 text-amber-300 border border-amber-800'
                  }`}>
                    {threat.severity}
                  </span>
                </div>

                <div className="text-[11px] font-mono text-slate-400 truncate bg-slate-900/60 p-1.5 rounded border border-slate-800/60">
                  {threat.targetPath}
                </div>

                <div className="text-[11px] text-slate-400 leading-relaxed">
                  {threat.description || threat.mitreTechnique}
                </div>

                <div className="flex items-center justify-between pt-1 border-t border-slate-900 text-xs">
                  <span className="text-[10px] font-mono text-cyan-400">
                    {threat.mitreTechnique}
                  </span>

                  <div className="flex items-center gap-1.5" onClick={e => e.stopPropagation()}>
                    {isDismissed ? (
                      <button
                        onClick={(e) => handleRestoreSingle(threat.id, e)}
                        className="inline-flex items-center gap-1 px-2 py-0.5 text-cyan-300 bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-800 font-semibold rounded text-[11px] transition-colors"
                      >
                        <RotateCcw className="w-3 h-3 text-cyan-400" />
                        <span>Restaurer</span>
                      </button>
                    ) : isScheduledDelete ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                        Boot Delete (0B)
                      </span>
                    ) : (
                      <button
                        onClick={() => {
                          setCustomPath(threat.targetPath);
                          simulateExcision();
                        }}
                        className="px-2 py-0.5 bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 rounded text-[11px] font-mono font-semibold transition-colors"
                      >
                        Éradiquer
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Main Grid: Excision Generator + Presets */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Interactive Path Configurator */}
        <div className="lg:col-span-2 p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <Unlock className="w-4 h-4 text-cyan-400" />
                Déverrouilleur & Destructeur de Fichiers Système
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Indiquez le fichier ou la DLL qu'aucun antivirus ou explorateur n'arrive à effacer.
              </p>
            </div>
          </div>

          <div className="space-y-3">
            <label className="text-xs font-medium text-slate-300 block">
              Chemin absolu de la cible à éliminer :
            </label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={customPath}
                onChange={e => setCustomPath(e.target.value)}
                className="flex-1 px-3.5 py-2.5 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
                placeholder="Ex: C:\Windows\System32\drivers\malicious.sys"
              />
              <button
                onClick={simulateExcision}
                className="flex items-center gap-2 px-4 py-2.5 bg-rose-600 hover:bg-rose-500 text-white font-semibold rounded-lg text-xs transition-colors shrink-0 shadow-sm"
              >
                <Trash2 className="w-4 h-4" />
                <span>Forcer l'Éradication</span>
              </button>
            </div>
          </div>

          {/* Stepper Visualization */}
          <div className="space-y-2 pt-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Chaîne d'Éradication Automatisée en 4 Phases :
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className={`p-3 rounded-lg border ${activeStage === 1 ? 'border-cyan-500 bg-cyan-950/40' : 'border-slate-800 bg-slate-950/60'}`}>
                <div className="font-bold text-slate-200 flex items-center gap-1.5">
                  <Key className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Phase 1</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  Takeown & Dépouillement TrustedInstaller
                </p>
              </div>

              <div className={`p-3 rounded-lg border ${activeStage === 2 ? 'border-cyan-500 bg-cyan-950/40' : 'border-slate-800 bg-slate-950/60'}`}>
                <div className="font-bold text-slate-200 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                  <span>Phase 2</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  Icacls Full Administrators + Neutralisation
                </p>
              </div>

              <div className={`p-3 rounded-lg border ${activeStage === 3 ? 'border-cyan-500 bg-cyan-950/40' : 'border-slate-800 bg-slate-950/60'}`}>
                <div className="font-bold text-slate-200 flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-rose-400" />
                  <span>Phase 3</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  NtSuspend & Abattage de l'Arbre de Processus
                </p>
              </div>

              <div className={`p-3 rounded-lg border ${activeStage === 4 ? 'border-cyan-500 bg-cyan-950/40' : 'border-slate-800 bg-slate-950/60'}`}>
                <div className="font-bold text-slate-200 flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Phase 4</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  MoveFileEx Boot Delay & Écrasement 0-Byte
                </p>
              </div>
            </div>
          </div>

          {/* Generated Code Preview */}
          <div className="space-y-2 pt-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">
                Commande PowerShell Ultra Générée pour cette cible :
              </span>
              <button
                onClick={copyToClipboard}
                className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300"
              >
                {copiedSnippet ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedSnippet ? 'Copié !' : 'Copier Code'}</span>
              </button>
            </div>
            <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-slate-300 text-[11px] font-mono overflow-x-auto max-h-48 scrollbar-thin">
              {generatedScript}
            </pre>
          </div>
        </div>

        {/* Right Col: Presets & Vectors */}
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            Vecteurs d'Infection Typiques
          </h3>
          <p className="text-xs text-slate-400">
            Cliquez sur un préréglage pour configurer instantanément la procédure d'excision :
          </p>

          <div className="space-y-3">
            {presets.map((preset, idx) => (
              <div
                key={idx}
                onClick={() => setCustomPath(preset.path)}
                className="p-3 bg-slate-950/80 hover:bg-slate-950 border border-slate-800 hover:border-cyan-800/80 rounded-lg cursor-pointer transition-colors"
              >
                <div className="font-semibold text-xs text-cyan-300">
                  {preset.title}
                </div>
                <div className="text-[11px] font-mono text-slate-400 truncate mt-1">
                  {preset.path}
                </div>
                <div className="text-[11px] text-slate-500 mt-1">
                  {preset.reason}
                </div>
              </div>
            ))}
          </div>

          <div className="p-3.5 bg-cyan-950/40 border border-cyan-800/60 rounded-lg text-xs space-y-2 text-slate-300">
            <div className="font-semibold text-cyan-300 flex items-center gap-1.5">
              <span>Pourquoi l'Admin classique échoue ?</span>
            </div>
            <p className="text-[11px] leading-relaxed text-slate-400">
              Windows interdit la modification des fichiers appartenant à <code className="text-cyan-200">TrustedInstaller</code> même si vous êtes membre du groupe Administrateurs. De plus, un pilote en ring0 peut intercepter l'appel <code className="text-cyan-200">IRP_MJ_CREATE</code> pour renvoyer une erreur d'accès. Notre script contourne ce piège via les privilèges de token et la réécriture du Session Manager.
            </p>
          </div>
        </div>
      </div>

      {/* Secondary Tools: IFEO Debugger Traps & Watchdogs Suspension */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* IFEO Trap Audit */}
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              Détournements IFEO (Debugger Trap)
            </h3>
            <button
              onClick={() => onRunInConsole('ifeo')}
              className="flex items-center gap-1 text-xs px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded transition-colors"
            >
              <RefreshCw className="w-3 h-3" />
              <span>Vérifier Registre</span>
            </button>
          </div>
          <p className="text-xs text-slate-400">
            Les trojans ajoutent souvent une valeur <code className="text-amber-300">Debugger</code> sous la clé <code className="text-slate-300">Image File Execution Options</code> pour neutraliser les outils d'analyse :
          </p>
          <div className="divide-y divide-slate-800 text-xs">
            <div className="py-2 flex items-center justify-between">
              <span className="font-mono text-slate-300">taskmgr.exe (Gestionnaire des tâches)</span>
              <span className="text-emerald-400 font-medium">Sain (Pas de hook)</span>
            </div>
            <div className="py-2 flex items-center justify-between">
              <span className="font-mono text-slate-300">cmd.exe / powershell.exe</span>
              <span className="text-emerald-400 font-medium">Sain (Pas de hook)</span>
            </div>
            <div className="py-2 flex items-center justify-between">
              <span className="font-mono text-slate-300">MpCmdRun.exe (Windows Defender)</span>
              <span className="text-emerald-400 font-medium">Sain (Pas de hook)</span>
            </div>
            <div className="py-2 flex items-center justify-between">
              <span className="font-mono text-slate-300">regedit.exe & procmon.exe</span>
              <span className="text-emerald-400 font-medium">Sain (Pas de hook)</span>
            </div>
          </div>
        </div>

        {/* Watchdogs Neutralizer */}
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              Anti-Watchdogs (Processus Mutuels)
            </h3>
            <button
              onClick={() => onRunInConsole('suspend swisyn')}
              className="flex items-center gap-1 text-xs px-2.5 py-1 bg-rose-950/80 hover:bg-rose-900 border border-rose-800/60 text-rose-300 rounded transition-colors"
            >
              <span>Geler & Tuer Watchdogs</span>
            </button>
          </div>
          <p className="text-xs text-slate-400">
            Certains malwares fonctionnent par paire : dès qu'un processus est terminé, son jumeau le ré-exécute en une fraction de seconde.
          </p>
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Solution implémentée :</span>
              <span className="text-cyan-400 font-mono font-semibold">NtSuspendProcess API</span>
            </div>
            <p className="text-[11px] text-slate-400">
              Le script appelle directement <code className="text-amber-300">ntdll.dll!NtSuspendProcess</code> sur tous les handles suspects simultanément. Les threads étant figés en mémoire vive, aucun watchdog ne peut réagir avant l'abattage par <code className="text-rose-400">taskkill /F /T</code>.
            </p>
          </div>
        </div>
      </div>

      {/* BITSTracker Module: Background Intelligent Transfer Service Inspector & Cleaner */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-5 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-cyan-400" />
              <h3 className="text-base font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
                BITSTracker : Traque & Purge des Tâches Asynchrones (Background Intelligent Transfer Service)
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 font-semibold">
                MITRE T1197 BITS Jobs
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 font-sans">
              Interception des transferts silencieux en arrière-plan exploités par les trojans pour télécharger des payloads secondaires ou exfiltrer des données sans alerter le pare-feu.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              onClick={() => onRunInConsole('bits')}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
              <span>Auditer BITS (Terminal)</span>
            </button>

            {bitsJobs.some(j => j.isSuspicious) && (
              <button
                onClick={handlePurgeAllSuspiciousBits}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold transition-colors shadow-sm"
              >
                <Ban className="w-3.5 h-3.5" />
                <span>Purger Toutes les Tâches Suspectes</span>
              </button>
            )}
          </div>
        </div>

        {/* Technical Callout */}
        <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 space-y-1.5">
          <div className="font-semibold text-cyan-300 flex items-center gap-2 font-mono">
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>Pourquoi les malwares abusent-ils de BITS (bitsadmin / Start-BitsTransfer) ?</span>
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
            Contrairement à une connexion TCP directe, un transfert BITS est délégué au service hôte système <code className="text-slate-300">svchost.exe (netsvcs)</code>. Il utilise la bande passante résiduelle, survit aux redémarrages de l'ordinateur, contourne la plupart des pare-feux applicatifs et permet d'exécuter un binaire via son paramètre de notification (<code className="text-amber-300">-SetNotifyCmdLine</code>) dès que le fichier est reconstitué.
          </p>
        </div>

        {/* BITS Jobs Table */}
        <div className="border border-slate-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3 font-semibold">Tâche (GUID & Nom)</th>
                  <th className="py-2.5 px-3 font-semibold">Direction / Type</th>
                  <th className="py-2.5 px-3 font-semibold">URL Distante (C2 / Serveur)</th>
                  <th className="py-2.5 px-3 font-semibold">Destination Locale</th>
                  <th className="py-2.5 px-3 font-semibold">Progression</th>
                  <th className="py-2.5 px-3 font-semibold">Statut & Menace</th>
                  <th className="py-2.5 px-3 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
                {bitsJobs.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-6 text-center text-slate-500 font-sans">
                      Aucune tâche de transfert BITS active. File d'attente saine.
                    </td>
                  </tr>
                ) : (
                  bitsJobs.map(job => (
                    <tr
                      key={job.id}
                      className={`transition-colors ${
                        job.isSuspicious
                          ? 'bg-rose-950/20 hover:bg-rose-950/30'
                          : 'hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="py-2.5 px-3">
                        <div className="font-semibold text-slate-200">
                          {job.jobName}
                        </div>
                        <div className="text-[10px] text-slate-500 truncate max-w-[150px]">
                          {job.id}
                        </div>
                        <div className="text-[10px] text-slate-400 font-sans mt-0.5">
                          Propriétaire: {job.owner}
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`flex items-center gap-1 font-bold text-[11px] ${
                            job.direction === 'UPLOAD_EXFIL' ? 'text-amber-400' : 'text-cyan-400'
                          }`}
                        >
                          {job.direction === 'UPLOAD_EXFIL' ? (
                            <>
                              <ArrowUpRight className="w-3.5 h-3.5 text-rose-400" />
                              <span>Exfiltration POST</span>
                            </>
                          ) : (
                            <>
                              <ArrowDownLeft className="w-3.5 h-3.5 text-cyan-400" />
                              <span>Download Payload</span>
                            </>
                          )}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300 max-w-[220px] truncate">
                        <span title={job.remoteUrl} className={job.isSuspicious ? 'text-rose-300 font-bold' : 'text-slate-300'}>
                          {job.remoteUrl}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 max-w-[180px] truncate text-[11px]">
                        <span title={job.localPath}>{job.localPath}</span>
                      </td>
                      <td className="py-2.5 px-3 tabular-nums text-slate-300">
                        {job.transferredBytes}
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              job.isSuspicious
                                ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            }`}
                          >
                            {job.isSuspicious ? 'SUSPECT' : 'LÉGITIME'}
                          </span>
                          <span className="text-slate-400 text-[10px]">({job.state})</span>
                        </div>
                        {job.threatDetails && (
                          <div className="text-[10px] text-rose-300 font-sans mt-0.5 max-w-[200px] leading-tight">
                            {job.threatDetails}
                          </div>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        {job.isSuspicious ? (
                          <button
                            onClick={() => handleCancelBitsJob(job.id)}
                            className="px-2.5 py-1 bg-rose-600 hover:bg-rose-500 text-white rounded text-[11px] font-semibold transition-colors"
                          >
                            Annuler & Supprimer
                          </button>
                        ) : (
                          <button
                            onClick={() => handleCancelBitsJob(job.id)}
                            className="px-2 py-1 text-slate-400 hover:text-slate-200 text-[11px] transition-colors"
                          >
                            Arrêter
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Shared Command Runner Modal */}
      <SharedCommandModal
        isOpen={isSharedCommandModalOpen}
        onClose={() => setIsSharedCommandModalOpen(false)}
        selectedThreats={selectedThreatsList}
        onExecuteSharedCommand={handleExecuteSharedCommand}
      />
    </div>
  );
};
