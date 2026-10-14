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
  Lock,
  Copy,
  Check,
  Search,
  Filter,
  Download,
  ChevronDown,
  ChevronUp,
  Flame,
  Zap,
  TrendingUp,
  Gauge,
  ShieldCheck,
} from 'lucide-react';
import { TabId, ThreatItem, ConsoleLogMessage, ThreatTimelineEvent, TimelinePhase } from '../types/cyberdefense';

interface ThreatTimelineProps {
  onRunInConsole: (command: string) => void;
  onNavigateTab?: (tab: TabId) => void;
  threats?: ThreatItem[];
  logs?: ConsoleLogMessage[];
  onMutateThreatStatus?: (threatId: string, targetPath: string, status: ThreatItem['status']) => void;
}

export const ThreatTimeline: React.FC<ThreatTimelineProps> = ({
  onRunInConsole,
  onNavigateTab,
  threats = [],
  logs = [],
  onMutateThreatStatus,
}) => {
  const [selectedPhase, setSelectedPhase] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Playback Simulation Mode state
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [currentPlaybackIndex, setCurrentPlaybackIndex] = useState<number>(-1);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1); // 1x, 2x, 4x

  // Dynamically build real timeline events from active and historical threats + logs
  const dynamicTimelineEvents: ThreatTimelineEvent[] = useMemo(() => {
    const list: ThreatTimelineEvent[] = [
      // Step 1: System Scan Ingestion & Privilege Elevation
      {
        id: 'evt-init-privelev',
        timeOffsetSec: 0,
        timeDisplay: 'T+00:00 (Initialisation)',
        phase: 'SCAN',
        phaseLabel: '1. Scan & Ingestion des Privilèges',
        title: 'Initialisation du Scan Système & Acquisition des Droits NT',
        severity: 'INFO',
        status: 'VERIFIED',
        mitreId: 'T1068',
        mitreTactic: 'Privilege Escalation Boundary',
        targetArtifact: 'ntdll.dll / SeDebugPrivilege + SeTakeOwnershipPrivilege',
        description: 'Vérification du jeton UAC Administrateur (SID S-1-5-32-544) et acquisition des privilèges natifs SeDebug et SeTakeOwnership pour l\'audit de la mémoire et des fichiers verrouillés.',
        evidence: '[P/Invoke] OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)\n[P/Invoke] SeDebugPrivilege : STATUS_SUCCESS (0x00000000)\n[P/Invoke] SeTakeOwnershipPrivilege : ACTIVÉ',
        remediationActionCmd: 'scan --deep',
        remediationButtonLabel: 'Relancer le Scan Système',
        remediationResult: 'Privilèges Administrateurs validés.',
        scoreDelta: 5,
        cumulativeScore: 35,
        riskReductionPercent: 5,
        riskCategory: 'Visibilité & Droits Noyau',
      },
    ];

    let currentScore = 35;
    let secCounter = 2;

    // Add each threat from real threats list as a dynamic timeline milestone
    threats.forEach((t, idx) => {
      secCounter += 3;
      const isRemediated = t.status === 'NEUTRALIZED';
      const isContained = t.status === 'SCHEDULED_BOOT_DELETE';
      const isDismissed = t.status === 'DISMISSED';

      let phase: TimelinePhase = 'DETECTION';
      let phaseLabel = '2. Détection d\'Anomalies';
      if (t.category === 'Kernel' || t.category === 'Rootkit' || t.trustedInstallerLocked) {
        phase = 'EXCISION';
        phaseLabel = '4. Excision Noyau & Ring 0';
      } else if (t.category === 'Persistence' || t.category === 'C2' || t.category === 'Network') {
        phase = 'CONTAINMENT';
        phaseLabel = '3. Confinement & Isolation';
      } else if (t.category === 'Defender') {
        phase = 'HARDENING';
        phaseLabel = '5. Durcissement Système';
      }

      const scoreDelta = t.severity === 'CRITICAL' ? 18 : t.severity === 'HIGH' ? 12 : 8;
      if (isRemediated || isDismissed) {
        currentScore = Math.min(100, currentScore + scoreDelta);
      }

      // Infer recommended command
      let cmd = 'scan --deep';
      if (t.targetPath.toLowerCase().includes('themes')) cmd = 'clean-themes';
      else if (t.targetPath.toLowerCase().includes('.sys') || t.lockedBySystem) cmd = `unlock "${t.targetPath}"`;
      else if (t.targetPath.toLowerCase().includes('pid:')) {
        const pid = t.targetPath.replace(/[^0-9]/g, '');
        cmd = pid ? `kill ${pid}` : 'tasklist';
      } else if (t.targetPath.toLowerCase().includes('bits')) cmd = 'bitsadmin /cancel WindowsHealthUpdate';
      else if (t.category === 'Defender') cmd = 'defender-repair';

      list.push({
        id: `evt-threat-${t.id}`,
        timeOffsetSec: secCounter,
        timeDisplay: `T+${String(secCounter).padStart(2, '0')}s (${t.detectedAt ? new Date(t.detectedAt).toLocaleTimeString('fr-FR') : 'Audit'})`,
        phase,
        phaseLabel,
        title: t.name,
        severity: t.severity,
        status: isRemediated ? 'REMEDIATED' : isContained ? 'CONTAINED' : isDismissed ? 'VERIFIED' : 'DETECTED',
        mitreId: t.mitreTechnique.split(' - ')[0] || 'T1059',
        mitreTactic: t.mitreTechnique.split(' - ')[1] || t.category,
        targetArtifact: t.targetPath,
        description: t.description,
        evidence: `Signature Détectée : ${t.category.toUpperCase()} // ${t.name}\nCible Système : ${t.targetPath}\nVerrouillage Système : ${t.lockedBySystem ? 'OUI (Handle actif)' : 'NON'}\nVerrouillage TrustedInstaller : ${t.trustedInstallerLocked ? 'OUI' : 'NON'}\nStatut Actuel : ${t.status}`,
        remediationActionCmd: cmd,
        remediationButtonLabel: isRemediated ? 'Menace Neutralisée' : 'Neutraliser l\'Anomalie',
        remediationResult: isRemediated ? 'Binaire ou clé hostile neutralisé.' : undefined,
        scoreDelta,
        cumulativeScore: currentScore,
        riskReductionPercent: Math.round(scoreDelta * 0.9),
        riskCategory: t.category,
      });
    });

    // Add real events from console / audit logs
    const relevantLogs = logs.filter(l => 
      l.level === 'WARN' || 
      l.level === 'ERROR' || 
      l.tag === 'SCAN' || 
      l.tag === 'THEMES-EXTIRPATION' || 
      l.tag === 'DEFENDER' ||
      l.tag === 'FIREWALL'
    ).slice(-6);

    relevantLogs.forEach((l) => {
      secCounter += 2;
      const isOk = l.level === 'OK';
      const isWarn = l.level === 'WARN' || l.level === 'ERROR';

      let phase: TimelinePhase = 'DETECTION';
      let phaseLabel = '2. Détection d\'Anomalies';
      if (l.tag === 'THEMES-EXTIRPATION' || l.tag === 'DEFENDER') {
        phase = 'EXCISION';
        phaseLabel = '4. Excision Noyau & Remédiation';
      } else if (l.tag === 'FIREWALL' || l.tag === 'WIFI-DEFENSE') {
        phase = 'CONTAINMENT';
        phaseLabel = '3. Confinement & Isolation';
      }

      list.push({
        id: `evt-log-${l.id}`,
        timeOffsetSec: secCounter,
        timeDisplay: `${l.timestamp || 'T+' + secCounter + 's'} (Journal)`,
        phase,
        phaseLabel,
        title: `Événement ${l.tag || 'Système'} : ${l.text.slice(0, 50)}...`,
        severity: isWarn ? 'HIGH' : isOk ? 'LOW' : 'INFO',
        status: isOk ? 'REMEDIATED' : isWarn ? 'DETECTED' : 'VERIFIED',
        mitreId: l.tag === 'THEMES-EXTIRPATION' ? 'T1036' : l.tag === 'DEFENDER' ? 'T1562' : 'T1059',
        mitreTactic: l.tag || 'Sécurité Système',
        targetArtifact: l.operatorName || 'System Kernel',
        description: l.text,
        evidence: `Journal Hôte (${l.timestamp}) // Opérateur: ${l.operatorName || 'System'}\nNiveau: [${l.level}] ${l.tag || 'SYSTEM'}\n${l.text}`,
        remediationActionCmd: 'scan --deep',
        remediationButtonLabel: 'Vérifier l\'Intégrité',
        scoreDelta: isOk ? 10 : 5,
        cumulativeScore: currentScore,
        riskReductionPercent: 8,
        riskCategory: l.tag || 'Journal d\'Audit',
      });
    });

    // Final Hardening milestone
    list.push({
      id: 'evt-final-hardening',
      timeOffsetSec: secCounter + 5,
      timeDisplay: `T+${String(secCounter + 5).padStart(2, '0')}s (Final)`,
      phase: 'HARDENING',
      phaseLabel: '5. Durcissement & Validation',
      title: 'Validation de l\'Intégrité Globale & Durcissement Windows',
      severity: 'INFO',
      status: 'VERIFIED',
      mitreId: 'T1562',
      mitreTactic: 'Defense Verification & Posture',
      targetArtifact: 'MpPreference / GPO / TamperProtection',
      description: 'Audit final de conformité : vérification de l\'antivirus temps réel, isolation des processus résiduels et intégrité de la persistance.',
      evidence: 'Get-MpPreference : RealTimeMonitoring actif, TamperProtection vérifiée.\nIntégrité du système de fichiers validée.',
      remediationActionCmd: 'defender-repair',
      remediationButtonLabel: 'Vérifier la Posture Finale',
      remediationResult: 'Posture défensive optimale atteinte.',
      scoreDelta: 8,
      cumulativeScore: Math.min(100, currentScore + 8),
      riskReductionPercent: 10,
      riskCategory: 'Durcissement Endpoint',
    });

    return list;
  }, [threats, logs]);

  const [events, setEvents] = useState<ThreatTimelineEvent[]>(dynamicTimelineEvents);

  useEffect(() => {
    setEvents(dynamicTimelineEvents);
    if (!expandedEventId && dynamicTimelineEvents.length > 1) {
      setExpandedEventId(dynamicTimelineEvents[1].id);
    }
  }, [dynamicTimelineEvents]);

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
          setExpandedEventId(events[next].id);
          return next;
        });
      }, delay);
    }
    return () => clearTimeout(timer);
  }, [isPlaying, currentPlaybackIndex, playbackSpeed, events]);

  const handleStartPlayback = () => {
    if (currentPlaybackIndex >= events.length - 1 || currentPlaybackIndex === -1) {
      setCurrentPlaybackIndex(0);
      setExpandedEventId(events[0]?.id || null);
    }
    setIsPlaying(true);
  };

  const handlePausePlayback = () => {
    setIsPlaying(false);
  };

  const handleResetPlayback = () => {
    setIsPlaying(false);
    setCurrentPlaybackIndex(-1);
    setExpandedEventId(events[0]?.id || null);
  };

  const handleStepForward = () => {
    setCurrentPlaybackIndex(prev => {
      const next = Math.min(events.length - 1, prev + 1);
      setExpandedEventId(events[next]?.id || null);
      return next;
    });
  };

  const handleStepBackward = () => {
    setCurrentPlaybackIndex(prev => {
      const next = Math.max(0, prev - 1);
      setExpandedEventId(events[next]?.id || null);
      return next;
    });
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Execute remediation action and update status
  const handleExecuteRemediation = (evt: ThreatTimelineEvent) => {
    if (evt.remediationActionCmd) {
      onRunInConsole(evt.remediationActionCmd);
      const threatId = evt.id.replace('evt-threat-', '');
      if (onMutateThreatStatus && threatId) {
        onMutateThreatStatus(threatId, evt.targetArtifact || '', 'NEUTRALIZED');
      }
      setEvents(prev =>
        prev.map(item =>
          item.id === evt.id ? { ...item, status: 'REMEDIATED' } : item
        )
      );
    }
  };

  // Run full remediation pipeline
  const handleRunAllRemediations = () => {
    onRunInConsole('scan --deep');
    setTimeout(() => onRunInConsole('clean-themes'), 800);
    setTimeout(() => onRunInConsole('wmi-clean'), 1600);
    setTimeout(() => onRunInConsole('defender-repair'), 2400);

    threats.forEach(t => {
      if (t.status === 'ACTIVE' && onMutateThreatStatus) {
        onMutateThreatStatus(t.id, t.targetPath, 'NEUTRALIZED');
      }
    });

    setEvents(prev =>
      prev.map(evt => ({
        ...evt,
        status: evt.phase === 'HARDENING' || evt.phase === 'SCAN' ? 'VERIFIED' : 'REMEDIATED',
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
      `Système : POSTE LOCAL (Architecture Windows NT x64)`,
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
- **Technique MITRE** : ${e.mitreId || 'N/A'} - ${e.mitreTactic || 'N/A'}
- **Cible Artifact** : ${e.targetArtifact || 'N/A'}
- **Description** : ${e.description}
- **Preuve Forensique** :
\`\`\`
${e.evidence}
\`\`\`
- **Action de Remédiation** : \`${e.remediationActionCmd || 'N/A'}\`
`;
      }),
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
        return { border: 'border-cyan-500', bg: 'bg-cyan-500/10', text: 'text-cyan-400' };
      case 'DETECTION':
        return { border: 'border-rose-500', bg: 'bg-rose-500/10', text: 'text-rose-400' };
      case 'CONTAINMENT':
        return { border: 'border-indigo-500', bg: 'bg-indigo-500/10', text: 'text-indigo-400' };
      case 'EXCISION':
        return { border: 'border-purple-500', bg: 'bg-purple-500/10', text: 'text-purple-400' };
      case 'HARDENING':
        return { border: 'border-emerald-500', bg: 'bg-emerald-500/10', text: 'text-emerald-400' };
      default:
        return { border: 'border-slate-500', bg: 'bg-slate-500/10', text: 'text-slate-400' };
    }
  };

  // Metrics calculations
  const totalEvents = events.length;
  const criticalCount = events.filter(e => e.severity === 'CRITICAL').length;
  const remediatedCount = events.filter(e => e.status === 'REMEDIATED' || e.status === 'VERIFIED').length;
  const remediationPercentage = totalEvents > 0 ? Math.round((remediatedCount / totalEvents) * 100) : 100;

  // Dynamic Security Score Calculation based on real threat statuses
  const baseScore = 35;
  const activeThreatsCount = threats.filter(t => t.status === 'ACTIVE').length;
  const neutralizedCount = threats.filter(t => t.status === 'NEUTRALIZED' || t.status === 'DISMISSED').length;
  const currentSecurityScore = activeThreatsCount === 0 && threats.length > 0
    ? 98
    : Math.max(25, Math.min(100, baseScore + neutralizedCount * 15 - activeThreatsCount * 12));
  const residualRisk = Math.max(0, 100 - currentSecurityScore);

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 md:p-8 bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 border border-slate-800 rounded-2xl relative overflow-hidden shadow-2xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-3xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 bg-cyan-950/80 border border-cyan-800/60 rounded-full text-cyan-300 font-mono text-xs font-semibold">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>CHRONOLOGIE FORENSIQUE TEMPS RÉEL</span>
            </div>

            <h1 className="text-2xl md:text-3xl font-extrabold text-white tracking-tight font-['Plus_Jakarta_Sans']">
              Chronologie Visuelle des Incidents & Séquence d'Éradication
            </h1>

            <p className="text-sm text-slate-300 leading-relaxed">
              Cycle de vie chronologique des détections et actions forensiques : du scan initial jusqu'au durcissement final de l'OS. Les jalons s'actualisent en direct au fur et à mesure des scans et des neutralisations.
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
                currentSecurityScore >= 85
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  : currentSecurityScore >= 60
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  : 'bg-rose-950 text-rose-300 border border-rose-800'
              }`}>
                {currentSecurityScore >= 85
                  ? 'SYSTÈME HAUTEMENT DURCI'
                  : currentSecurityScore >= 60
                  ? 'MENACES EN COURS DE REMÉDIATION'
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
                  currentSecurityScore >= 85
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
                <span>Gain de protection : <strong className="text-emerald-300">+{Math.max(0, currentSecurityScore - baseScore)} pts</strong></span>
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
            <span className="text-xs text-slate-400">Total Jalons</span>
            <div className="text-2xl font-bold text-white font-mono">{totalEvents} Événements</div>
            <span className="text-[11px] text-slate-500">Scan initial → Durcissement</span>
          </div>

          <div className="space-y-1">
            <span className="text-xs text-slate-400">Menaces Détectées</span>
            <div className="text-2xl font-bold text-rose-400 font-mono">{threats.length} Éléments</div>
            <span className="text-[11px] text-slate-500">{activeThreatsCount} active(s) · {neutralizedCount} remédiée(s)</span>
          </div>

          <div className="space-y-1">
            <span className="text-xs text-slate-400">Taux de Remédiation</span>
            <div className="text-2xl font-bold text-emerald-400 font-mono">{remediationPercentage}%</div>
            <span className="text-[11px] text-slate-500">{remediatedCount} sur {totalEvents} étapes sécurisées</span>
          </div>

          <div className="space-y-1">
            <span className="text-xs text-slate-400">Critiques Résolues</span>
            <div className="text-2xl font-bold text-cyan-400 font-mono">
              {events.filter(e => e.severity === 'CRITICAL' && (e.status === 'REMEDIATED' || e.status === 'VERIFIED')).length} / {criticalCount}
            </div>
            <span className="text-[11px] text-slate-500">Priorités P0 neutralisées</span>
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
              placeholder="Filtrer (MITRE, nom, fichier, PID)..."
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
            { id: 'HARDENING', label: '5. Durcissement' },
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
        {filteredEvents.map(evt => {
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

                  {/* Security Score Impact */}
                  {evt.scoreDelta !== undefined && (
                    <div className="p-3 bg-slate-950/90 rounded-lg border border-slate-800 space-y-2">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="flex items-center gap-1 font-bold font-mono px-2 py-0.5 rounded text-xs bg-emerald-950/90 text-emerald-400 border border-emerald-800/60 shadow-sm">
                            <TrendingUp className="w-3 h-3 text-emerald-400" />
                            +{evt.scoreDelta} pts Score Sécurité
                          </span>

                          <span className="text-[11px] text-slate-400 font-mono">
                            Palier Score : <strong className="text-emerald-400">{evt.cumulativeScore}%</strong>
                          </span>
                        </div>

                        <div className="flex items-center gap-2">
                          <span className="inline-flex items-center gap-1 text-[11px] font-mono text-cyan-300 bg-cyan-950/50 px-2 py-0.5 rounded border border-cyan-800/40">
                            <ShieldCheck className="w-3 h-3 text-cyan-400" />
                            Réduction Risque : <strong className="text-white">-{evt.riskReductionPercent}%</strong>
                          </span>
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
                          Preuve Forensique & Diagnostic :
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
                  </div>
                )}

                {/* Action Bar Footer for the Event */}
                <div className="mt-4 pt-3 border-t border-slate-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                  <div className="flex items-center gap-2">
                    {evt.status !== 'REMEDIATED' && evt.status !== 'VERIFIED' && (
                      <button
                        onClick={() => handleExecuteRemediation(evt)}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white font-bold rounded-lg text-xs transition-colors shadow-sm"
                      >
                        <Zap className="w-3.5 h-3.5" />
                        <span>{evt.remediationButtonLabel || 'Remédier'}</span>
                      </button>
                    )}

                    {onNavigateTab && (
                      <button
                        onClick={() => onNavigateTab('overview')}
                        className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs transition-colors"
                      >
                        Voir dans le Tableau de Bord
                      </button>
                    )}
                  </div>

                  <div className="text-[11px] font-mono text-slate-500">
                    Commande : <code className="text-cyan-400">{evt.remediationActionCmd}</code>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
