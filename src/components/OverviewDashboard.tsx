import React, { useState, useMemo } from 'react';
import {
  Shield,
  ShieldAlert,
  Cpu,
  Network,
  Lock,
  Terminal,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Play,
  Download,
  Archive,
  Clock,
  Zap,
  Filter,
  Search,
  Flame,
  ArrowUpDown,
  X,
  Info,
  FileText,
  Binary,
  FileCode,
  CheckSquare,
  Square,
  MinusSquare,
  EyeOff,
  RotateCcw,
  Layers,
  Trash2,
  CheckCheck,
  Code2,
  Undo2,
} from 'lucide-react';
import { TabId, ThreatItem } from '../types/cyberdefense';
import { ThreatHeatmap } from './ThreatHeatmap';
import { ThreatIntensityMap } from './ThreatIntensityMap';
import { ThreatCategoryDonutChart } from './ThreatCategoryDonutChart';
import { VulnerabilityRadarChart } from './VulnerabilityRadarChart';
import { SharedCommandModal } from './SharedCommandModal';
import { calculateSecurityScore } from '../utils/pdfReportGenerator';

interface OverviewDashboardProps {
  onNavigateTab: (tab: TabId) => void;
  onRunInConsole: (command: string) => void;
  threats: ThreatItem[];
  onDownloadZip: () => void;
  onDownloadScript?: () => void;
  onOpenPdfReport?: () => void;
  onMutateThreatStatus?: (threatId: string, targetPath: string, status: ThreatItem['status']) => void;
  onBulkMutateThreatStatus?: (threatIds: string[], status: ThreatItem['status'], command?: string) => void;
  onMassDismissThreats?: (threatIds: string[]) => void;
  onRestoreThreats?: (threatIds: string[]) => void;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  onNavigateTab,
  onRunInConsole,
  threats,
  onDownloadZip,
  onDownloadScript,
  onOpenPdfReport,
  onMutateThreatStatus,
  onBulkMutateThreatStatus,
  onMassDismissThreats,
  onRestoreThreats,
}) => {
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM'>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [searchThreatQuery, setSearchThreatQuery] = useState<string>('');
  const [sortBySeverity, setSortBySeverity] = useState<boolean>(true);
  const [selectedThreatIds, setSelectedThreatIds] = useState<Set<string>>(new Set());
  const [showDismissedThreats, setShowDismissedThreats] = useState<boolean>(false);
  const [isSharedCommandModalOpen, setIsSharedCommandModalOpen] = useState<boolean>(false);
  const [bulkFeedbackMessage, setBulkFeedbackMessage] = useState<string | null>(null);
  const [recentlyDismissedIds, setRecentlyDismissedIds] = useState<string[]>([]);

  // Counts by severity
  // Security Score calculation
  const scoreData = useMemo(() => calculateSecurityScore(threats), [threats]);
  const { criticalCount, highCount, mediumCount } = scoreData;

  const severityWeight: Record<string, number> = {
    CRITICAL: 3,
    HIGH: 2,
    MEDIUM: 1,
    LOW: 0,
  };

  const dismissedCount = useMemo(() => {
    return threats.filter(t => t.status === 'DISMISSED').length;
  }, [threats]);

  // Filtered and sorted threat list
  const displayedThreats = useMemo(() => {
    return threats
      .filter(threat => {
        if (!showDismissedThreats && threat.status === 'DISMISSED') {
          return false;
        }
        if (severityFilter !== 'ALL' && threat.severity !== severityFilter) {
          return false;
        }
        if (categoryFilter !== 'ALL') {
          const normThreatCat = threat.category === 'Rootkit' ? 'Kernel' : threat.category;
          if (normThreatCat !== categoryFilter && threat.category !== categoryFilter) {
            return false;
          }
        }
        if (searchThreatQuery.trim()) {
          const q = searchThreatQuery.toLowerCase();
          const matches =
            threat.name.toLowerCase().includes(q) ||
            Boolean(threat.description && threat.description.toLowerCase().includes(q)) ||
            threat.targetPath.toLowerCase().includes(q) ||
            threat.mitreTechnique.toLowerCase().includes(q) ||
            threat.category.toLowerCase().includes(q);
          if (!matches) return false;
        }
        return true;
      })
      .sort((a, b) => {
        if (sortBySeverity) {
          return (severityWeight[b.severity] || 0) - (severityWeight[a.severity] || 0);
        }
        return 0;
      });
  }, [threats, severityFilter, categoryFilter, searchThreatQuery, sortBySeverity, showDismissedThreats]);

  const selectedThreatsList = useMemo(() => {
    return threats.filter(t => selectedThreatIds.has(t.id));
  }, [threats, selectedThreatIds]);

  // Selection handlers
  const toggleSelectThreat = (id: string) => {
    setSelectedThreatIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleToggleSelectAll = () => {
    if (selectedThreatIds.size === displayedThreats.length && displayedThreats.length > 0) {
      setSelectedThreatIds(new Set());
    } else {
      setSelectedThreatIds(new Set(displayedThreats.map(t => t.id)));
    }
  };

  const handleSelectActiveOnly = () => {
    const active = displayedThreats.filter(t => t.status === 'ACTIVE').map(t => t.id);
    setSelectedThreatIds(new Set(active));
  };

  const handleSelectCriticalOnly = () => {
    const crit = displayedThreats.filter(t => t.severity === 'CRITICAL' && t.status === 'ACTIVE').map(t => t.id);
    setSelectedThreatIds(new Set(crit));
  };

  const handleClearSelection = () => {
    setSelectedThreatIds(new Set());
  };

  // Bulk Actions
  const handleBulkKernelUnlock = () => {
    if (selectedThreatIds.size === 0) return;
    const targetThreats = threats.filter(t => selectedThreatIds.has(t.id));
    const ids = targetThreats.map(t => t.id);

    onRunInConsole(`bulk-unlock ${ids.join(',')}`);
    if (onBulkMutateThreatStatus) {
      onBulkMutateThreatStatus(ids, 'SCHEDULED_BOOT_DELETE', 'Éradication Kernel');
    }
    setBulkFeedbackMessage(`Éradication kernel programmée sur ${ids.length} menace(s).`);
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
    setBulkFeedbackMessage(`${ids.length} menace(s) transférée(s) en quarantaine chiffrée.`);
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
    setBulkFeedbackMessage(`${ids.length} menace(s) rejetée(s) et archivée(s).`);
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
    setBulkFeedbackMessage(`${recentlyDismissedIds.length} menace(s) restaurée(s).`);
    setRecentlyDismissedIds([]);
    setTimeout(() => setBulkFeedbackMessage(null), 3000);
  };

  const handleRestoreSingle = (threatId: string) => {
    if (onRestoreThreats) {
      onRestoreThreats([threatId]);
    } else if (onMutateThreatStatus) {
      const threat = threats.find(t => t.id === threatId);
      onMutateThreatStatus(threatId, threat?.targetPath || '', 'ACTIVE');
    }
    setBulkFeedbackMessage(`Menace réactivée dans la liste active.`);
    setTimeout(() => setBulkFeedbackMessage(null), 3000);
  };

  const handleSingleDismiss = (threatId: string) => {
    setRecentlyDismissedIds([threatId]);
    if (onMassDismissThreats) {
      onMassDismissThreats([threatId]);
    } else if (onMutateThreatStatus) {
      const threat = threats.find(t => t.id === threatId);
      onMutateThreatStatus(threatId, threat?.targetPath || '', 'DISMISSED');
    }
    setBulkFeedbackMessage(`Menace ignorée/rejetée.`);
    setTimeout(() => setBulkFeedbackMessage(null), 4000);
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

    setBulkFeedbackMessage(`Commande partagée appliquée sur ${targets.length} cibles.`);
    setTimeout(() => setBulkFeedbackMessage(null), 4000);
    handleClearSelection();
  };
  return (
    <div className="space-y-6">
      {/* Hero Central Header */}
      <div className="p-6 md:p-8 bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 border border-slate-800 rounded-2xl relative overflow-hidden shadow-2xl">
        <div className="max-w-3xl space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-cyan-950/80 border border-cyan-800/60 rounded-full text-cyan-300 font-mono text-xs font-semibold">
            <Shield className="w-3.5 h-3.5 text-cyan-400" />
            <span>SpaceSec CyberDefense Engine · KERNEL & SYSTEM EDITION v3.0</span>
          </div>

          <h1 className="text-2xl md:text-3xl font-extrabold text-white tracking-tight font-['Plus_Jakarta_Sans']">
            Poste de Commandement Cyberdéfense & Éradication Racine
          </h1>

          <p className="text-sm text-slate-300 leading-relaxed max-w-2xl">
            Conçu pour les ingénieurs en cybersécurité et développeurs système : débusque les virus enfouis dans le système d'exploitation,
            brise les verrous <strong className="text-cyan-300">TrustedInstaller</strong>, neutralise les watchdogs mutuels
            et détruit les payloads verrouillés directement au démarrage du noyau Windows via <code className="text-amber-300 font-mono text-xs">PendingFileRenameOperations</code>.
          </p>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <button
              onClick={onDownloadZip}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold rounded-lg text-xs transition-colors shadow-sm"
            >
              <Archive className="w-3.5 h-3.5" />
              <span>Télécharger le Pack ZIP (.zip)</span>
            </button>

            {onOpenPdfReport && (
              <button
                onClick={onOpenPdfReport}
                className="flex items-center gap-2 px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-bold rounded-lg text-xs transition-colors shadow-md shadow-rose-900/30"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Générer Rapport PDF (Score Sécurité)</span>
              </button>
            )}

            <button
              onClick={() => onNavigateTab('timeline')}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-950/90 hover:bg-cyan-900 border border-cyan-700/80 text-cyan-300 font-bold rounded-lg text-xs transition-colors shadow-sm"
            >
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>Chronologie Visuelle des Menaces</span>
            </button>

            <button
              onClick={() => onNavigateTab('heuristic')}
              className="flex items-center gap-2 px-4 py-2 bg-amber-950/90 hover:bg-amber-900 border border-amber-700/80 text-amber-300 font-bold rounded-lg text-xs transition-colors shadow-sm"
            >
              <Binary className="w-3.5 h-3.5 text-amber-400" />
              <span>Moteur Heuristique & Entropie</span>
            </button>

            <button
              onClick={() => onRunInConsole('scan --deep')}
              className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold rounded-lg text-xs transition-colors"
            >
              <Play className="w-3.5 h-3.5 text-cyan-400" />
              <span>Lancer le Scan Complet Approfondi</span>
            </button>

            <button
              onClick={() => onNavigateTab('deep-excision')}
              className="flex items-center gap-2 px-4 py-2 bg-rose-950/80 hover:bg-rose-900 border border-rose-800/80 text-rose-300 font-semibold rounded-lg text-xs transition-colors"
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>Éradiquer un Fichier Verrouillé</span>
            </button>

            <button
              onClick={() => onNavigateTab('console')}
              className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium rounded-lg text-xs transition-colors"
            >
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              <span>Ouvrir la Console Live</span>
            </button>
          </div>
        </div>
      </div>

      {/* Security Score Posture Banner with PDF Export Button */}
      <div className="p-5 bg-gradient-to-r from-slate-900 via-slate-900/95 to-slate-950 border border-slate-800 rounded-2xl relative overflow-hidden shadow-xl">
        <div className="flex flex-col lg:flex-row items-center justify-between gap-6">
          
          {/* Left: Score Gauge Dial & Status Text */}
          <div className="flex items-center gap-5 w-full lg:w-auto">
            <div className="relative w-20 h-20 shrink-0 flex items-center justify-center">
              <svg className="w-20 h-20 transform -rotate-90" viewBox="0 0 100 100">
                <circle
                  cx="50"
                  cy="50"
                  r="40"
                  stroke="#1e293b"
                  strokeWidth="10"
                  fill="transparent"
                />
                <circle
                  cx="50"
                  cy="50"
                  r="40"
                  stroke={scoreData.ratingColor}
                  strokeWidth="10"
                  strokeDasharray={251.2}
                  strokeDashoffset={251.2 - (251.2 * scoreData.score) / 100}
                  strokeLinecap="round"
                  fill="transparent"
                  className="transition-all duration-700 ease-out"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="text-xl font-bold font-mono text-white leading-none">
                  {scoreData.score}
                </span>
                <span className="text-[9px] text-slate-400 font-mono">/ 100</span>
              </div>
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                  Indice de Sécurité Hôte & Ring0
                </span>
                <span
                  className="text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border"
                  style={{
                    color: scoreData.ratingColor,
                    borderColor: `${scoreData.ratingColor}50`,
                    backgroundColor: `${scoreData.ratingColor}15`,
                  }}
                >
                  {scoreData.ratingLabel}
                </span>
              </div>
              <p className="text-xs text-slate-300 max-w-xl leading-relaxed">
                Score calculé à partir des {scoreData.totalThreats} menaces identifiées :{' '}
                <strong className="text-rose-400">{scoreData.criticalCount} critique(s)</strong>,{' '}
                <strong className="text-orange-400">{scoreData.highCount} élevée(s)</strong>, et{' '}
                <strong className="text-emerald-400">{scoreData.neutralizedCount} en cours d'éradication / neutralisée(s)</strong>.
              </p>
            </div>
          </div>

          {/* Right: PDF Action Button */}
          {onOpenPdfReport && (
            <div className="flex items-center gap-3 w-full lg:w-auto shrink-0 justify-end">
              <button
                onClick={onOpenPdfReport}
                className="flex items-center gap-2.5 px-4 py-2.5 rounded-xl bg-gradient-to-r from-rose-600 to-rose-700 hover:from-rose-500 hover:to-rose-600 text-white font-bold text-xs shadow-lg shadow-rose-950/50 transition-all hover:scale-[1.02] active:scale-[0.98]"
              >
                <FileText className="w-4 h-4 text-white" />
                <span>Télécharger Rapport PDF Détaillé</span>
              </button>
            </div>
          )}

        </div>
      </div>

      {/* KPI Stats Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Privilèges Noyau</span>
            <span className="text-emerald-400 font-mono">ACTIF</span>
          </div>
          <div className="text-xl font-bold text-white font-mono">
            SeDebug + SeTakeOwnership
          </div>
          <div className="text-[11px] text-slate-500">
            Élévation automatique P/Invoke native
          </div>
        </div>

        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Menaces Détectées</span>
            <span className="text-rose-400 font-mono">ATTENTION</span>
          </div>
          <div className="text-xl font-bold text-rose-400 font-mono">
            {threats.filter(t => t.status === 'ACTIVE').length} Menace(s)
          </div>
          <div className="text-[11px] text-slate-500">
            Trojan verrouillé, LOLBin & C2 Socket
          </div>
        </div>

        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Modules de Sécurité</span>
            <span className="text-cyan-400 font-mono">READY</span>
          </div>
          <div className="text-xl font-bold text-white font-mono">
            25+ Modules
          </div>
          <div className="text-[11px] text-slate-500">
            Kernel, RAM, C2, ADS, WMI, Defender
          </div>
        </div>

        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Statut Windows Defender</span>
            <span className="text-emerald-400 font-mono">SÉCURISÉ</span>
          </div>
          <div className="text-xl font-bold text-emerald-400 font-mono">
            Tamper Protection OK
          </div>
          <div className="text-[11px] text-slate-500">
            DLLs cryptographiques opérationnelles
          </div>
        </div>
      </div>

      {/* Machine Vulnerability Radar Chart (Recharts: Services, Patchs, Ports Audits) */}
      <VulnerabilityRadarChart
        threats={threats}
        onNavigateTab={onNavigateTab}
        onRunInConsole={onRunInConsole}
      />

      {/* Threat Distribution Donut Chart (Recharts) */}
      <ThreatCategoryDonutChart
        threats={threats}
        selectedCategory={categoryFilter}
        onSelectCategory={setCategoryFilter}
      />

      {/* Threat Heatmap: System Areas Visualizer (Kernel, Registry, Startup, Filesystem) */}
      <ThreatHeatmap onRunInConsole={onRunInConsole} />

      {/* Threat Intensity Map: D3-based Heatmap Visualizing Geographical Origin of Malicious C2 Connections */}
      <ThreatIntensityMap onRunInConsole={onRunInConsole} onNavigateTab={onNavigateTab} />

      {/* Visual Threat Timeline Mini Preview & Gateway */}
      <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white tracking-tight">
              Chronologie des Menaces : Séquence Détection & Remédiation
            </h3>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800/60">
              T0 → T+25s
            </span>
          </div>

          <button
            onClick={() => onNavigateTab('timeline')}
            className="flex items-center gap-1.5 text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition-colors shrink-0 group"
          >
            <span>Ouvrir la Chronologie Interactive</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </button>
        </div>

        {/* Milestone Steps Visual Strip */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 pt-1">
          <div 
            onClick={() => onNavigateTab('timeline')}
            className="p-3 bg-slate-950 rounded-lg border border-slate-800 hover:border-cyan-800 cursor-pointer transition-colors space-y-1 group"
          >
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className="text-cyan-400 font-bold">1. SCAN T0</span>
              <span className="text-emerald-400">OK</span>
            </div>
            <div className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300">
              Élévation Privilèges NT
            </div>
            <div className="text-[10px] text-slate-500 font-mono">
              SeDebug & SeTakeOwnership
            </div>
          </div>

          <div 
            onClick={() => onNavigateTab('timeline')}
            className="p-3 bg-slate-950 rounded-lg border border-slate-800 hover:border-amber-800 cursor-pointer transition-colors space-y-1 group"
          >
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className="text-amber-400 font-bold">2. DÉTECTION T+2s</span>
              <span className="text-amber-400">LOLBin</span>
            </div>
            <div className="text-xs font-semibold text-slate-200 group-hover:text-amber-300">
              Abus certutil.exe
            </div>
            <div className="text-[10px] text-slate-500 font-mono">
              Téléchargement furtif en cache
            </div>
          </div>

          <div 
            onClick={() => onNavigateTab('timeline')}
            className="p-3 bg-slate-950 rounded-lg border border-slate-800 hover:border-rose-800 cursor-pointer transition-colors space-y-1 group"
          >
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className="text-rose-400 font-bold">3. ALERTE T+5s</span>
              <span className="text-rose-400">C2 Beacon</span>
            </div>
            <div className="text-xs font-semibold text-slate-200 group-hover:text-rose-300">
              Balisage Port 4444
            </div>
            <div className="text-[10px] text-slate-500 font-mono">
              Netstat Sockets TCP
            </div>
          </div>

          <div 
            onClick={() => onNavigateTab('timeline')}
            className="p-3 bg-slate-950 rounded-lg border border-slate-800 hover:border-purple-800 cursor-pointer transition-colors space-y-1 group"
          >
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className="text-purple-400 font-bold">4. EXCISION T+18s</span>
              <span className="text-purple-400">Kernel</span>
            </div>
            <div className="text-xs font-semibold text-slate-200 group-hover:text-purple-300">
              Dépossession TrustedInstaller
            </div>
            <div className="text-[10px] text-slate-500 font-mono">
              PendingFileRenameOperations
            </div>
          </div>

          <div 
            onClick={() => onNavigateTab('timeline')}
            className="p-3 bg-slate-950 rounded-lg border border-slate-800 hover:border-emerald-800 cursor-pointer transition-colors space-y-1 group"
          >
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className="text-emerald-400 font-bold">5. SÉCURISÉ T+25s</span>
              <span className="text-emerald-400">Vérifié</span>
            </div>
            <div className="text-xs font-semibold text-slate-200 group-hover:text-emerald-300">
              Purge WMI & Defender
            </div>
            <div className="text-[10px] text-slate-500 font-mono">
              Désactivation SMBv1 (WannaCry)
            </div>
          </div>
        </div>
      </div>

      {/* Main Grid: Active Threats + Modular Navigator */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Active Threat Watchlist */}
        <div className="lg:col-span-2 p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          {/* Header Row */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2 flex-wrap">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <h3 className="text-base font-semibold text-slate-100">
                Menaces Détectées en Attente d'Action
              </h3>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                {displayedThreats.length} / {threats.length}
              </span>
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950/60 text-emerald-300 border border-emerald-800/60" title="Synchronisé en temps réel avec tous les analystes connectés">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                <span>Synchro Directe Multi-Utilisateurs</span>
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setSortBySeverity(!sortBySeverity)}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                  sortBySeverity
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 font-semibold'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700'
                }`}
                title="Trier par gravité décroissante"
              >
                <ArrowUpDown className="w-3 h-3" />
                <span>{sortBySeverity ? 'Tri : Gravité Max' : 'Ordre Original'}</span>
              </button>
            </div>
          </div>

          {/* Severity Filter Component Bar */}
          <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 space-y-2.5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              {/* Severity Buttons */}
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-xs text-slate-400 font-medium flex items-center gap-1 mr-1">
                  <Filter className="w-3 h-3 text-cyan-400" /> Priorité :
                </span>

                <button
                  onClick={() => setSeverityFilter('ALL')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
                    severityFilter === 'ALL'
                      ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-700 shadow-sm shadow-cyan-950'
                      : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  <span>TOUTES</span>
                  <span className="px-1.5 py-0.2 rounded text-[10px] bg-slate-800/80 text-slate-300">
                    {threats.length}
                  </span>
                </button>

                <button
                  onClick={() => setSeverityFilter('CRITICAL')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
                    severityFilter === 'CRITICAL'
                      ? 'bg-rose-950 text-rose-300 font-bold border border-rose-600 shadow-md shadow-rose-950 ring-1 ring-rose-500/30'
                      : 'bg-slate-900 text-rose-400/80 hover:text-rose-300 border border-slate-800 hover:border-rose-900/60'
                  }`}
                >
                  <Flame className="w-3 h-3 text-rose-400 animate-pulse" />
                  <span>CRITIQUE</span>
                  <span className="px-1.5 py-0.2 rounded text-[10px] bg-rose-900/40 text-rose-300 font-bold">
                    {criticalCount}
                  </span>
                </button>

                <button
                  onClick={() => setSeverityFilter('HIGH')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
                    severityFilter === 'HIGH'
                      ? 'bg-orange-950 text-orange-300 font-bold border border-orange-600 shadow-md shadow-orange-950'
                      : 'bg-slate-900 text-orange-400/80 hover:text-orange-300 border border-slate-800 hover:border-orange-900/60'
                  }`}
                >
                  <AlertTriangle className="w-3 h-3 text-orange-400" />
                  <span>ÉLEVÉ</span>
                  <span className="px-1.5 py-0.2 rounded text-[10px] bg-orange-900/40 text-orange-300 font-bold">
                    {highCount}
                  </span>
                </button>

                <button
                  onClick={() => setSeverityFilter('MEDIUM')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
                    severityFilter === 'MEDIUM'
                      ? 'bg-amber-950 text-amber-300 font-bold border border-amber-600 shadow-md shadow-amber-950'
                      : 'bg-slate-900 text-amber-400/80 hover:text-amber-300 border border-slate-800 hover:border-amber-900/60'
                  }`}
                >
                  <Info className="w-3 h-3 text-amber-400" />
                  <span>MOYEN</span>
                  <span className="px-1.5 py-0.2 rounded text-[10px] bg-amber-900/40 text-amber-300 font-bold">
                    {mediumCount}
                  </span>
                </button>

                {categoryFilter !== 'ALL' && (
                  <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono bg-cyan-950 text-cyan-300 border border-cyan-700 shadow-sm animate-fadeIn">
                    <span className="text-[10px] text-cyan-400 uppercase font-semibold">Catégorie :</span>
                    <span className="font-bold">{categoryFilter}</span>
                    <button
                      onClick={() => setCategoryFilter('ALL')}
                      className="ml-1 text-cyan-400 hover:text-white font-bold p-0.5"
                      title="Réinitialiser le filtre de catégorie"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </div>
                )}
              </div>

              {/* Quick Search Input */}
              <div className="relative min-w-[200px]">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Rechercher (binaire, MITRE)..."
                  value={searchThreatQuery}
                  onChange={e => setSearchThreatQuery(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-8 pr-7 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
                {searchThreatQuery && (
                  <button
                    onClick={() => setSearchThreatQuery('')}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                  >
                    <X className="w-3 h-3" />
                  </button>
                )}
              </div>
            </div>

            {/* Active Filter Status Bar */}
            {(severityFilter !== 'ALL' || searchThreatQuery) && (
              <div className="flex items-center justify-between text-[11px] font-mono pt-1 text-slate-400 border-t border-slate-900">
                <div className="flex items-center gap-2">
                  <span>Filtre appliqué :</span>
                  {severityFilter !== 'ALL' && (
                    <span className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 font-bold">
                      Gravité: {severityFilter}
                    </span>
                  )}
                  {searchThreatQuery && (
                    <span className="px-1.5 py-0.5 rounded bg-slate-800 text-amber-300">
                      Recherche: "{searchThreatQuery}"
                    </span>
                  )}
                  <span className="text-slate-500">
                    ({displayedThreats.length} résultat{displayedThreats.length > 1 ? 's' : ''})
                  </span>
                </div>

                <button
                  onClick={() => {
                    setSeverityFilter('ALL');
                    setSearchThreatQuery('');
                  }}
                  className="text-cyan-400 hover:text-cyan-300 underline font-medium"
                >
                  Réinitialiser les filtres
                </button>
              </div>
            )}
          </div>

          {/* Feedback alert banner */}
          {bulkFeedbackMessage && (
            <div className="p-3 bg-cyan-950/80 border border-cyan-700/80 rounded-xl flex items-center justify-between gap-3 text-xs text-cyan-200 animate-in fade-in duration-200">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
                <span className="font-medium">{bulkFeedbackMessage}</span>
              </div>
              {recentlyDismissedIds.length > 0 && (
                <button
                  onClick={handleUndoDismiss}
                  className="inline-flex items-center gap-1 px-2.5 py-1 bg-cyan-900/80 hover:bg-cyan-800 text-cyan-100 rounded-lg text-xs font-semibold transition-colors shrink-0"
                >
                  <Undo2 className="w-3.5 h-3.5" />
                  <span>Annuler</span>
                </button>
              )}
            </div>
          )}

          {/* Bulk Selection Bar & Control Strip */}
          <div className="p-3 bg-slate-950/90 rounded-xl border border-slate-800 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              {/* Select All & Quick Filters */}
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={handleToggleSelectAll}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all border ${
                    selectedThreatIds.size > 0 && selectedThreatIds.size === displayedThreats.length
                      ? 'bg-cyan-950 text-cyan-300 border-cyan-600 shadow-sm shadow-cyan-950'
                      : selectedThreatIds.size > 0
                      ? 'bg-slate-900 text-cyan-300 border-cyan-800'
                      : 'bg-slate-900 text-slate-400 hover:text-slate-200 border-slate-800'
                  }`}
                  title={selectedThreatIds.size === displayedThreats.length ? 'Tout désélectionner' : 'Sélectionner toutes les menaces affichées'}
                >
                  {selectedThreatIds.size > 0 && selectedThreatIds.size === displayedThreats.length ? (
                    <CheckSquare className="w-3.5 h-3.5 text-cyan-400" />
                  ) : selectedThreatIds.size > 0 ? (
                    <MinusSquare className="w-3.5 h-3.5 text-cyan-400" />
                  ) : (
                    <Square className="w-3.5 h-3.5 text-slate-500" />
                  )}
                  <span>Tout ({displayedThreats.length})</span>
                </button>

                <button
                  onClick={handleSelectActiveOnly}
                  className="px-2.5 py-1.5 rounded-lg text-xs font-mono bg-slate-900 hover:bg-slate-850 text-slate-300 border border-slate-800 hover:border-slate-700 transition-colors"
                >
                  Actives ({displayedThreats.filter(t => t.status === 'ACTIVE').length})
                </button>

                <button
                  onClick={handleSelectCriticalOnly}
                  className="px-2.5 py-1.5 rounded-lg text-xs font-mono bg-slate-900 hover:bg-slate-850 text-rose-400 border border-slate-800 hover:border-rose-900/60 transition-colors"
                >
                  Critiques ({displayedThreats.filter(t => t.severity === 'CRITICAL' && t.status === 'ACTIVE').length})
                </button>

                {selectedThreatIds.size > 0 && (
                  <button
                    onClick={handleClearSelection}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-mono text-slate-400 hover:text-slate-200 hover:bg-slate-900 transition-colors"
                  >
                    <X className="w-3 h-3" />
                    <span>Effacer sélection</span>
                  </button>
                )}
              </div>

              {/* Toggle Dismissed Threats View */}
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowDismissedThreats(!showDismissedThreats)}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-mono transition-colors border ${
                    showDismissedThreats
                      ? 'bg-slate-800 text-cyan-300 border-cyan-800 font-semibold'
                      : 'bg-slate-900 text-slate-400 hover:text-slate-300 border-slate-800'
                  }`}
                  title="Afficher ou masquer les menaces ignorées / rejetées par les analystes"
                >
                  <EyeOff className="w-3.5 h-3.5 text-slate-400" />
                  <span>Ignorées ({dismissedCount})</span>
                </button>
              </div>
            </div>

            {/* Sticky / Active Bulk Actions Command Bar (visible when 1+ selected) */}
            {selectedThreatIds.size > 0 && (
              <div className="p-3 bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/40 rounded-xl border border-cyan-800/80 shadow-lg shadow-cyan-950/30 space-y-2.5 animate-in slide-in-from-top-2 duration-200">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 rounded-lg bg-cyan-950 text-cyan-300 border border-cyan-800">
                      <Layers className="w-4 h-4 text-cyan-400" />
                    </div>
                    <div>
                      <div className="text-xs font-bold text-white flex items-center gap-1.5">
                        <span>Actions Groupées sur la Sélection</span>
                        <span className="px-2 py-0.2 rounded-full text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                          {selectedThreatIds.size} sélectionnée{selectedThreatIds.size > 1 ? 's' : ''}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400">
                        Appliquez un traitement simultané synchronisé avec tous les postes connectés.
                      </p>
                    </div>
                  </div>

                  {/* Bulk Action Buttons */}
                  <div className="flex items-center gap-2 flex-wrap">
                    {/* Bulk Kernel Unlock */}
                    <button
                      onClick={handleBulkKernelUnlock}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold font-mono text-white bg-rose-600 hover:bg-rose-500 shadow-md shadow-rose-950 transition-all"
                      title="Exécute takeown, icacls et planifie la suppression au boot pour toutes les menaces sélectionnées"
                    >
                      <Zap className="w-3.5 h-3.5" />
                      <span>Éradication Kernel ({selectedThreatIds.size})</span>
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
          </div>

          {/* Threats List */}
          <div className="space-y-3">
            {displayedThreats.length === 0 ? (
              <div className="p-8 text-center bg-slate-950/60 border border-slate-800/80 rounded-xl space-y-3">
                <Shield className="w-8 h-8 text-slate-600 mx-auto" />
                <div className="text-sm font-semibold text-slate-300">
                  Aucune menace ne correspond aux filtres sélectionnés
                </div>
                <p className="text-xs text-slate-500 max-w-sm mx-auto">
                  Modifiez votre critère de sévérité, effacez la recherche ou activez l'affichage des menaces ignorées.
                </p>
                <div className="flex items-center justify-center gap-2 pt-1">
                  <button
                    onClick={() => {
                      setSeverityFilter('ALL');
                      setSearchThreatQuery('');
                      setShowDismissedThreats(false);
                    }}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-400 rounded-lg text-xs font-mono font-semibold transition-colors"
                  >
                    Afficher Toutes les Menaces
                  </button>
                  {dismissedCount > 0 && !showDismissedThreats && (
                    <button
                      onClick={() => setShowDismissedThreats(true)}
                      className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded-lg text-xs font-mono transition-colors"
                    >
                      Voir les {dismissedCount} Menaces Ignorées
                    </button>
                  )}
                </div>
              </div>
            ) : (
              displayedThreats.map(threat => {
                const isSelected = selectedThreatIds.has(threat.id);
                const isCritical = threat.severity === 'CRITICAL';
                const isHigh = threat.severity === 'HIGH';
                const isMedium = threat.severity === 'MEDIUM';
                const isDismissed = threat.status === 'DISMISSED';
                const isScheduledDelete = threat.status === 'SCHEDULED_BOOT_DELETE';
                const isQuarantined = threat.status === 'QUARANTINED';
                const isNeutralized = threat.status === 'NEUTRALIZED';

                return (
                  <div
                    key={threat.id}
                    className={`p-4 rounded-xl transition-all space-y-2.5 border ${
                      isSelected
                        ? 'bg-slate-900/95 border-cyan-500/80 ring-1 ring-cyan-500/40 shadow-lg shadow-cyan-950/40'
                        : isDismissed
                        ? 'bg-slate-950/50 border-slate-800/60 opacity-60 hover:opacity-90'
                        : isCritical
                        ? 'bg-slate-950/90 border-rose-900/60 hover:border-rose-700/80 shadow-sm shadow-rose-950/30'
                        : isHigh
                        ? 'bg-slate-950/90 border-orange-900/60 hover:border-orange-700/80 shadow-sm shadow-orange-950/30'
                        : 'bg-slate-950/80 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        {/* Tactical Row Checkbox */}
                        <button
                          type="button"
                          onClick={() => toggleSelectThreat(threat.id)}
                          className={`p-1 rounded-md transition-colors ${
                            isSelected
                              ? 'text-cyan-400 bg-cyan-950/80 border border-cyan-700'
                              : 'text-slate-500 hover:text-slate-300 bg-slate-900 border border-slate-800'
                          }`}
                          title={isSelected ? 'Désélectionner cette menace' : 'Sélectionner pour action groupée'}
                        >
                          {isSelected ? (
                            <CheckSquare className="w-4 h-4 text-cyan-400" />
                          ) : (
                            <Square className="w-4 h-4" />
                          )}
                        </button>

                        {isDismissed && (
                          <span className="inline-flex items-center gap-1 font-bold text-xs text-slate-400 bg-slate-900 border border-slate-700 px-2 py-0.5 rounded">
                            <EyeOff className="w-3 h-3 text-slate-400" />
                            [IGNORÉE / REJETÉE]
                          </span>
                        )}

                        {!isDismissed && isCritical && (
                          <span className="inline-flex items-center gap-1 font-bold text-xs text-rose-400 bg-rose-950/80 border border-rose-800/80 px-2 py-0.5 rounded">
                            <Flame className="w-3 h-3 text-rose-400 animate-pulse" />
                            [CRITIQUE]
                          </span>
                        )}
                        {!isDismissed && isHigh && (
                          <span className="inline-flex items-center gap-1 font-bold text-xs text-orange-400 bg-orange-950/80 border border-orange-800/80 px-2 py-0.5 rounded">
                            <AlertTriangle className="w-3 h-3 text-orange-400" />
                            [ÉLEVÉ]
                          </span>
                        )}
                        {!isDismissed && isMedium && (
                          <span className="inline-flex items-center gap-1 font-bold text-xs text-amber-400 bg-amber-950/80 border border-amber-800/80 px-2 py-0.5 rounded">
                            [MOYEN]
                          </span>
                        )}

                        <span className={`font-semibold text-sm ${isDismissed ? 'text-slate-400 line-through' : 'text-slate-100'}`}>
                          {threat.name}
                        </span>

                        <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400 font-mono">
                          {threat.category}
                        </span>

                        {threat.trustedInstallerLocked && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-purple-950 text-purple-300 border border-purple-800/80 font-mono">
                            Verrou TrustedInstaller
                          </span>
                        )}
                      </div>

                      <div className="text-[11px] font-mono text-cyan-400 shrink-0">
                        {threat.mitreTechnique}
                      </div>
                    </div>

                    <div className={`text-xs leading-relaxed font-sans ${isDismissed ? 'text-slate-500' : 'text-slate-300'}`}>
                      {threat.description || threat.name}
                    </div>

                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-2 border-t border-slate-900 text-xs">
                      <div className="text-[11px] font-mono text-slate-400 truncate max-w-md">
                        Cible : <span className="text-slate-200 select-all">{threat.targetPath}</span>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        {isDismissed ? (
                          <div className="flex items-center gap-2">
                            <span className="text-[11px] font-mono text-slate-500">
                              Rejetée de l'audit
                            </span>
                            <button
                              onClick={() => handleRestoreSingle(threat.id)}
                              className="inline-flex items-center gap-1 px-2.5 py-1 text-cyan-300 bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-800 font-semibold rounded text-xs transition-colors"
                              title="Restaurer cette menace dans la liste active"
                            >
                              <RotateCcw className="w-3 h-3 text-cyan-400" />
                              <span>Restaurer</span>
                            </button>
                          </div>
                        ) : isScheduledDelete ? (
                          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                            Destruction planifiée au boot (0 octet)
                          </span>
                        ) : isQuarantined ? (
                          <div className="flex items-center gap-2">
                            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800">
                              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                              En Quarantaine Chiffrée
                            </span>
                            <button
                              onClick={() => onRunInConsole(`unlock "${threat.targetPath}"`)}
                              className="px-2.5 py-1 text-white bg-rose-600 hover:bg-rose-500 rounded text-xs font-semibold"
                            >
                              Éradiquer
                            </button>
                          </div>
                        ) : isNeutralized ? (
                          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                            Neutralisée
                          </span>
                        ) : (
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => handleSingleDismiss(threat.id)}
                              className="px-2.5 py-1 text-slate-400 hover:text-slate-200 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded text-xs transition-colors"
                              title="Ignorer cette alerte (faux positif ou risque accepté)"
                            >
                              Ignorer
                            </button>
                            <button
                              onClick={() => onRunInConsole(`unlock "${threat.targetPath}"`)}
                              className={`px-3 py-1 text-white font-semibold rounded text-xs transition-colors shadow-sm ${
                                isCritical
                                  ? 'bg-rose-600 hover:bg-rose-500 shadow-rose-950'
                                  : isHigh
                                  ? 'bg-orange-600 hover:bg-orange-500 shadow-orange-950'
                                  : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700'
                              }`}
                            >
                              Éradiquer au Niveau Kernel
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Col: Interactive Modules Hub */}
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            Accès Rapide aux Modules de Défense
          </h3>

          <div className="space-y-3">
            <div
              onClick={() => onNavigateTab('timeline')}
              className="p-3.5 bg-cyan-950/40 border border-cyan-800/80 hover:border-cyan-500 rounded-xl cursor-pointer transition-colors group"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-cyan-300 group-hover:text-cyan-200 flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-cyan-400" />
                  Chronologie Visuelle des Menaces
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-300 transition-transform group-hover:translate-x-1" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Rejeu chronologique pas-à-pas du scan initial jusqu'à la remédiation et l'excision noyau.
              </p>
            </div>

            <div
              onClick={() => onNavigateTab('heuristic')}
              className="p-3.5 bg-amber-950/30 border border-amber-800/70 hover:border-amber-500 rounded-xl cursor-pointer transition-colors group"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-amber-300 group-hover:text-amber-200 flex items-center gap-1.5">
                  <Binary className="w-3.5 h-3.5 text-amber-400" />
                  Moteur Heuristique (Entropie & API Hooks)
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-amber-300 transition-transform group-hover:translate-x-1" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Scoring en temps réel de l'entropie de Shannon, crochets d'appels API NT suspects et confiance bayésienne.
              </p>
            </div>

            <div
              onClick={() => onNavigateTab('task-manager')}
              className="p-3.5 bg-slate-950 border border-slate-800 hover:border-cyan-800 rounded-xl cursor-pointer transition-colors group"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-cyan-300 group-hover:text-cyan-200">
                  Gestionnaire des Tâches Live
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-300 transition-transform group-hover:translate-x-1" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Charge CPU, RAM, durée d'activité et terminaison immédiate de processus (Fin de tâche).
              </p>
            </div>

            <div
              onClick={() => onNavigateTab('bits')}
              className="p-3.5 bg-slate-950 border border-slate-800 hover:border-cyan-800 rounded-xl cursor-pointer transition-colors group"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-cyan-300 group-hover:text-cyan-200">
                  BITS Task Manager (T1197)
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-300 transition-transform group-hover:translate-x-1" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Traque et purge des transferts furtifs et de la persistance Background Intelligent Transfer Service.
              </p>
            </div>

            <div
              onClick={() => onNavigateTab('deep-excision')}
              className="p-3.5 bg-slate-950 border border-slate-800 hover:border-cyan-800 rounded-xl cursor-pointer transition-colors group"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-cyan-300 group-hover:text-cyan-200">
                  Éradication OS & Kernel
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-300 transition-transform group-hover:translate-x-1" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Takeown, Session Manager boot delete, IFEO traps & watchdogs killer.
              </p>
            </div>

            <div
              onClick={() => onNavigateTab('forensics')}
              className="p-3.5 bg-slate-950 border border-slate-800 hover:border-cyan-800 rounded-xl cursor-pointer transition-colors group"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-cyan-300 group-hover:text-cyan-200">
                  Forensique RAM & Processus
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-300 transition-transform group-hover:translate-x-1" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Dump RAM d'urgence, LOLBins certutil/mshta et détection ADS.
              </p>
            </div>

            <div
              onClick={() => onNavigateTab('network')}
              className="p-3.5 bg-slate-950 border border-slate-800 hover:border-cyan-800 rounded-xl cursor-pointer transition-colors group"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-cyan-300 group-hover:text-cyan-200">
                  Réseau C2 & Tuyaux Nommés
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-300 transition-transform group-hover:translate-x-1" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Sockets Metasploit (4444), tuyaux Cobalt Strike et intégrité HOSTS.
              </p>
            </div>

            <div
              onClick={() => onNavigateTab('hardening')}
              className="p-3.5 bg-slate-950 border border-slate-800 hover:border-cyan-800 rounded-xl cursor-pointer transition-colors group"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-cyan-300 group-hover:text-cyan-200">
                  Durcissement & Anti-Persistance
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-300 transition-transform group-hover:translate-x-1" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Désactivation SMBv1, purge WMI root\subscription et Shadow Copies.
              </p>
            </div>

            <div
              onClick={() => onNavigateTab('script-hub')}
              className="p-3.5 bg-amber-950/20 border border-amber-900/50 hover:border-amber-600/80 rounded-xl cursor-pointer transition-colors group"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-amber-300 group-hover:text-amber-200 flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-amber-400" />
                  Script PowerShell (.ps1 & .bat)
                </span>
                <div className="flex items-center gap-2">
                  {onDownloadScript && (
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onDownloadScript();
                      }}
                      title="Télécharger directement le script SpaceSecurity_ULTRA_v3_Kernel.ps1"
                      className="px-2 py-0.5 text-[10px] font-mono text-amber-200 bg-amber-950/80 hover:bg-amber-900 border border-amber-700/70 rounded flex items-center gap-1 transition-colors"
                    >
                      <Download className="w-2.5 h-2.5 text-amber-400" />
                      <span>Télécharger .ps1</span>
                    </button>
                  )}
                  <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-amber-300 transition-transform group-hover:translate-x-1" />
                </div>
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Visualisez le code source et téléchargez le script autonome <code className="text-amber-300 font-mono">.ps1</code> d'assainissement noyau.
              </p>
            </div>
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
