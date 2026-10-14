import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  ShieldAlert,
  Cpu,
  Activity,
  AlertTriangle,
  Play,
  Pause,
  RotateCcw,
  Terminal,
  Zap,
  Filter,
  Layers,
  FileCode,
  Lock,
  Binary,
  Radio,
  Sliders,
  CheckCircle2,
  XCircle,
  Eye,
  Crosshair,
  ArrowRight,
  TrendingUp,
  Flame,
  Search,
  CheckSquare,
  Square,
  MinusSquare,
  EyeOff,
  X,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
  Legend,
} from 'recharts';
import {
  TabId,
  EntropyMetric,
  SuspiciousApiCall,
  ThreatConfidenceItem,
  ThreatItem,
} from '../types/cyberdefense';
import { SharedCommandModal } from './SharedCommandModal';
import { FileEntropyAnalyzer } from './FileEntropyAnalyzer';
import { RegistrySurveillancePanel } from './RegistrySurveillancePanel';
import { DigitalSignatureInspector } from './DigitalSignatureInspector';
import { ShieldCheck, FileText } from 'lucide-react';

interface HeuristicEngineProps {
  onRunInConsole: (command: string) => void;
  onNavigateTab?: (tab: TabId) => void;
  threats?: ThreatItem[];
  onBulkMutateThreatStatus?: (threatIds: string[], status: ThreatItem['status'], command?: string) => void;
  onMassDismissThreats?: (threatIds: string[]) => void;
  onRestoreThreats?: (threatIds: string[]) => void;
}

interface ConfidenceHistoryPoint {
  time: string;
  confidence: number;
  entropyImpact: number;
  apiAnomalyImpact: number;
  threatCount: number;
}

// Monitored Entropy Sections for standard Windows binaries (Shannon Entropy H: 0.00 to 8.00 bits/byte)
const INITIAL_ENTROPY_METRICS: EntropyMetric[] = [
  {
    id: 'ent-1',
    target: 'C:\\Windows\\System32\\ntoskrnl.exe',
    section: '.text [Kernel Core]',
    process: 'ntoskrnl.exe',
    pid: 4,
    entropy: 5.82,
    baseline: 5.80,
    deviation: 0.02,
    sizeBytes: 10485760,
    status: 'NORMAL',
    isObfuscated: false,
    classification: 'Noyau Exécutif Windows NT Microsoft',
  },
  {
    id: 'ent-2',
    target: 'C:\\Windows\\System32\\svchost.exe',
    section: '.text [Code Virtuel VAD]',
    process: 'svchost.exe (netsvcs)',
    pid: 1420,
    entropy: 6.12,
    baseline: 6.10,
    deviation: 0.02,
    sizeBytes: 524288,
    status: 'NORMAL',
    isObfuscated: false,
    classification: 'Hôte de Services Windows Standard Microsoft',
  },
  {
    id: 'ent-3',
    target: 'C:\\Windows\\System32\\lsass.exe',
    section: '.rdata [Import Directory]',
    process: 'lsass.exe',
    pid: 780,
    entropy: 5.08,
    baseline: 5.05,
    deviation: 0.03,
    sizeBytes: 262144,
    status: 'NORMAL',
    isObfuscated: false,
    classification: 'Imports Natifs Légitimes NT AUTHORITY',
  },
  {
    id: 'ent-4',
    target: 'C:\\Windows\\System32\\csrss.exe',
    section: '.text [Native Subsystem]',
    process: 'csrss.exe',
    pid: 612,
    entropy: 5.82,
    baseline: 5.80,
    deviation: 0.02,
    sizeBytes: 196608,
    status: 'NORMAL',
    isObfuscated: false,
    classification: 'Sous-système Win32 Standard Microsoft',
  },
  {
    id: 'ent-5',
    target: 'C:\\Windows\\explorer.exe',
    section: '.rsrc [GUI Resources]',
    process: 'explorer.exe',
    pid: 2480,
    entropy: 5.45,
    baseline: 5.40,
    deviation: 0.05,
    sizeBytes: 4194304,
    status: 'NORMAL',
    isObfuscated: false,
    classification: 'Interface Utilisateur & Explorateur de Fichiers',
  },
  {
    id: 'ent-6',
    target: 'C:\\Windows\\System32\\kernel32.dll',
    section: '.text [Win32 Core API]',
    process: 'kernel32.dll',
    pid: 0,
    entropy: 6.32,
    baseline: 6.30,
    deviation: 0.02,
    sizeBytes: 1703936,
    status: 'NORMAL',
    isObfuscated: false,
    classification: 'Bibliothèque Win32 Fondamentale Microsoft',
  },
];

// Suspicious API Calls Hook Feed (starts empty for clean system)
const INITIAL_SUSPICIOUS_APIS: SuspiciousApiCall[] = [];

// Threat Confidence Matrix (starts empty for clean system)
const INITIAL_THREAT_CONFIDENCE: ThreatConfidenceItem[] = [];

export const HeuristicEngine: React.FC<HeuristicEngineProps> = ({
  onRunInConsole,
  onNavigateTab,
  threats,
  onBulkMutateThreatStatus,
  onMassDismissThreats,
  onRestoreThreats,
}) => {
  // Main telemetry states
  const [isStreaming, setIsStreaming] = useState<boolean>(true);
  const [activeView, setActiveView] = useState<'OVERVIEW' | 'ENTROPY' | 'REGISTRY' | 'SIGNATURES' | 'APIS' | 'CONFIDENCE_MATRIX'>('OVERVIEW');
  const [apiCategoryFilter, setApiCategoryFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  
  // Data states
  const [entropyMetrics, setEntropyMetrics] = useState<EntropyMetric[]>(INITIAL_ENTROPY_METRICS);
  const [suspiciousApis, setSuspiciousApis] = useState<SuspiciousApiCall[]>(INITIAL_SUSPICIOUS_APIS);
  const [threatConfidenceList, setThreatConfidenceList] = useState<ThreatConfidenceItem[]>(INITIAL_THREAT_CONFIDENCE);

  // Bulk selection states for Heuristic Confidence Matrix
  const [selectedConfidenceIds, setSelectedConfidenceIds] = useState<Set<string>>(new Set());
  const [dismissedConfidenceIds, setDismissedConfidenceIds] = useState<Set<string>>(new Set());
  const [showDismissedConfidence, setShowDismissedConfidence] = useState<boolean>(false);
  const [isSharedCommandModalOpen, setIsSharedCommandModalOpen] = useState<boolean>(false);
  const [bulkFeedbackMessage, setBulkFeedbackMessage] = useState<string | null>(null);
  
  // Weights calibration state
  const [weights, setWeights] = useState({
    entropy: 0.35,
    api: 0.35,
    behavior: 0.15,
    mitre: 0.15,
  });
  const [preset, setPreset] = useState<'BALANCED' | 'PACKER_FOCUSED' | 'API_FOCUSED'>('BALANCED');

  // Inspection modal/card
  const [inspectedApi, setInspectedApi] = useState<SuspiciousApiCall | null>(null);
  const [inspectedEntropy, setInspectedEntropy] = useState<EntropyMetric | null>(null);

  // Time-series history for recharts
  const [history, setHistory] = useState<ConfidenceHistoryPoint[]>([
    { time: '11:11:40', confidence: 78.2, entropyImpact: 82, apiAnomalyImpact: 75, threatCount: 3 },
    { time: '11:11:45', confidence: 81.0, entropyImpact: 84, apiAnomalyImpact: 79, threatCount: 3 },
    { time: '11:11:50', confidence: 84.5, entropyImpact: 88, apiAnomalyImpact: 82, threatCount: 4 },
    { time: '11:11:55', confidence: 88.0, entropyImpact: 92, apiAnomalyImpact: 85, threatCount: 4 },
    { time: '11:12:00', confidence: 91.5, entropyImpact: 94, apiAnomalyImpact: 89, threatCount: 4 },
    { time: '11:12:05', confidence: 93.8, entropyImpact: 96, apiAnomalyImpact: 93, threatCount: 4 },
  ]);

  // Aggregate stats computed in real-time
  const aggregateStats = useMemo(() => {
    const totalEntropy = entropyMetrics.reduce((acc, curr) => acc + curr.entropy, 0);
    const avgEntropy = totalEntropy / (entropyMetrics.length || 1);
    
    const highEntropyCount = entropyMetrics.filter(m => m.status === 'CRITICAL_PACKED').length;
    const totalApiCallRate = suspiciousApis.reduce((acc, curr) => acc + curr.ratePerSec, 0);
    const interceptedCount = suspiciousApis.filter(a => a.hookStatus === 'INTERCEPTED' || a.hookStatus === 'BLOCKED').length;
    
    // Overall confidence calculation weighted by user weights
    const avgThreatConfidence = threatConfidenceList.reduce((acc, t) => {
      const computed = (
        t.entropyScore * weights.entropy +
        t.apiScore * weights.api +
        t.behaviorScore * weights.behavior +
        t.mitreAlignment * weights.mitre
      );
      return acc + computed;
    }, 0) / (threatConfidenceList.length || 1);

    return {
      avgEntropy: Math.round(avgEntropy * 100) / 100,
      highEntropyCount,
      totalApiCallRate: Math.round(totalApiCallRate * 10) / 10,
      interceptedCount,
      overallConfidence: Math.round(avgThreatConfidence * 10) / 10,
    };
  }, [entropyMetrics, suspiciousApis, threatConfidenceList, weights]);

  // Handle Preset Changes
  const handleSelectPreset = (newPreset: 'BALANCED' | 'PACKER_FOCUSED' | 'API_FOCUSED') => {
    setPreset(newPreset);
    if (newPreset === 'BALANCED') {
      setWeights({ entropy: 0.35, api: 0.35, behavior: 0.15, mitre: 0.15 });
    } else if (newPreset === 'PACKER_FOCUSED') {
      setWeights({ entropy: 0.55, api: 0.20, behavior: 0.15, mitre: 0.10 });
    } else if (newPreset === 'API_FOCUSED') {
      setWeights({ entropy: 0.20, api: 0.55, behavior: 0.15, mitre: 0.10 });
    }
  };

  // Bulk Selection Logic for Threat Confidence Items
  const displayedConfidenceThreats = useMemo(() => {
    return threatConfidenceList.filter(t => {
      if (!showDismissedConfidence && dismissedConfidenceIds.has(t.id)) return false;
      return true;
    });
  }, [threatConfidenceList, showDismissedConfidence, dismissedConfidenceIds]);

  const toggleSelectConfidence = (id: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setSelectedConfidenceIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleToggleSelectAllConfidence = () => {
    if (selectedConfidenceIds.size === displayedConfidenceThreats.length && displayedConfidenceThreats.length > 0) {
      setSelectedConfidenceIds(new Set());
    } else {
      setSelectedConfidenceIds(new Set(displayedConfidenceThreats.map(t => t.id)));
    }
  };

  const handleSelectHighConfidenceOnly = () => {
    const high = displayedConfidenceThreats
      .filter(t => {
        const dynConf = (
          t.entropyScore * weights.entropy +
          t.apiScore * weights.api +
          t.behaviorScore * weights.behavior +
          t.mitreAlignment * weights.mitre
        );
        return dynConf >= 85;
      })
      .map(t => t.id);
    setSelectedConfidenceIds(new Set(high));
  };

  const handleClearConfidenceSelection = () => {
    setSelectedConfidenceIds(new Set());
  };

  const handleMassDismissConfidence = () => {
    if (selectedConfidenceIds.size === 0) return;
    const ids = Array.from(selectedConfidenceIds);
    setDismissedConfidenceIds(prev => {
      const next = new Set(prev);
      ids.forEach(id => next.add(id));
      return next;
    });
    if (onMassDismissThreats) {
      onMassDismissThreats(ids);
    }
    onRunInConsole(`bulk-dismiss-heuristic ${ids.join(',')}`);
    setBulkFeedbackMessage(`${ids.length} menace(s) heuristique(s) rejetée(s) et archivée(s).`);
    setTimeout(() => setBulkFeedbackMessage(null), 4000);
    handleClearConfidenceSelection();
  };

  const handleBulkRemediateConfidence = () => {
    if (selectedConfidenceIds.size === 0) return;
    const targets = threatConfidenceList.filter(t => selectedConfidenceIds.has(t.id));
    targets.forEach((t, idx) => {
      setTimeout(() => {
        onRunInConsole(t.remediationCmd);
      }, idx * 400);
    });
    setBulkFeedbackMessage(`Éradication programmée sur ${targets.length} menace(s) heuristique(s).`);
    setTimeout(() => setBulkFeedbackMessage(null), 4000);
    handleClearConfidenceSelection();
  };

  const selectedThreatsForModal: ThreatItem[] = useMemo(() => {
    return threatConfidenceList
      .filter(t => selectedConfidenceIds.has(t.id))
      .map(t => ({
        id: t.id,
        name: t.threatName,
        category: (t.targetPath.includes('.sys') ? 'Rootkit' : t.targetPath.includes('updater') ? 'Trojan' : 'Memory') as ThreatItem['category'],
        severity: t.confidence > 90 ? 'CRITICAL' : 'HIGH',
        targetPath: t.targetPath,
        mitreTechnique: t.primaryTechnique,
        lockedBySystem: true,
        trustedInstallerLocked: t.targetPath.includes('.sys'),
        status: 'ACTIVE',
        description: t.recommendedAction,
      }));
  }, [threatConfidenceList, selectedConfidenceIds]);

  const handleExecuteSharedCommandConfidence = (template: string, targets: ThreatItem[]) => {
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

    setBulkFeedbackMessage(`Commande partagée exécutée sur ${targets.length} menace(s).`);
    setTimeout(() => setBulkFeedbackMessage(null), 4000);
    handleClearConfidenceSelection();
  };

  // Real-time telemetry simulation interval
  useEffect(() => {
    if (!isStreaming) return;

    const interval = setInterval(() => {
      const now = new Date();
      const timeStr = now.toLocaleTimeString('fr-FR', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });

      // Subtle natural fluctuations in entropy and API rates
      setEntropyMetrics(prev =>
        prev.map(item => {
          if (item.status === 'CRITICAL_PACKED') {
            // Keep critical items high (between 7.50 and 7.98)
            const jitter = (Math.random() - 0.48) * 0.04;
            const newEntropy = Math.min(7.99, Math.max(7.45, item.entropy + jitter));
            return {
              ...item,
              entropy: Math.round(newEntropy * 100) / 100,
              deviation: Math.round((newEntropy - item.baseline) * 100) / 100,
            };
          }
          const jitter = (Math.random() - 0.5) * 0.02;
          const newEntropy = Math.min(6.5, Math.max(4.5, item.entropy + jitter));
          return {
            ...item,
            entropy: Math.round(newEntropy * 100) / 100,
            deviation: Math.round((newEntropy - item.baseline) * 100) / 100,
          };
        })
      );

      // Random jitter for API rates
      setSuspiciousApis(prev =>
        prev.map(item => {
          const deltaCalls = Math.floor(Math.random() * 3);
          const jitterRate = (Math.random() - 0.5) * 0.4;
          return {
            ...item,
            callCount: item.callCount + deltaCalls,
            ratePerSec: Math.max(0.1, Math.round((item.ratePerSec + jitterRate) * 10) / 10),
          };
        })
      );

      // Append point to history
      setHistory(prev => {
        const last = prev[prev.length - 1];
        const jitterConf = (Math.random() - 0.45) * 1.2;
        const newConf = Math.min(99.4, Math.max(70.0, (last ? last.confidence : 88) + jitterConf));
        const newPoint: ConfidenceHistoryPoint = {
          time: timeStr,
          confidence: Math.round(newConf * 10) / 10,
          entropyImpact: Math.min(100, Math.round(newConf * 1.02)),
          apiAnomalyImpact: Math.min(100, Math.round(newConf * 0.96)),
          threatCount: 4,
        };
        const next = [...prev.slice(1), newPoint];
        return next;
      });
    }, 2500);

    return () => clearInterval(interval);
  }, [isStreaming]);

  // Action: Inject Simulated Anomaly
  const handleInjectAnomaly = useCallback((type: 'HOLLOWING' | 'PACKER' | 'LSASS_DUMP') => {
    const now = new Date();
    const timeStr = now.toLocaleTimeString('fr-FR', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });

    if (type === 'HOLLOWING') {
      const newApi: SuspiciousApiCall = {
        id: `api-inj-${Date.now()}`,
        timestamp: timeStr,
        apiName: 'NtQueueApcThread [Early Bird APC]',
        callerProcess: 'malware_stage2.exe',
        pid: 6240,
        targetProcess: 'svchost.exe',
        targetPid: 1420,
        category: 'INJECTION',
        riskScore: 99,
        callCount: 45,
        ratePerSec: 15.4,
        mitreTechnique: 'T1055.004 - Asynchronous Procedure Call Injection',
        hookStatus: 'INTERCEPTED',
        details: 'Injection de shellcode asynchrone lors de la phase d\'initialisation du thread suspendu.',
      };
      setSuspiciousApis(prev => [newApi, ...prev]);
      onRunInConsole('suspend malware_stage2');
    } else if (type === 'PACKER') {
      const newEntropy: EntropyMetric = {
        id: `ent-inj-${Date.now()}`,
        target: 'C:\\Users\\Public\\RansomPayload.bin',
        section: '.vmp1 [VMProtect Virtual Section]',
        process: 'RansomPayload.bin',
        pid: 6912,
        entropy: 7.98,
        baseline: 5.10,
        deviation: 2.88,
        sizeBytes: 8388608,
        status: 'CRITICAL_PACKED',
        isObfuscated: true,
        classification: 'Charge Utile Fortement Chiffrée (Chiffrement AES/ChaCha20)',
      };
      setEntropyMetrics(prev => [newEntropy, ...prev]);
      onRunInConsole('scan --deep');
    } else if (type === 'LSASS_DUMP') {
      const newApi: SuspiciousApiCall = {
        id: `api-lsass-${Date.now()}`,
        timestamp: timeStr,
        apiName: 'OpenProcess [PROCESS_VM_READ | PROCESS_QUERY_INFORMATION]',
        callerProcess: 'procdump64.exe',
        pid: 7714,
        targetProcess: 'lsass.exe',
        targetPid: 780,
        category: 'CREDENTIAL',
        riskScore: 97,
        callCount: 12,
        ratePerSec: 4.8,
        mitreTechnique: 'T1003.001 - LSASS Memory Dumping via ProcDump',
        hookStatus: 'BLOCKED',
        details: 'Demande de handle étendu vers la mémoire du sous-système de sécurité locale.',
      };
      setSuspiciousApis(prev => [newApi, ...prev]);
      onRunInConsole('dump-ram');
    }
  }, [onRunInConsole]);

  // Filtered APIs
  const filteredApis = useMemo(() => {
    return suspiciousApis.filter(api => {
      if (apiCategoryFilter !== 'ALL' && api.category !== apiCategoryFilter) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          api.apiName.toLowerCase().includes(q) ||
          api.callerProcess.toLowerCase().includes(q) ||
          api.details.toLowerCase().includes(q) ||
          api.mitreTechnique.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [suspiciousApis, apiCategoryFilter, searchQuery]);

  return (
    <div className="space-y-6">
      {/* ========================================================================= */}
      {/* SECTION 1: HEADER & LIVE TELEMETRY CONTROL BAR */}
      {/* ========================================================================= */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="font-semibold text-cyan-400">MOTEUR HEURISTIQUE RING0</span>
              <span aria-hidden="true">·</span>
              <span>ENTROPIE DE SHANNON</span>
              <span aria-hidden="true">·</span>
              <span>CROCHETS API WIN32 & NT</span>
            </div>
            <h1 className="text-xl md:text-2xl font-bold text-white tracking-tight">
              Moteur d'Analyse Heuristique & Confiance de Détection
            </h1>
            <p className="text-xs text-slate-300 max-w-3xl leading-relaxed">
              Mesure l'entropie spectrale des régions mémoires et sections PE exécutables (0.00 à 8.00 bits/octet)
              combinée à l'interception en temps réel des appels API NT suspects pour établir un indice bayésien de certitude des menaces.
            </p>
          </div>

          {/* Interactive Top Actions & Simulation Triggers */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              onClick={() => setIsStreaming(!isStreaming)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
                isStreaming
                  ? 'bg-cyan-950/80 text-cyan-300 border-cyan-700/80 hover:bg-cyan-900'
                  : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
              }`}
            >
              {isStreaming ? (
                <>
                  <Pause className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Flux Actif (2.5s)</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 text-slate-300" />
                  <span>Flux Suspendu</span>
                </>
              )}
            </button>

            {/* Quick Simulation Dropdown / Buttons */}
            <button
              onClick={() => handleInjectAnomaly('HOLLOWING')}
              title="Simule une rafale d'appels NtUnmapViewOfSection et VirtualAllocEx"
              className="flex items-center gap-1 px-2.5 py-1.5 bg-rose-950/70 hover:bg-rose-900 border border-rose-800/80 text-rose-300 rounded-lg text-xs font-medium transition-colors"
            >
              <Zap className="w-3 h-3 text-rose-400" />
              <span>+ Pic Process Hollowing</span>
            </button>

            <button
              onClick={() => handleInjectAnomaly('PACKER')}
              title="Injecte une section mémoire avec entropie critique de 7.98 bits/octet"
              className="flex items-center gap-1 px-2.5 py-1.5 bg-amber-950/70 hover:bg-amber-900 border border-amber-800/80 text-amber-300 rounded-lg text-xs font-medium transition-colors"
            >
              <Binary className="w-3 h-3 text-amber-400" />
              <span>+ Pic Entropie Packer</span>
            </button>

            <button
              onClick={() => {
                setEntropyMetrics(INITIAL_ENTROPY_METRICS);
                setSuspiciousApis(INITIAL_SUSPICIOUS_APIS);
                setThreatConfidenceList(INITIAL_THREAT_CONFIDENCE);
              }}
              title="Réinitialiser l'état initial des signatures"
              className="p-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded-lg transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* ======================================================================= */}
        {/* TOP KPI NUMERICS (Unboxed text with tabular figures) */}
        {/* ======================================================================= */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 pt-6 border-t border-slate-800">
          <div>
            <div className="text-xs text-slate-400 font-medium">Entropie Moyenne Système</div>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-2xl font-bold font-mono tabular-nums text-white">
                {aggregateStats.avgEntropy.toFixed(2)}
              </span>
              <span className="text-xs font-mono text-slate-400">/ 8.00 bits</span>
            </div>
            <div className="text-[11px] text-amber-400 mt-0.5">
              {aggregateStats.highEntropyCount} sections compactées suspectes
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-400 font-medium">Fréquence API NT Surveillées</div>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-2xl font-bold font-mono tabular-nums text-cyan-300">
                {aggregateStats.totalApiCallRate.toFixed(1)}
              </span>
              <span className="text-xs font-mono text-slate-400">appels/sec</span>
            </div>
            <div className="text-[11px] text-emerald-400 mt-0.5">
              Crochets Ring0 opérationnels
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-400 font-medium">Crochets Actifs / Interceptions</div>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-2xl font-bold font-mono tabular-nums text-rose-300">
                {aggregateStats.interceptedCount}
              </span>
              <span className="text-xs font-mono text-slate-400">/ {suspiciousApis.length} surveillés</span>
            </div>
            <div className="text-[11px] text-rose-400 mt-0.5">
              Menaces bloquées à la source
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-400 font-medium">Indice de Confiance Global</div>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-2xl font-bold font-mono tabular-nums text-white">
                {aggregateStats.overallConfidence.toFixed(1)}%
              </span>
              <span className="text-xs font-semibold text-rose-400 font-mono">CRITIQUE</span>
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              Certitude bayésienne validée
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECTION 2: VIEW SELECTOR TABS */}
      {/* ========================================================================= */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex flex-wrap items-center gap-1.5 p-1 bg-slate-900 rounded-lg border border-slate-800">
          <button
            onClick={() => setActiveView('OVERVIEW')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeView === 'OVERVIEW'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Vue Synthétique
          </button>
          <button
            onClick={() => setActiveView('ENTROPY')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 ${
              activeView === 'ENTROPY'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Binary className="w-3.5 h-3.5 text-cyan-400" />
            <span>Calcul d'Entropie & Ransomware</span>
          </button>
          <button
            onClick={() => setActiveView('REGISTRY')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 ${
              activeView === 'REGISTRY'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>Surveillance Registre (Run/Winlogon)</span>
          </button>
          <button
            onClick={() => setActiveView('SIGNATURES')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 ${
              activeView === 'SIGNATURES'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Inspecteur Signatures (Faux explorer.exe)</span>
          </button>
          <button
            onClick={() => setActiveView('APIS')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeView === 'APIS'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Appels API ({suspiciousApis.length})
          </button>
          <button
            onClick={() => setActiveView('CONFIDENCE_MATRIX')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeView === 'CONFIDENCE_MATRIX'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Matrice ({threatConfidenceList.length})
          </button>
        </div>

        {/* Preset Selector */}
        <div className="hidden sm:flex items-center gap-2 text-xs">
          <span className="text-slate-400 font-mono text-[11px]">Calibrage :</span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => handleSelectPreset('BALANCED')}
              className={`px-2 py-1 rounded text-xs font-mono transition-colors ${
                preset === 'BALANCED'
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Équilibré
            </button>
            <button
              onClick={() => handleSelectPreset('PACKER_FOCUSED')}
              className={`px-2 py-1 rounded text-xs font-mono transition-colors ${
                preset === 'PACKER_FOCUSED'
                  ? 'bg-slate-800 text-amber-300 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Priorité Entropie
            </button>
            <button
              onClick={() => handleSelectPreset('API_FOCUSED')}
              className={`px-2 py-1 rounded text-xs font-mono transition-colors ${
                preset === 'API_FOCUSED'
                  ? 'bg-slate-800 text-rose-300 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Priorité API Hooks
            </button>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECTION 3: VIEW CONTENT - OVERVIEW (CHARTS & CORRELATION) */}
      {/* ========================================================================= */}
      {activeView === 'OVERVIEW' && (
        <div className="space-y-6">
          {/* Main Confidence & Entropy Evolution Real-Time Chart */}
          <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-cyan-400" />
                  <span>Évolution Graphique du Niveau de Confiance & Poids Heuristiques</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Surveillance continue du score de confiance dynamique vs anomalies d'entropie et fréquence des crochets API.
                </p>
              </div>
              <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block"></span>
                  Confiance (%)
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-400 inline-block"></span>
                  Impact Entropie
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-400 inline-block"></span>
                  Impact API
                </span>
              </div>
            </div>

            {/* Recharts Area Chart */}
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={history} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorConfidence" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="colorEntropy" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="colorApi" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="time"
                    stroke="#64748b"
                    fontSize={11}
                    tickLine={false}
                    fontFamily="JetBrains Mono, monospace"
                  />
                  <YAxis
                    domain={[60, 100]}
                    stroke="#64748b"
                    fontSize={11}
                    tickLine={false}
                    fontFamily="JetBrains Mono, monospace"
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '12px',
                      color: '#f8fafc',
                      fontFamily: 'JetBrains Mono, monospace',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="confidence"
                    name="Confiance Globale"
                    stroke="#06b6d4"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorConfidence)"
                  />
                  <Area
                    type="monotone"
                    dataKey="entropyImpact"
                    name="Impact Entropie"
                    stroke="#f59e0b"
                    strokeWidth={1.5}
                    fillOpacity={1}
                    fill="url(#colorEntropy)"
                  />
                  <Area
                    type="monotone"
                    dataKey="apiAnomalyImpact"
                    name="Impact Appels API"
                    stroke="#f43f5e"
                    strokeWidth={1.5}
                    fillOpacity={1}
                    fill="url(#colorApi)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Dual Panels: Top Entropy Sections vs Live API Ticker */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left: Top Entropy Anomalies */}
            <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
                    <Binary className="w-4 h-4 text-amber-400" />
                    <span>Distribution de l'Entropie par Section PE</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Seuil d'alerte : &gt; 7.20 bits indique un binaire crypté ou obfuscé.
                  </p>
                </div>
                <button
                  onClick={() => setActiveView('ENTROPY')}
                  className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
                >
                  <span>Détails</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>

              {/* Bar Chart Representation of Entropy */}
              <div className="h-52 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={entropyMetrics.map(e => ({
                      name: e.section.split(' ')[0],
                      entropy: e.entropy,
                      baseline: e.baseline,
                      isPacked: e.status === 'CRITICAL_PACKED',
                    }))}
                    margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis
                      dataKey="name"
                      stroke="#64748b"
                      fontSize={11}
                      tickLine={false}
                      fontFamily="JetBrains Mono, monospace"
                    />
                    <YAxis
                      domain={[0, 8]}
                      stroke="#64748b"
                      fontSize={11}
                      tickLine={false}
                      fontFamily="JetBrains Mono, monospace"
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        borderColor: '#334155',
                        borderRadius: '8px',
                        fontSize: '12px',
                        fontFamily: 'JetBrains Mono, monospace',
                      }}
                    />
                    <Bar dataKey="entropy" name="Entropie Observée">
                      {entropyMetrics.map((entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={
                            entry.status === 'CRITICAL_PACKED'
                              ? '#f43f5e'
                              : entry.status === 'ELEVATED'
                              ? '#f59e0b'
                              : '#10b981'
                          }
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {/* Quick List of High Entropy Targets */}
              <div className="space-y-2 pt-2 border-t border-slate-800">
                {entropyMetrics.slice(0, 3).map(metric => (
                  <div
                    key={metric.id}
                    onClick={() => {
                      setInspectedEntropy(metric);
                      setActiveView('ENTROPY');
                    }}
                    className="p-2.5 bg-slate-950/70 border border-slate-800/80 hover:border-slate-700 rounded-lg cursor-pointer transition-colors flex items-center justify-between"
                  >
                    <div className="truncate pr-2">
                      <div className="text-xs font-semibold text-slate-200 truncate font-mono">
                        {metric.target.split('\\').pop() || metric.target}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate">
                        {metric.classification}
                      </div>
                    </div>
                    <div className="text-right shrink-0">
                      <div className="text-xs font-bold font-mono text-rose-400 tabular-nums">
                        {metric.entropy.toFixed(2)} bits
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono">
                        +{metric.deviation.toFixed(2)} dev
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Right: Hooked Suspicious APIs Live Feed */}
            <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
                    <Crosshair className="w-4 h-4 text-rose-400" />
                    <span>Appels API Hookés en Temps Réel</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Surveillance d'injections DLL, élévation de jetons et hooks clavier.
                  </p>
                </div>
                <button
                  onClick={() => setActiveView('APIS')}
                  className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
                >
                  <span>Explorer</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="space-y-2">
                {suspiciousApis.slice(0, 4).map(api => (
                  <div
                    key={api.id}
                    onClick={() => {
                      setInspectedApi(api);
                      setActiveView('APIS');
                    }}
                    className="p-3 bg-slate-950/70 border border-slate-800/80 hover:border-slate-700 rounded-lg cursor-pointer transition-colors space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-white">
                          {api.apiName}
                        </span>
                        <span className="text-[10px] font-mono text-slate-400">
                          PID {api.pid}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                          api.hookStatus === 'BLOCKED'
                            ? 'text-rose-400 bg-rose-950/60 border-rose-800/60'
                            : 'text-amber-400 bg-amber-950/60 border-amber-800/60'
                        }`}>
                          {api.hookStatus}
                        </span>
                        <span className="text-xs font-mono font-bold text-rose-400 tabular-nums">
                          {api.riskScore}/100
                        </span>
                      </div>
                    </div>
                    <div className="text-[11px] text-slate-400 line-clamp-1">
                      {api.details}
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1">
                      <span>{api.mitreTechnique}</span>
                      <span>{api.ratePerSec} appels/sec</span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Console Quick trigger */}
              <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
                <span className="text-xs text-slate-400">Crochets actifs sur NT & Kernel32</span>
                <button
                  onClick={() => onRunInConsole('scan --deep')}
                  className="px-3 py-1 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 text-xs rounded-lg font-medium transition-colors"
                >
                  Scanner Arbre Processus
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SECTION 4: VIEW CONTENT - ENTROPY DETAILED SCORING */}
      {/* ========================================================================= */}
      {activeView === 'ENTROPY' && (
        <div className="space-y-6">
          {/* Calcul d'Entropie & Détecteur de Ransomware / Obfuscation */}
          <FileEntropyAnalyzer onRunInConsole={onRunInConsole} />

          <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
                  <Binary className="w-4 h-4 text-cyan-400" />
                  <span>Analyse Spectrale d'Entropie de Shannon ($H \in [0.00, 8.00]$ bits/octet)</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  L'entropie mesure le désordre de distribution des octets : un code compilé normal a une entropie comprise entre 4.8 et 6.2.
                  Une valeur &gt; 7.2 indique presque systématiquement du code chiffré, compressé (UPX/Themida) ou du shellcode polymorphe.
                </p>
              </div>

              <button
                onClick={() => handleInjectAnomaly('PACKER')}
                className="px-3 py-1.5 bg-amber-950 hover:bg-amber-900 border border-amber-800 text-amber-300 rounded-lg text-xs font-semibold transition-colors shrink-0"
              >
                + Injecter Section Chiffrée (7.98 bits)
              </button>
            </div>

            {/* List / Table of Monitored Sections */}
            <div className="space-y-3">
              {entropyMetrics.map(item => {
                const percent = Math.min(100, Math.round((item.entropy / 8.0) * 100));
                const isSelected = inspectedEntropy?.id === item.id;

                return (
                  <div
                    key={item.id}
                    className={`p-4 rounded-xl border transition-all ${
                      isSelected
                        ? 'bg-slate-900 border-cyan-500/80 shadow-md'
                        : 'bg-slate-950/80 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                      <div className="space-y-1 min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-xs font-bold text-white truncate">
                            {item.target}
                          </span>
                          <span className="text-slate-500 font-mono text-xs">·</span>
                          <span className="text-xs text-slate-400 font-mono">
                            PID {item.pid} ({item.process})
                          </span>
                        </div>
                        <div className="text-xs text-slate-300">
                          Section : <strong className="font-mono text-cyan-300">{item.section}</strong> · {item.classification}
                        </div>
                      </div>

                      {/* Visual Gauge of Shannon Entropy */}
                      <div className="w-full md:w-64 space-y-1.5 shrink-0">
                        <div className="flex items-center justify-between text-xs font-mono">
                          <span className="text-slate-400">Entropie :</span>
                          <span className={`font-bold tabular-nums ${
                            item.status === 'CRITICAL_PACKED'
                              ? 'text-rose-400'
                              : item.status === 'ELEVATED'
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }`}>
                            {item.entropy.toFixed(2)} / 8.00 bits
                          </span>
                        </div>
                        {/* Progress bar with color thresholds */}
                        <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all duration-300 ${
                              item.status === 'CRITICAL_PACKED'
                                ? 'bg-rose-500'
                                : item.status === 'ELEVATED'
                                ? 'bg-amber-400'
                                : 'bg-emerald-400'
                            }`}
                            style={{ width: `${percent}%` }}
                          />
                        </div>
                        <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
                          <span>Base : {item.baseline.toFixed(2)}</span>
                          <span className="text-slate-400">Écart : +{item.deviation.toFixed(2)}</span>
                          <span>{(item.sizeBytes / 1024).toFixed(0)} Ko</span>
                        </div>
                      </div>

                      {/* Action Button */}
                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          onClick={() => {
                            if (item.target.includes('.sys')) {
                              onRunInConsole(`unlock ${item.target}`);
                            } else {
                              onRunInConsole(`kill ${item.pid}`);
                            }
                          }}
                          className="px-3 py-1.5 bg-rose-950 hover:bg-rose-900 border border-rose-800 text-rose-300 rounded-lg text-xs font-medium transition-colors"
                        >
                          {item.target.includes('.sys') ? 'Neutraliser Driver' : 'Abattre PID'}
                        </button>
                        <button
                          onClick={() => setInspectedEntropy(isSelected ? null : item)}
                          className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-mono"
                        >
                          {isSelected ? 'Fermer' : 'Inspecter'}
                        </button>
                      </div>
                    </div>

                    {/* Inspected Section Details */}
                    {isSelected && (
                      <div className="mt-4 pt-4 border-t border-slate-800/80 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono bg-slate-900/60 p-3 rounded-lg">
                        <div>
                          <div className="text-slate-400 font-semibold mb-1">Détails de l'Inspecteur PE / VAD</div>
                          <div className="text-slate-300">Emplacement : {item.target}</div>
                          <div className="text-slate-300">Taille Réelle : {item.sizeBytes} octets ({Math.round(item.sizeBytes / 1024)} Ko)</div>
                          <div className="text-slate-300">Status Obfuscation : {item.isObfuscated ? 'CONFIRMÉ (Packer actif)' : 'Non détecté'}</div>
                        </div>
                        <div>
                          <div className="text-slate-400 font-semibold mb-1">Diagnostic Heuristique</div>
                          <div className="text-slate-300">
                            {item.entropy > 7.5
                              ? 'Alerte : Uniformité quasi-parfaite des octets. Signe probant de chiffrement de charge utile ou de coquille polymorphe.'
                              : item.entropy > 6.5
                              ? 'Attention : Entropie surélevée. Possibilité de données graphiques embarquées ou de compression intermédiaire.'
                              : 'Nominal : Distribution normale d\'instructions assembleur x86/x64.'}
                          </div>
                          <div className="mt-2 text-cyan-400">
                            Action recommandée : Analyser les imports et la table d'adresses d'importation (IAT).
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SECTION 4-B: VIEW CONTENT - REGISTRY PERSISTENCE SURVEILLANCE */}
      {/* ========================================================================= */}
      {activeView === 'REGISTRY' && (
        <RegistrySurveillancePanel onRunInConsole={onRunInConsole} />
      )}

      {/* ========================================================================= */}
      {/* SECTION 4-C: VIEW CONTENT - DIGITAL SIGNATURE INSPECTOR & SPOOFING */}
      {/* ========================================================================= */}
      {activeView === 'SIGNATURES' && (
        <DigitalSignatureInspector onRunInConsole={onRunInConsole} />
      )}

      {/* ========================================================================= */}
      {/* SECTION 5: VIEW CONTENT - SUSPICIOUS APIS */}
      {/* ========================================================================= */}
      {activeView === 'APIS' && (
        <div className="space-y-6">
          <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <span>Crochets d'Interception d'Appels API Natifs NT / Win32</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Surveillance dynamique des fonctions critiques utilisées pour l'injection de code, l'évasion de défenses et l'usurpation de jetons.
                </p>
              </div>

              {/* Filters */}
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleInjectAnomaly('HOLLOWING')}
                  className="px-3 py-1.5 bg-rose-950 hover:bg-rose-900 border border-rose-800 text-rose-300 rounded-lg text-xs font-semibold transition-colors shrink-0"
                >
                  + Injecter Rafale Injection
                </button>
                <button
                  onClick={() => handleInjectAnomaly('LSASS_DUMP')}
                  className="px-3 py-1.5 bg-amber-950 hover:bg-amber-900 border border-amber-800 text-amber-300 rounded-lg text-xs font-semibold transition-colors shrink-0"
                >
                  + Injecter Dump LSASS
                </button>
              </div>
            </div>

            {/* Category Filter Pills & Search */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
              <div className="flex items-center gap-1.5 flex-wrap">
                {(['ALL', 'INJECTION', 'CREDENTIAL', 'PERSISTENCE', 'EVASION'] as const).map(cat => (
                  <button
                    key={cat}
                    onClick={() => setApiCategoryFilter(cat)}
                    className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                      apiCategoryFilter === cat
                        ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 font-bold'
                        : 'bg-slate-950/60 text-slate-400 hover:text-white border border-slate-800'
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>

              <div className="relative w-full sm:w-64">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder="Rechercher API, PID, MITRE..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
            </div>

            {/* API Hooks Table */}
            <div className="space-y-2.5">
              {filteredApis.length === 0 ? (
                <div className="py-8 text-center text-xs text-slate-500 font-mono">
                  Aucun appel API correspondant au filtre actuel.
                </div>
              ) : (
                filteredApis.map(api => (
                  <div
                    key={api.id}
                    className="p-3.5 bg-slate-950/80 border border-slate-800 rounded-xl hover:border-slate-700 transition-all space-y-2"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <span className="font-mono text-xs font-bold text-white">
                          {api.apiName}
                        </span>
                        <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                          {api.category}
                        </span>
                        <span className="text-xs text-slate-400 font-mono">
                          PID {api.pid} ({api.callerProcess})
                        </span>
                        {api.targetProcess && (
                          <span className="text-xs text-rose-400 font-mono">
                            ➔ {api.targetProcess} (PID {api.targetPid})
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                          api.hookStatus === 'BLOCKED'
                            ? 'text-rose-300 bg-rose-950/80 border-rose-800'
                            : api.hookStatus === 'INTERCEPTED'
                            ? 'text-amber-300 bg-amber-950/80 border-amber-800'
                            : 'text-cyan-300 bg-cyan-950/80 border-cyan-800'
                        }`}>
                          {api.hookStatus}
                        </span>

                        <span className="text-xs font-mono font-bold text-rose-400 tabular-nums">
                          Score {api.riskScore}/100
                        </span>

                        <button
                          onClick={() => onRunInConsole(`kill ${api.pid}`)}
                          className="px-2.5 py-1 bg-rose-950 hover:bg-rose-900 border border-rose-800 text-rose-300 text-xs rounded font-medium transition-colors"
                        >
                          Tuer PID {api.pid}
                        </button>
                      </div>
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed">
                      {api.details}
                    </p>

                    <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono pt-1 border-t border-slate-900">
                      <span>MITRE : <strong className="text-slate-300">{api.mitreTechnique}</strong></span>
                      <div className="flex items-center gap-3">
                        <span>Total : {api.callCount} appels</span>
                        <span className="text-cyan-400">{api.ratePerSec} appels/sec</span>
                        <span className="text-slate-500">{api.timestamp}</span>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SECTION 6: VIEW CONTENT - CONFIDENCE MATRIX */}
      {/* ========================================================================= */}
      {activeView === 'CONFIDENCE_MATRIX' && (
        <div className="space-y-6">
          {/* Bulk Action Feedback Message */}
          {bulkFeedbackMessage && (
            <div className="p-3 bg-cyan-950/80 border border-cyan-800 rounded-xl flex items-center justify-between text-xs text-cyan-200 animate-in fade-in duration-200">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
                <span>{bulkFeedbackMessage}</span>
              </div>
            </div>
          )}

          <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
                  <Flame className="w-4 h-4 text-rose-400" />
                  <span>Matrice de Confiance Multi-Critères des Menaces Détectées</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Agrégation des vecteurs d'entropie (poids : {(weights.entropy * 100).toFixed(0)}%), d'appels API ({(weights.api * 100).toFixed(0)}%),
                  de comportement ({(weights.behavior * 100).toFixed(0)}%) et de conformité MITRE ({(weights.mitre * 100).toFixed(0)}%).
                </p>
              </div>

              {/* Controls */}
              <div className="flex items-center gap-2 text-xs font-mono">
                <button
                  onClick={() => setShowDismissedConfidence(!showDismissedConfidence)}
                  className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border transition-colors ${
                    showDismissedConfidence
                      ? 'bg-slate-800 text-cyan-300 border-cyan-800'
                      : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
                  }`}
                >
                  <EyeOff className="w-3.5 h-3.5 text-slate-400" />
                  <span>Ignorées ({dismissedConfidenceIds.size})</span>
                </button>

                <div className="flex items-center gap-1.5 pl-2 border-l border-slate-800">
                  <span className="text-slate-400">Pondération :</span>
                  <span className="text-cyan-300 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                    {preset}
                  </span>
                </div>
              </div>
            </div>

            {/* Selection Toolbar */}
            <div className="flex items-center justify-between gap-3 pt-2 border-t border-slate-800 flex-wrap text-xs">
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={handleToggleSelectAllConfidence}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg font-mono bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors"
                >
                  {selectedConfidenceIds.size > 0 && selectedConfidenceIds.size === displayedConfidenceThreats.length ? (
                    <CheckSquare className="w-3.5 h-3.5 text-cyan-400" />
                  ) : selectedConfidenceIds.size > 0 ? (
                    <MinusSquare className="w-3.5 h-3.5 text-cyan-400" />
                  ) : (
                    <Square className="w-3.5 h-3.5 text-slate-500" />
                  )}
                  <span>Tout ({displayedConfidenceThreats.length})</span>
                </button>

                <button
                  onClick={handleSelectHighConfidenceOnly}
                  className="px-2.5 py-1.5 rounded-lg font-mono bg-slate-950 hover:bg-slate-800 text-rose-400 border border-slate-800 transition-colors"
                >
                  Forte Confiance (&ge;85%)
                </button>

                {selectedConfidenceIds.size > 0 && (
                  <button
                    onClick={handleClearConfidenceSelection}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg font-mono text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
                  >
                    <X className="w-3 h-3" />
                    <span>Effacer</span>
                  </button>
                )}
              </div>

              <div className="text-xs text-slate-500 font-mono">
                {selectedConfidenceIds.size} sélectionnée(s) sur {displayedConfidenceThreats.length}
              </div>
            </div>

            {/* Sticky Bulk Action Command Bar */}
            {selectedConfidenceIds.size > 0 && (
              <div className="p-3 bg-gradient-to-r from-slate-950 via-slate-900 to-cyan-950/40 rounded-xl border border-cyan-800/80 shadow-lg shadow-cyan-950/30 space-y-2 animate-in slide-in-from-top-2 duration-200">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 rounded-lg bg-cyan-950 text-cyan-300 border border-cyan-800">
                      <Layers className="w-4 h-4 text-cyan-400" />
                    </div>
                    <div>
                      <div className="text-xs font-bold text-white flex items-center gap-1.5">
                        <span>Actions Groupées sur Menaces Heuristiques</span>
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                          {selectedConfidenceIds.size} cible{selectedConfidenceIds.size > 1 ? 's' : ''}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400">
                        Exécutez un modèle de commande partagé ou marquez comme ignorées en masse.
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 flex-wrap">
                    {/* Bulk Remediate */}
                    <button
                      onClick={handleBulkRemediateConfidence}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold font-mono text-slate-950 bg-cyan-400 hover:bg-cyan-300 shadow-md transition-all"
                      title="Exécute les commandes d'éradication pour toutes les menaces sélectionnées"
                    >
                      <Zap className="w-3.5 h-3.5" />
                      <span>Éradication Groupée ({selectedConfidenceIds.size})</span>
                    </button>

                    {/* Shared Command Runner */}
                    <button
                      onClick={() => setIsSharedCommandModalOpen(true)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold font-mono text-cyan-200 bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 shadow-sm shadow-cyan-950 transition-all"
                      title="Exécute un modèle de commande unifié sur les menaces sélectionnées"
                    >
                      <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Commande Partagée...</span>
                    </button>

                    {/* Mass Dismiss */}
                    <button
                      onClick={handleMassDismissConfidence}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono text-slate-300 bg-slate-800 hover:bg-slate-700 hover:text-slate-100 border border-slate-700 transition-colors"
                      title="Rejeter et marquer comme traitées/fausses alertes en masse"
                    >
                      <EyeOff className="w-3.5 h-3.5 text-slate-400" />
                      <span>Rejet en Masse</span>
                    </button>

                    {/* Cancel Selection */}
                    <button
                      onClick={handleClearConfidenceSelection}
                      className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
                      title="Annuler la sélection"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Threat Confidence Cards */}
            <div className="space-y-4">
              {displayedConfidenceThreats.map(threat => {
                const isSelected = selectedConfidenceIds.has(threat.id);
                const isDismissed = dismissedConfidenceIds.has(threat.id);

                // Dynamically recompute confidence based on active user weights
                const dynamicConfidence = Math.round((
                  threat.entropyScore * weights.entropy +
                  threat.apiScore * weights.api +
                  threat.behaviorScore * weights.behavior +
                  threat.mitreAlignment * weights.mitre
                ) * 10) / 10;

                return (
                  <div
                    key={threat.id}
                    className={`p-4 rounded-xl space-y-3 transition-all border ${
                      isSelected
                        ? 'bg-slate-950/95 border-cyan-500 ring-1 ring-cyan-500/50 shadow-md shadow-cyan-950/40'
                        : isDismissed
                        ? 'bg-slate-950/40 border-slate-800/60 opacity-60'
                        : 'bg-slate-950/90 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                      <div className="flex items-center gap-2.5">
                        <button
                          type="button"
                          onClick={(e) => toggleSelectConfidence(threat.id, e)}
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

                        <div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <h4 className={`text-sm font-bold font-['Plus_Jakarta_Sans'] ${isDismissed ? 'line-through text-slate-500' : 'text-white'}`}>
                              {threat.threatName}
                            </h4>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded border text-rose-300 bg-rose-950/80 border-rose-800">
                              {threat.verdict}
                            </span>
                            {isDismissed && (
                              <span className="text-[10px] font-mono px-2 py-0.5 rounded border text-slate-400 bg-slate-900 border-slate-700">
                                REJETÉE
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-slate-400 font-mono mt-0.5 truncate max-w-xl">
                            {threat.targetPath}
                          </p>
                        </div>
                      </div>

                      {/* Overall Confidence Display */}
                      <div className="flex items-center gap-3">
                        <div className="text-right">
                          <div className="text-xs text-slate-400 font-medium">Confiance Heuristique</div>
                          <div className="text-xl font-extrabold font-mono text-cyan-300 tabular-nums">
                            {dynamicConfidence.toFixed(1)}%
                          </div>
                        </div>

                        {isDismissed ? (
                          <button
                            onClick={() => {
                              setDismissedConfidenceIds(prev => {
                                const next = new Set(prev);
                                next.delete(threat.id);
                                return next;
                              });
                              setBulkFeedbackMessage(`Menace réactivée dans la liste active.`);
                              setTimeout(() => setBulkFeedbackMessage(null), 3000);
                            }}
                            className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium rounded-lg text-xs transition-colors shrink-0 border border-slate-700"
                          >
                            Restaurer
                          </button>
                        ) : (
                          <button
                            onClick={() => onRunInConsole(threat.remediationCmd)}
                            className="px-3 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold rounded-lg text-xs transition-colors shrink-0 shadow-sm"
                          >
                            Éradiquer la Menace
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Breakdown Factors (4 bars) */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 border-t border-slate-900">
                      <div className="space-y-1">
                        <div className="flex justify-between text-[11px] font-mono">
                          <span className="text-slate-400">Score Entropie</span>
                          <span className="text-amber-400 font-bold">{threat.entropyScore}%</span>
                        </div>
                        <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full bg-amber-400 rounded-full" style={{ width: `${threat.entropyScore}%` }} />
                        </div>
                      </div>

                      <div className="space-y-1">
                        <div className="flex justify-between text-[11px] font-mono">
                          <span className="text-slate-400">Score Appels API</span>
                          <span className="text-rose-400 font-bold">{threat.apiScore}%</span>
                        </div>
                        <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full bg-rose-400 rounded-full" style={{ width: `${threat.apiScore}%` }} />
                        </div>
                      </div>

                      <div className="space-y-1">
                        <div className="flex justify-between text-[11px] font-mono">
                          <span className="text-slate-400">Comportement</span>
                          <span className="text-cyan-400 font-bold">{threat.behaviorScore}%</span>
                        </div>
                        <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full bg-cyan-400 rounded-full" style={{ width: `${threat.behaviorScore}%` }} />
                        </div>
                      </div>

                      <div className="space-y-1">
                        <div className="flex justify-between text-[11px] font-mono">
                          <span className="text-slate-400">Alignement MITRE</span>
                          <span className="text-indigo-400 font-bold">{threat.mitreAlignment}%</span>
                        </div>
                        <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full bg-indigo-400 rounded-full" style={{ width: `${threat.mitreAlignment}%` }} />
                        </div>
                      </div>
                    </div>

                    {/* Recommendation Line */}
                    <div className="flex items-center justify-between text-xs text-slate-300 pt-2 border-t border-slate-900/80">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 font-mono">Recommandation :</span>
                        <span>{threat.recommendedAction}</span>
                      </div>
                      <span className="font-mono text-cyan-400 text-[11px] hidden sm:inline">
                        {threat.primaryTechnique}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Shared Command Modal for Heuristic Threats */}
      <SharedCommandModal
        isOpen={isSharedCommandModalOpen}
        onClose={() => setIsSharedCommandModalOpen(false)}
        selectedThreats={selectedThreatsForModal}
        onExecuteSharedCommand={handleExecuteSharedCommandConfidence}
      />
    </div>
  );
};
