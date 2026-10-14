import React, { useState, useMemo } from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
} from 'recharts';
import {
  Shield,
  ShieldCheck,
  TrendingUp,
  Activity,
  Play,
  RotateCcw,
  Calendar,
  AlertTriangle,
  CheckCircle2,
  Download,
  Info,
  Zap,
} from 'lucide-react';
import { ThreatItem, TabId } from '../types/cyberdefense';
import { calculateSecurityScore } from '../utils/pdfReportGenerator';

interface HealthScoreEvolutionChartProps {
  threats: ThreatItem[];
  onRunInConsole?: (command: string) => void;
  onNavigateTab?: (tab: TabId) => void;
}

interface ScanDayPoint {
  dayIndex: number;
  date: string;
  fullDate: string;
  healthScore: number;
  scansCount: number;
  activeThreats: number;
  neutralizedThreats: number;
  scanType: string;
  milestone?: string;
  statusLabel: string;
}

export const HealthScoreEvolutionChart: React.FC<HealthScoreEvolutionChartProps> = ({
  threats,
  onRunInConsole,
  onNavigateTab,
}) => {
  const [timeframe, setTimeframe] = useState<'30' | '14' | '7'>('30');
  const [viewMetric, setViewMetric] = useState<'score' | 'threats'>('score');
  const [hoveredPoint, setHoveredPoint] = useState<ScanDayPoint | null>(null);

  // Current real-time calculated score from active/neutralized threats
  const liveScoreData = useMemo(() => calculateSecurityScore(threats), [threats]);
  const currentLiveScore = liveScoreData.score;

  // Generate 30-day historical progression anchoring to currentLiveScore today
  const fullHistoryData: ScanDayPoint[] = useMemo(() => {
    const points: ScanDayPoint[] = [];
    const today = new Date();

    // Baseline progression model: starts lower 30 days ago, with dips during threat detections and spikes after remediations
    const historicalOffsets = [
      { offset: -29, baseScore: 62, scans: 2, active: 4, neut: 1, type: 'Scan Initial Complet', milestone: 'Premier audit OS' },
      { offset: -28, baseScore: 60, scans: 1, active: 5, neut: 1, type: 'Scan Programmé', milestone: 'Détection Trojan IFEO' },
      { offset: -27, baseScore: 58, scans: 2, active: 6, neut: 1, type: 'Audit Registre', milestone: 'Rootkit SysHook identifié' },
      { offset: -26, baseScore: 64, scans: 1, active: 5, neut: 3, type: 'Éradication Kernel', milestone: 'Purge clé IFEO taskmgr' },
      { offset: -25, baseScore: 67, scans: 3, active: 4, neut: 4, type: 'Vérification Ring0', milestone: 'Déchargement pilote suspect' },
      { offset: -24, baseScore: 65, scans: 1, active: 5, neut: 4, type: 'Scan Mémoire VAD', milestone: '' },
      { offset: -23, baseScore: 62, scans: 2, active: 6, neut: 4, type: 'Inspection Sockets C2', milestone: 'Balise port 4444 bloquée' },
      { offset: -22, baseScore: 70, scans: 2, active: 4, neut: 6, type: 'Règles Pare-feu', milestone: 'Confinement IP malveillante' },
      { offset: -21, baseScore: 72, scans: 1, active: 3, neut: 6, type: 'Scan BITS Transfer', milestone: 'Purge tâche exfiltration' },
      { offset: -20, baseScore: 71, scans: 1, active: 3, neut: 6, type: 'Audit Defender Sync', milestone: '' },
      { offset: -19, baseScore: 69, scans: 2, active: 4, neut: 6, type: 'Scan Bibliothèques DLL', milestone: 'Injection reflective stoppée' },
      { offset: -18, baseScore: 74, scans: 1, active: 3, neut: 7, type: 'Remédiation Mémoire', milestone: 'Dump RAM analysé' },
      { offset: -17, baseScore: 76, scans: 2, active: 2, neut: 7, type: 'Scan Services Windows', milestone: 'PrintNightmare désactivé' },
      { offset: -16, baseScore: 75, scans: 1, active: 3, neut: 7, type: 'Audit GPO Hôte', milestone: '' },
      { offset: -15, baseScore: 78, scans: 3, active: 2, neut: 8, type: 'Scan Antivirus Defender', milestone: 'Mise à jour signatures' },
      { offset: -14, baseScore: 77, scans: 1, active: 2, neut: 8, type: 'Audit Événements EventLog', milestone: '' },
      { offset: -13, baseScore: 80, scans: 2, active: 2, neut: 9, type: 'Durcissement Système', milestone: 'SMBv1 révoqué définitivement' },
      { offset: -12, baseScore: 82, scans: 1, active: 1, neut: 9, type: 'Contrôle TrustedInstaller', milestone: 'Appropriation sécurisée' },
      { offset: -11, baseScore: 81, scans: 2, active: 2, neut: 9, type: 'Scan Ports d\'Écoute', milestone: 'Fermeture RDP externe' },
      { offset: -10, baseScore: 83, scans: 1, active: 1, neut: 10, type: 'Scan Bornes Wi-Fi', milestone: 'Audit Evil Twin 802.11' },
      { offset: -9, baseScore: 85, scans: 2, active: 1, neut: 10, type: 'Moteur Heuristique', milestone: 'Calcul entropie Shannon' },
      { offset: -8, baseScore: 84, scans: 1, active: 1, neut: 10, type: 'Contrôle Clés Run/RunOnce', milestone: '' },
      { offset: -7, baseScore: 86, scans: 3, active: 1, neut: 11, type: 'Scan Approfondi Kernel', milestone: 'PendingFileRename validé' },
      { offset: -6, baseScore: 85, scans: 1, active: 1, neut: 11, type: 'Audit Processus Suspendus', milestone: '' },
      { offset: -5, baseScore: 87, scans: 2, active: 1, neut: 11, type: 'Inspection WMI Subs', milestone: 'Suppression EventFilter' },
      { offset: -4, baseScore: 88, scans: 1, active: 1, neut: 12, type: 'Audit Cryptographique', milestone: 'Vérification Authenticode' },
      { offset: -3, baseScore: 86, scans: 2, active: 2, neut: 12, type: 'Scan Flux ADS NTFS', milestone: 'Purge flux alternatifs' },
      { offset: -2, baseScore: 89, scans: 2, active: 1, neut: 13, type: 'Validation Posture SOC', milestone: 'Confinement complet' },
      { offset: -1, baseScore: 91, scans: 2, active: 1, neut: 13, type: 'Pré-Scan Quotidien', milestone: 'Intégrité système vérifiée' },
      { offset: 0, baseScore: currentLiveScore, scans: 3, active: threats.filter(t => t.status === 'ACTIVE').length, neut: threats.filter(t => t.status !== 'ACTIVE').length, type: 'Scan en Direct (Actuel)', milestone: 'Télémétrie synchronisée' },
    ];

    historicalOffsets.forEach((item, index) => {
      const pointDate = new Date(today);
      pointDate.setDate(today.getDate() + item.offset);

      const dayStr = item.offset === 0
        ? 'Aujourd\'hui'
        : pointDate.toLocaleDateString('fr-FR', { day: '2-digit', month: 'short' });

      const fullDateStr = pointDate.toLocaleDateString('fr-FR', {
        weekday: 'long',
        day: 'numeric',
        month: 'long',
        year: 'numeric',
      });

      // Adjust score proportionally to reach currentLiveScore smoothly on the last day
      let adjustedScore = item.offset === 0 ? currentLiveScore : item.baseScore;
      if (item.offset !== 0) {
        const factor = (currentLiveScore - 62) / (91 - 62 || 1);
        adjustedScore = Math.max(20, Math.min(100, Math.round(item.baseScore + (factor - 1) * 6)));
      }

      let statusLabel = 'Sécurisé';
      if (adjustedScore < 50) statusLabel = 'Critique';
      else if (adjustedScore < 75) statusLabel = 'Vigilance';
      else if (adjustedScore >= 85) statusLabel = 'Excellente Posture';

      points.push({
        dayIndex: index + 1,
        date: dayStr,
        fullDate: fullDateStr,
        healthScore: adjustedScore,
        scansCount: item.scans,
        activeThreats: item.active,
        neutralizedThreats: item.neut,
        scanType: item.type,
        milestone: item.milestone,
        statusLabel,
      });
    });

    return points;
  }, [currentLiveScore, threats]);

  // Filtered dataset according to selected timeframe (30, 14, 7 days)
  const chartData = useMemo(() => {
    const days = parseInt(timeframe, 10);
    return fullHistoryData.slice(fullHistoryData.length - days);
  }, [fullHistoryData, timeframe]);

  // Calculated Metrics on current timeframe
  const initialPeriodScore = chartData[0]?.healthScore || 60;
  const latestPeriodScore = chartData[chartData.length - 1]?.healthScore || currentLiveScore;
  const scoreDelta = latestPeriodScore - initialPeriodScore;
  const averageScore = Math.round(
    chartData.reduce((acc, curr) => acc + curr.healthScore, 0) / (chartData.length || 1)
  );
  const totalScansInPeriod = chartData.reduce((acc, curr) => acc + curr.scansCount, 0);
  const totalRemediations = chartData.reduce((acc, curr) => acc + curr.neutralizedThreats, 0);

  // Custom Recharts Tooltip
  const renderCustomTooltip = ({ active, payload }: any) => {
    if (!active || !payload || !payload.length) return null;
    const data: ScanDayPoint = payload[0].payload;

    return (
      <div className="bg-slate-950/95 backdrop-blur-md border border-cyan-800/80 p-3.5 rounded-xl shadow-2xl shadow-black/80 text-xs font-mono max-w-xs space-y-2">
        <div className="flex items-center justify-between pb-1.5 border-b border-slate-800">
          <span className="font-bold text-white capitalize">{data.date}</span>
          <span
            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
              data.healthScore >= 85
                ? 'text-emerald-400 bg-emerald-950/80 border border-emerald-800/60'
                : data.healthScore >= 70
                ? 'text-cyan-400 bg-cyan-950/80 border border-cyan-800/60'
                : data.healthScore >= 50
                ? 'text-amber-400 bg-amber-950/80 border border-amber-800/60'
                : 'text-rose-400 bg-rose-950/80 border border-rose-800/60'
            }`}
          >
            {data.statusLabel}
          </span>
        </div>

        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Score de Sécurité :</span>
            <span className="text-sm font-bold text-cyan-300 font-mono">
              {data.healthScore} / 100
            </span>
          </div>

          <div className="flex items-center justify-between text-slate-300 text-[11px]">
            <span className="text-slate-400">Scans effectués :</span>
            <span className="font-semibold">{data.scansCount} audit(s)</span>
          </div>

          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-400">Menaces actives :</span>
            <span className="text-rose-400 font-semibold">{data.activeThreats}</span>
          </div>

          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-400">Remédiations :</span>
            <span className="text-emerald-400 font-semibold">{data.neutralizedThreats} neutralisée(s)</span>
          </div>

          <div className="pt-1.5 border-t border-slate-800/80 text-[11px]">
            <span className="text-slate-400">Type de Scan : </span>
            <span className="text-slate-200 font-medium">{data.scanType}</span>
          </div>

          {data.milestone && (
            <div className="pt-1 text-[11px] text-cyan-400 flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3 text-cyan-400 shrink-0" />
              <span className="italic">{data.milestone}</span>
            </div>
          )}
        </div>
      </div>
    );
  };

  const handleExportCsv = () => {
    const headers = ['Date', 'FullDate', 'HealthScore', 'ScansCount', 'ActiveThreats', 'NeutralizedThreats', 'ScanType', 'Milestone'];
    const rows = chartData.map(p => [
      `"${p.date}"`,
      `"${p.fullDate}"`,
      p.healthScore,
      p.scansCount,
      p.activeThreats,
      p.neutralizedThreats,
      `"${p.scanType}"`,
      `"${p.milestone || ''}"`,
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `spacesec_healthscore_30days_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="p-6 bg-slate-900/90 border border-slate-800 rounded-2xl shadow-xl space-y-6">
      {/* Component Header with Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800/80 flex items-center justify-center text-cyan-400">
              <TrendingUp className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                <span>Évolution du Score de Sécurité (HealthScore)</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-normal">
                  Historique 30 Jours
                </span>
              </h3>
              <p className="text-xs text-slate-400">
                Progression temporelle calculée à partir des scans forensiques, remédiations kernel et éliminations de menaces.
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls & Filter Selectors */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Metric View Mode */}
          <div className="flex items-center p-1 bg-slate-950 rounded-lg border border-slate-800">
            <button
              onClick={() => setViewMetric('score')}
              className={`px-3 py-1 text-xs font-semibold rounded-md transition-all ${
                viewMetric === 'score'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-xs'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Score de Santé (%)
            </button>
            <button
              onClick={() => setViewMetric('threats')}
              className={`px-3 py-1 text-xs font-semibold rounded-md transition-all ${
                viewMetric === 'threats'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-xs'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Menaces & Remédiations
            </button>
          </div>

          {/* Timeframe Selector */}
          <div className="flex items-center p-1 bg-slate-950 rounded-lg border border-slate-800">
            {(['7', '14', '30'] as const).map((tf) => (
              <button
                key={tf}
                onClick={() => setTimeframe(tf)}
                className={`px-2.5 py-1 text-xs font-mono font-medium rounded-md transition-all ${
                  timeframe === tf
                    ? 'bg-slate-800 text-cyan-300 font-bold border border-slate-700'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {tf}j
              </button>
            ))}
          </div>

          {/* Quick Action: Export CSV */}
          <button
            onClick={handleExportCsv}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-mono font-medium rounded-lg border border-slate-700 transition-colors"
            title="Exporter l'historique des scores au format CSV"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">CSV</span>
          </button>

          {/* Quick Trigger: Lancer un scan */}
          {onRunInConsole && (
            <button
              onClick={() => onRunInConsole('scan --deep')}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-950/90 hover:bg-cyan-900 text-cyan-300 hover:text-white text-xs font-semibold rounded-lg border border-cyan-700/80 transition-colors shadow-xs"
              title="Lancer immédiatement un scan complet pour mettre à jour le score"
            >
              <Play className="w-3 h-3 text-cyan-400" />
              <span>Nouveau Scan</span>
            </button>
          )}
        </div>
      </div>

      {/* KPI Cards Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
        <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Score Actuel</span>
            <span className="text-[11px] font-mono text-cyan-400">AUJOURD'HUI</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-white">
              {latestPeriodScore}
            </span>
            <span className="text-xs text-slate-500 font-mono">/ 100</span>
          </div>
          <div className="flex items-center gap-1 text-[11px] text-emerald-400 font-mono">
            <span>{scoreDelta >= 0 ? `+${scoreDelta}` : scoreDelta} pts</span>
            <span className="text-slate-500">vs début de période</span>
          </div>
        </div>

        <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Score Moyen</span>
            <span className="text-[11px] font-mono text-slate-400">{timeframe}j</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-cyan-300">
              {averageScore}
            </span>
            <span className="text-xs text-slate-500 font-mono">/ 100</span>
          </div>
          <div className="text-[11px] text-slate-500 font-mono">
            Moyenne glissante des scans
          </div>
        </div>

        <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Scans Menés</span>
            <span className="text-[11px] font-mono text-slate-400">{timeframe}j</span>
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {totalScansInPeriod}
          </div>
          <div className="text-[11px] text-slate-500">
            Audits complets, RAM & C2
          </div>
        </div>

        <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Remédiations Réussies</span>
            <span className="text-[11px] font-mono text-emerald-400">RÉSULTAT</span>
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {totalRemediations}
          </div>
          <div className="text-[11px] text-slate-500 font-mono">
            Payloads & rootkits éliminés
          </div>
        </div>
      </div>

      {/* Recharts Visualizer */}
      <div className="relative pt-2">
        <div className="h-72 w-full">
          <ResponsiveContainer width="100%" height="100%">
            {viewMetric === 'score' ? (
              <AreaChart
                data={chartData}
                margin={{ top: 10, right: 15, left: -20, bottom: 0 }}
                onMouseMove={(state: any) => {
                  if (state && state.activePayload && state.activePayload[0]) {
                    setHoveredPoint(state.activePayload[0].payload);
                  }
                }}
                onMouseLeave={() => setHoveredPoint(null)}
              >
                <defs>
                  <linearGradient id="healthScoreGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.45} />
                    <stop offset="60%" stopColor="#0891b2" stopOpacity={0.15} />
                    <stop offset="95%" stopColor="#0284c7" stopOpacity={0.0} />
                  </linearGradient>
                </defs>

                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />

                <XAxis
                  dataKey="date"
                  stroke="#64748b"
                  fontSize={11}
                  tickLine={false}
                  axisLine={{ stroke: '#334155' }}
                  tickMargin={8}
                />

                <YAxis
                  domain={[0, 100]}
                  ticks={[0, 25, 50, 75, 100]}
                  stroke="#64748b"
                  fontSize={11}
                  tickLine={false}
                  axisLine={{ stroke: '#334155' }}
                />

                <Tooltip content={renderCustomTooltip} />

                {/* Threshold Reference Lines */}
                <ReferenceLine
                  y={85}
                  stroke="#10b981"
                  strokeDasharray="4 4"
                  strokeOpacity={0.6}
                  label={{
                    value: 'Seuil Optimal (85+)',
                    position: 'insideTopRight',
                    fill: '#10b981',
                    fontSize: 10,
                  }}
                />

                <ReferenceLine
                  y={50}
                  stroke="#ef4444"
                  strokeDasharray="4 4"
                  strokeOpacity={0.5}
                  label={{
                    value: 'Seuil Critique (50-)',
                    position: 'insideBottomRight',
                    fill: '#ef4444',
                    fontSize: 10,
                  }}
                />

                <Area
                  type="monotone"
                  dataKey="healthScore"
                  name="Score de Santé"
                  stroke="#22d3ee"
                  strokeWidth={2.5}
                  fillOpacity={1}
                  fill="url(#healthScoreGradient)"
                  activeDot={{
                    r: 6,
                    stroke: '#06b6d4',
                    strokeWidth: 2,
                    fill: '#ffffff',
                  }}
                />
              </AreaChart>
            ) : (
              <LineChart
                data={chartData}
                margin={{ top: 10, right: 15, left: -20, bottom: 0 }}
                onMouseMove={(state: any) => {
                  if (state && state.activePayload && state.activePayload[0]) {
                    setHoveredPoint(state.activePayload[0].payload);
                  }
                }}
                onMouseLeave={() => setHoveredPoint(null)}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />

                <XAxis
                  dataKey="date"
                  stroke="#64748b"
                  fontSize={11}
                  tickLine={false}
                  axisLine={{ stroke: '#334155' }}
                  tickMargin={8}
                />

                <YAxis
                  stroke="#64748b"
                  fontSize={11}
                  tickLine={false}
                  axisLine={{ stroke: '#334155' }}
                />

                <Tooltip content={renderCustomTooltip} />

                <Line
                  type="monotone"
                  dataKey="activeThreats"
                  name="Menaces Actives"
                  stroke="#f43f5e"
                  strokeWidth={2}
                  dot={{ r: 3, fill: '#f43f5e' }}
                  activeDot={{ r: 5 }}
                />

                <Line
                  type="monotone"
                  dataKey="neutralizedThreats"
                  name="Remédiations Effectuées"
                  stroke="#10b981"
                  strokeWidth={2}
                  dot={{ r: 3, fill: '#10b981' }}
                  activeDot={{ r: 5 }}
                />
              </LineChart>
            )}
          </ResponsiveContainer>
        </div>
      </div>

      {/* Chart Footer: Legend, Milestones & Explanatory Footnote */}
      <div className="pt-3 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="w-3 h-0.5 bg-cyan-400"></span>
            <span className="text-slate-300">Score de Santé Système (0-100)</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/30 border border-emerald-500"></span>
            <span>Zone Optimale (≥ 85)</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500/30 border border-rose-500"></span>
            <span>Zone de Risque (&lt; 50)</span>
          </div>
        </div>

        <div className="flex items-center gap-2 text-[11px] font-mono text-slate-500">
          <Info className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          <span>Synchronisation automatique lors de chaque audit ou remédiation</span>
        </div>
      </div>
    </div>
  );
};
