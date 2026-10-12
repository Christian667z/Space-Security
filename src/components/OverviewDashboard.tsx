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
} from 'lucide-react';
import { TabId, ThreatItem } from '../types/cyberdefense';
import { ThreatHeatmap } from './ThreatHeatmap';
import { ThreatIntensityMap } from './ThreatIntensityMap';
import { calculateSecurityScore } from '../utils/pdfReportGenerator';

interface OverviewDashboardProps {
  onNavigateTab: (tab: TabId) => void;
  onRunInConsole: (command: string) => void;
  threats: ThreatItem[];
  onDownloadZip: () => void;
  onOpenPdfReport?: () => void;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  onNavigateTab,
  onRunInConsole,
  threats,
  onDownloadZip,
  onOpenPdfReport,
}) => {
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM'>('ALL');
  const [searchThreatQuery, setSearchThreatQuery] = useState<string>('');
  const [sortBySeverity, setSortBySeverity] = useState<boolean>(true);

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

  // Filtered and sorted threat list
  const displayedThreats = useMemo(() => {
    return threats
      .filter(threat => {
        if (severityFilter !== 'ALL' && threat.severity !== severityFilter) {
          return false;
        }
        if (searchThreatQuery.trim()) {
          const q = searchThreatQuery.toLowerCase();
          const matches =
            threat.name.toLowerCase().includes(q) ||
            threat.description.toLowerCase().includes(q) ||
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
  }, [threats, severityFilter, searchThreatQuery, sortBySeverity]);
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
              185.220.101.4 svch0st
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
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <h3 className="text-base font-semibold text-slate-100">
                Menaces Détectées en Attente d'Action
              </h3>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                {displayedThreats.length} / {threats.length}
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

          {/* Threats List */}
          <div className="space-y-3">
            {displayedThreats.length === 0 ? (
              <div className="p-8 text-center bg-slate-950/60 border border-slate-800/80 rounded-xl space-y-3">
                <Shield className="w-8 h-8 text-slate-600 mx-auto" />
                <div className="text-sm font-semibold text-slate-300">
                  Aucune menace ne correspond aux filtres sélectionnés
                </div>
                <p className="text-xs text-slate-500 max-w-sm mx-auto">
                  Modifiez votre critère de sévérité ou effacez le terme de recherche pour afficher les autres menaces répertoriées.
                </p>
                <button
                  onClick={() => {
                    setSeverityFilter('ALL');
                    setSearchThreatQuery('');
                  }}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-400 rounded-lg text-xs font-mono font-semibold transition-colors"
                >
                  Afficher Toutes les Menaces
                </button>
              </div>
            ) : (
              displayedThreats.map(threat => {
                const isCritical = threat.severity === 'CRITICAL';
                const isHigh = threat.severity === 'HIGH';
                const isMedium = threat.severity === 'MEDIUM';

                return (
                  <div
                    key={threat.id}
                    className={`p-4 rounded-xl transition-all space-y-2.5 border ${
                      isCritical
                        ? 'bg-slate-950/90 border-rose-900/60 hover:border-rose-700/80 shadow-sm shadow-rose-950/30'
                        : isHigh
                        ? 'bg-slate-950/90 border-orange-900/60 hover:border-orange-700/80 shadow-sm shadow-orange-950/30'
                        : 'bg-slate-950/80 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        {isCritical && (
                          <span className="inline-flex items-center gap-1 font-bold text-xs text-rose-400 bg-rose-950/80 border border-rose-800/80 px-2 py-0.5 rounded">
                            <Flame className="w-3 h-3 text-rose-400 animate-pulse" />
                            [CRITIQUE]
                          </span>
                        )}
                        {isHigh && (
                          <span className="inline-flex items-center gap-1 font-bold text-xs text-orange-400 bg-orange-950/80 border border-orange-800/80 px-2 py-0.5 rounded">
                            <AlertTriangle className="w-3 h-3 text-orange-400" />
                            [ÉLEVÉ]
                          </span>
                        )}
                        {isMedium && (
                          <span className="inline-flex items-center gap-1 font-bold text-xs text-amber-400 bg-amber-950/80 border border-amber-800/80 px-2 py-0.5 rounded">
                            [MOYEN]
                          </span>
                        )}

                        <span className="font-semibold text-sm text-slate-100">
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

                    <div className="text-xs text-slate-300 leading-relaxed font-sans">
                      {threat.description}
                    </div>

                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-2 border-t border-slate-900 text-xs">
                      <div className="text-[11px] font-mono text-slate-400 truncate max-w-md">
                        Cible : <span className="text-slate-200 select-all">{threat.targetPath}</span>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        {threat.status === 'SCHEDULED_BOOT_DELETE' ? (
                          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                            Destruction planifiée au boot (0 octet)
                          </span>
                        ) : (
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
              className="p-3.5 bg-slate-950 border border-slate-800 hover:border-cyan-800 rounded-xl cursor-pointer transition-colors group"
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-cyan-300 group-hover:text-cyan-200">
                  Script Workshop (.ps1 & .bat)
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-300 transition-transform group-hover:translate-x-1" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Visualisez et téléchargez les scripts complets pour vos machines Windows.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
