import React, { useState, useMemo } from 'react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
} from 'recharts';
import {
  ShieldAlert,
  Radio,
  Clock,
  Bug,
  Key,
  HardDrive,
  Network,
  Shield,
  HelpCircle,
  Filter,
  Flame,
  CheckCircle2,
} from 'lucide-react';
import { ThreatItem } from '../types/cyberdefense';

interface CategoryConfig {
  label: string;
  shortLabel: string;
  color: string;
  icon: React.ComponentType<{ className?: string }>;
  borderClass: string;
  bgClass: string;
  textClass: string;
  description: string;
}

const CATEGORY_MAP: Record<string, CategoryConfig> = {
  Kernel: {
    label: 'Kernel / Rootkit',
    shortLabel: 'Kernel',
    color: '#f43f5e', // rose-500
    icon: Flame,
    borderClass: 'border-rose-800/60',
    bgClass: 'bg-rose-950/30',
    textClass: 'text-rose-400',
    description: 'Drivers Ring0, hook IRP_MJ_CREATE & verrouillage TrustedInstaller',
  },
  Rootkit: {
    label: 'Kernel / Rootkit',
    shortLabel: 'Kernel',
    color: '#f43f5e',
    icon: Flame,
    borderClass: 'border-rose-800/60',
    bgClass: 'bg-rose-950/30',
    textClass: 'text-rose-400',
    description: 'Drivers Ring0, hook IRP_MJ_CREATE & verrouillage TrustedInstaller',
  },
  C2: {
    label: 'C2 (Command & Control)',
    shortLabel: 'C2',
    color: '#f97316', // orange-500
    icon: Radio,
    borderClass: 'border-orange-800/60',
    bgClass: 'bg-orange-950/30',
    textClass: 'text-orange-400',
    description: 'Balises sortantes, sockets distants (Port 4444) & Reverse Shells',
  },
  Persistence: {
    label: 'Persistance',
    shortLabel: 'Persistance',
    color: '#eab308', // yellow-500
    icon: Clock,
    borderClass: 'border-yellow-800/60',
    bgClass: 'bg-yellow-950/30',
    textClass: 'text-yellow-400',
    description: 'Abonnements WMI EventConsumer, BITS jobs T1197 & abuse certutil',
  },
  Trojan: {
    label: 'Trojan / Malware',
    shortLabel: 'Trojan',
    color: '#a855f7', // purple-500
    icon: Bug,
    borderClass: 'border-purple-800/60',
    bgClass: 'bg-purple-950/30',
    textClass: 'text-purple-400',
    description: 'Binaires masqués, watchdogs croisés & charges utiles déguisées',
  },
  Privilege: {
    label: 'Privilège & IFEO',
    shortLabel: 'Privilège',
    color: '#06b6d4', // cyan-500
    icon: Key,
    borderClass: 'border-cyan-800/60',
    bgClass: 'bg-cyan-950/30',
    textClass: 'text-cyan-400',
    description: 'Pièges IFEO Debugger, contournement UAC & manipulation de jetons',
  },
  Memory: {
    label: 'Mémoire & ADS',
    shortLabel: 'Mémoire',
    color: '#3b82f6', // blue-500
    icon: HardDrive,
    borderClass: 'border-blue-800/60',
    bgClass: 'bg-blue-950/30',
    textClass: 'text-blue-400',
    description: 'Flux NTFS alternatifs (:ADS), injection DLL & injection volatile',
  },
  Network: {
    label: 'Réseau / Flux',
    shortLabel: 'Réseau',
    color: '#14b8a6', // teal-500
    icon: Network,
    borderClass: 'border-teal-800/60',
    bgClass: 'bg-teal-950/30',
    textClass: 'text-teal-400',
    description: 'Trafic non sollicité, altération du fichier HOSTS & tunnels',
  },
  Defender: {
    label: 'Protection Defender',
    shortLabel: 'Defender',
    color: '#10b981', // emerald-500
    icon: Shield,
    borderClass: 'border-emerald-800/60',
    bgClass: 'bg-emerald-950/30',
    textClass: 'text-emerald-400',
    description: 'Tentatives de désactivation de l\'antivirus & altérations GPO',
  },
};

export interface ThreatCategoryData {
  key: string;
  name: string;
  shortLabel: string;
  count: number;
  percentage: number;
  color: string;
  icon: React.ComponentType<{ className?: string }>;
  borderClass: string;
  bgClass: string;
  textClass: string;
  description: string;
  threats: ThreatItem[];
  criticalCount: number;
  highCount: number;
  activeCount: number;
}

interface ThreatCategoryDonutChartProps {
  threats: ThreatItem[];
  selectedCategory: string;
  onSelectCategory: (categoryKey: string) => void;
}

export const ThreatCategoryDonutChart: React.FC<ThreatCategoryDonutChartProps> = ({
  threats,
  selectedCategory,
  onSelectCategory,
}) => {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  const totalThreats = threats.length;

  // Process data for Donut Chart
  const chartData: ThreatCategoryData[] = useMemo(() => {
    if (totalThreats === 0) return [];

    const map: Record<string, {
      key: string;
      rawThreats: ThreatItem[];
      critical: number;
      high: number;
      active: number;
    }> = {};

    threats.forEach(t => {
      // Normalize 'Rootkit' to 'Kernel' so they are unified under Kernel / Rootkit
      const rawCat = t.category || 'Inconnu';
      const normKey = rawCat === 'Rootkit' ? 'Kernel' : rawCat;

      if (!map[normKey]) {
        map[normKey] = {
          key: normKey,
          rawThreats: [],
          critical: 0,
          high: 0,
          active: 0,
        };
      }

      map[normKey].rawThreats.push(t);
      if (t.severity === 'CRITICAL') map[normKey].critical += 1;
      if (t.severity === 'HIGH') map[normKey].high += 1;
      if (t.status === 'ACTIVE') map[normKey].active += 1;
    });

    return Object.values(map)
      .map(entry => {
        const config = CATEGORY_MAP[entry.key] || {
          label: entry.key,
          shortLabel: entry.key,
          color: '#94a3b8',
          icon: HelpCircle,
          borderClass: 'border-slate-800',
          bgClass: 'bg-slate-900',
          textClass: 'text-slate-300',
          description: 'Catégorie de menace non spécifiée',
        };

        const percentage = Math.round((entry.rawThreats.length / totalThreats) * 1000) / 10;

        return {
          key: entry.key,
          name: config.label,
          shortLabel: config.shortLabel,
          count: entry.rawThreats.length,
          percentage,
          color: config.color,
          icon: config.icon,
          borderClass: config.borderClass,
          bgClass: config.bgClass,
          textClass: config.textClass,
          description: config.description,
          threats: entry.rawThreats,
          criticalCount: entry.critical,
          highCount: entry.high,
          activeCount: entry.active,
        };
      })
      .sort((a, b) => b.count - a.count);
  }, [threats, totalThreats]);

  // Current active display (hovered or selected or overview)
  const activeHoveredData = hoveredIndex !== null ? chartData[hoveredIndex] : null;
  const activeSelectedData = selectedCategory !== 'ALL' ? chartData.find(c => c.key === selectedCategory) : null;
  const currentFocalData = activeHoveredData || activeSelectedData;

  // Dominant category
  const dominantCategory = chartData[0];

  return (
    <div className="p-5 bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 border border-slate-800 rounded-2xl relative shadow-xl overflow-hidden space-y-4">
      {/* Top Banner Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl bg-cyan-950/60 border border-cyan-800/80 text-cyan-400 shadow-inner">
            <ShieldAlert className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-white tracking-tight">
                Répartition des Menaces par Catégorie
              </h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800/60">
                Recharts · Donut Chart Ring0/C2
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Distribution vectorielle des implants malveillants identifiés sur le système hôte
            </p>
          </div>
        </div>

        {/* Category Filter Status / Reset */}
        <div className="flex items-center gap-2">
          {selectedCategory !== 'ALL' && (
            <button
              onClick={() => onSelectCategory('ALL')}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono bg-cyan-950 text-cyan-300 border border-cyan-700/80 hover:bg-cyan-900 transition-colors"
              title="Afficher toutes les catégories"
            >
              <Filter className="w-3 h-3 text-cyan-400" />
              <span>Filtre actif : {selectedCategory}</span>
              <span className="text-cyan-400 font-bold ml-1 hover:text-white">✕</span>
            </button>
          )}

          <div className="hidden md:flex items-center gap-2 text-[11px] font-mono text-slate-400">
            <span>Total : <strong className="text-white">{totalThreats}</strong> menaces</span>
            <span>·</span>
            <span><strong className="text-cyan-400">{chartData.length}</strong> catégories</span>
          </div>
        </div>
      </div>

      {/* Main Visual Content: Donut Ring + Interactive Category Breakdown Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        
        {/* Left Col: Donut Chart with Centered Metric (5 Cols) */}
        <div className="lg:col-span-5 flex flex-col items-center justify-center relative">
          <div className="relative w-full h-[230px] flex items-center justify-center">
            {totalThreats === 0 ? (
              <div className="flex flex-col items-center justify-center text-slate-500 text-xs">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mb-1" />
                <span>Aucune menace enregistrée</span>
              </div>
            ) : (
              <>
                <ResponsiveContainer width="100%" height={230}>
                  <PieChart>
                    <Tooltip
                      content={({ active, payload }) => {
                        if (active && payload && payload.length) {
                          const item = payload[0].payload as ThreatCategoryData;
                          const Icon = item.icon;
                          return (
                            <div className="p-3 bg-slate-950/95 border border-slate-700 rounded-xl shadow-2xl backdrop-blur-md text-xs space-y-1.5 min-w-[210px]">
                              <div className="flex items-center justify-between border-b border-slate-800 pb-1.5">
                                <div className="flex items-center gap-1.5 font-bold text-white">
                                  <span
                                    className="w-2.5 h-2.5 rounded-full"
                                    style={{ backgroundColor: item.color }}
                                  />
                                  <span>{item.name}</span>
                                </div>
                                <span className="text-[10px] font-mono font-bold text-slate-300">
                                  {item.percentage}%
                                </span>
                              </div>
                              <div className="text-[11px] text-slate-300 leading-tight">
                                {item.description}
                              </div>
                              <div className="flex items-center justify-between text-[10px] font-mono pt-1 text-slate-400">
                                <span>Total : <strong className="text-white">{item.count}</strong></span>
                                {item.criticalCount > 0 && (
                                  <span className="text-rose-400 font-bold">
                                    {item.criticalCount} Critique(s)
                                  </span>
                                )}
                                <span className="text-emerald-400">
                                  {item.activeCount} Active(s)
                                </span>
                              </div>
                            </div>
                          );
                        }
                        return null;
                      }}
                    />
                    <Pie
                      data={chartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={65}
                      outerRadius={92}
                      paddingAngle={4}
                      dataKey="count"
                      nameKey="name"
                      onClick={(entry: any) => {
                        const targetKey = String(entry?.key || '');
                        if (targetKey) {
                          onSelectCategory(targetKey === selectedCategory ? 'ALL' : targetKey);
                        }
                      }}
                      onMouseEnter={(_, index) => setHoveredIndex(index)}
                      onMouseLeave={() => setHoveredIndex(null)}
                      animationDuration={600}
                    >
                      {chartData.map((entry, index) => {
                        const isSelected = selectedCategory === entry.key;
                        const isHovered = hoveredIndex === index;
                        const isDimmed =
                          (selectedCategory !== 'ALL' && !isSelected) ||
                          (hoveredIndex !== null && !isHovered);

                        return (
                          <Cell
                            key={`donut-slice-${entry.key}`}
                            fill={entry.color}
                            stroke={isSelected || isHovered ? '#ffffff' : '#0f172a'}
                            strokeWidth={isSelected || isHovered ? 2.5 : 2}
                            opacity={isDimmed ? 0.4 : 1}
                            style={{
                              outline: 'none',
                              transition: 'all 0.25s ease',
                              filter: isSelected || isHovered ? `drop-shadow(0 0 8px ${entry.color}80)` : 'none',
                            }}
                          />
                        );
                      })}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>

                {/* Donut Center Display */}
                <div 
                  className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center select-none"
                  style={{ transform: 'translateY(-2px)' }}
                >
                  <span className="text-2xl font-black font-mono tracking-tight leading-none text-white drop-shadow">
                    {currentFocalData ? currentFocalData.count : totalThreats}
                  </span>
                  <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 mt-1 max-w-[90px] truncate">
                    {currentFocalData ? currentFocalData.shortLabel : 'Menaces'}
                  </span>
                  <span className="text-[9px] font-mono text-cyan-400 font-semibold leading-none mt-0.5">
                    {currentFocalData ? `${currentFocalData.percentage}%` : '100%'}
                  </span>
                </div>
              </>
            )}
          </div>

          <div className="text-[10px] text-slate-500 font-mono text-center mt-1">
            {selectedCategory === 'ALL'
              ? 'Cliquez sur un segment ou une carte pour filtrer'
              : `Filtre actif : ${selectedCategory} (cliquez pour désactiver)`}
          </div>
        </div>

        {/* Right Col: Category Legend & Metric Cards Grid (7 Cols) */}
        <div className="lg:col-span-7 space-y-2.5">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {chartData.map((item, index) => {
              const Icon = item.icon;
              const isSelected = selectedCategory === item.key;
              const isHovered = hoveredIndex === index;

              return (
                <div
                  key={item.key}
                  onClick={() => onSelectCategory(isSelected ? 'ALL' : item.key)}
                  onMouseEnter={() => setHoveredIndex(index)}
                  onMouseLeave={() => setHoveredIndex(null)}
                  className={`p-3 rounded-xl border transition-all cursor-pointer flex flex-col justify-between ${
                    isSelected
                      ? 'bg-slate-900 border-cyan-500 shadow-md shadow-cyan-950/40 ring-1 ring-cyan-500/50'
                      : isHovered
                      ? `${item.bgClass} ${item.borderClass} shadow-md`
                      : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <div
                        className="w-2.5 h-2.5 rounded-full shrink-0"
                        style={{ backgroundColor: item.color }}
                      />
                      <Icon className={`w-3.5 h-3.5 ${item.textClass} shrink-0`} />
                      <span className="text-xs font-bold text-slate-100 truncate">
                        {item.name}
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className="text-xs font-mono font-bold text-white">
                        {item.count}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">
                        ({item.percentage}%)
                      </span>
                    </div>
                  </div>

                  {/* Progress proportion bar */}
                  <div className="w-full h-1 bg-slate-800 rounded-full overflow-hidden mt-2">
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${item.percentage}%`,
                        backgroundColor: item.color,
                      }}
                    />
                  </div>

                  {/* Badges footer */}
                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mt-2">
                    <span className="truncate max-w-[130px] text-slate-400 text-[10px]" title={item.description}>
                      {item.description}
                    </span>
                    <div className="flex items-center gap-1 shrink-0">
                      {item.criticalCount > 0 && (
                        <span className="px-1.5 py-0.2 rounded bg-rose-950/80 text-rose-400 border border-rose-800/60 font-semibold text-[9px]">
                          {item.criticalCount} Crit.
                        </span>
                      )}
                      {item.activeCount > 0 && (
                        <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 text-[9px]">
                          {item.activeCount} Actif
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Bottom Insights Strip */}
          {dominantCategory && (
            <div className="p-2.5 bg-slate-950/90 border border-slate-800/80 rounded-xl flex items-center justify-between text-xs text-slate-300">
              <div className="flex items-center gap-2">
                <span className="text-amber-400 font-mono text-[11px] font-bold">Vecteur Principal :</span>
                <span className="text-white font-semibold">{dominantCategory.name}</span>
                <span className="text-slate-400 text-[11px]">
                  ({dominantCategory.count} menaces sur {totalThreats}, soit {dominantCategory.percentage}%)
                </span>
              </div>
              <div className="text-[11px] font-mono text-slate-400 hidden sm:block">
                Intervention prioritaire recommandée
              </div>
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
