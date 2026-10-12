import React, { useState } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Flame,
  Radio,
  Terminal,
  X,
  ChevronRight,
  ShieldCheck,
  BellRing,
  Layers,
  Pause,
  Play,
  RotateCcw,
  Sparkles,
} from 'lucide-react';
import { TabId, ThreatNotification } from '../types/cyberdefense';

interface ThreatToastContainerProps {
  toasts: ThreatNotification[];
  onDismiss: (id: string) => void;
  onClearAll: () => void;
  onNavigateTab: (tab: TabId) => void;
  onRunInConsole: (command: string) => void;
  isSimulationActive: boolean;
  onToggleSimulation: () => void;
  onTriggerTestThreat: () => void;
}

export const ThreatToastContainer: React.FC<ThreatToastContainerProps> = ({
  toasts,
  onDismiss,
  onClearAll,
  onNavigateTab,
  onRunInConsole,
  isSimulationActive,
  onToggleSimulation,
  onTriggerTestThreat,
}) => {
  const [isExpandedTray, setIsExpandedTray] = useState(false);
  const [isAudioMuted, setIsAudioMuted] = useState(false);

  // Play subtle futuristic beep using Web Audio API on toast creation
  const playAlertSound = (severity: ThreatNotification['severity']) => {
    if (isAudioMuted) return;
    try {
      const audioCtx = new (window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext)();
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      
      const freq = severity === 'CRITICAL' ? 880 : severity === 'HIGH' ? 660 : 440;
      osc.type = severity === 'CRITICAL' ? 'sawtooth' : 'sine';
      osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(severity === 'CRITICAL' ? 440 : 220, audioCtx.currentTime + 0.18);
      
      gain.gain.setValueAtTime(0.04, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.2);
      
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.22);
    } catch {
      // AudioContext may be restricted before user gesture
    }
  };

  // Severity styles configuration
  const getSeverityBadge = (severity: ThreatNotification['severity']) => {
    switch (severity) {
      case 'CRITICAL':
        return {
          border: 'border-rose-500/50 shadow-rose-950/40',
          bg: 'bg-rose-950/70',
          accent: 'text-rose-400',
          indicator: 'bg-rose-500 shadow-[0_0_12px_rgba(244,63,94,0.8)]',
          badge: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
          icon: ShieldAlert,
        };
      case 'HIGH':
        return {
          border: 'border-amber-500/50 shadow-amber-950/30',
          bg: 'bg-amber-950/60',
          accent: 'text-amber-400',
          indicator: 'bg-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.8)]',
          badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
          icon: AlertTriangle,
        };
      case 'MEDIUM':
        return {
          border: 'border-yellow-500/40 shadow-yellow-950/20',
          bg: 'bg-yellow-950/40',
          accent: 'text-yellow-400',
          indicator: 'bg-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.7)]',
          badge: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
          icon: Flame,
        };
      default:
        return {
          border: 'border-cyan-500/40 shadow-cyan-950/20',
          bg: 'bg-cyan-950/40',
          accent: 'text-cyan-400',
          indicator: 'bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.7)]',
          badge: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
          icon: Radio,
        };
    }
  };

  // Top visible toasts (up to 3 in the non-intrusive floating stack)
  const visibleToasts = toasts.slice(0, 3);
  const hiddenCount = Math.max(0, toasts.length - 3);

  return (
    <aside
      aria-label="Threat notifications toast system"
      className="fixed bottom-5 right-5 z-50 flex flex-col items-end pointer-events-none max-w-sm sm:max-w-md w-full select-none"
    >
      {/* Toast Controls Bar (Compact HUD Trigger & Simulation Toggle) */}
      <div className="pointer-events-auto mb-2 flex items-center gap-1.5 bg-slate-900/90 backdrop-blur-md border border-slate-800 text-xs text-slate-300 px-3 py-1.5 rounded-lg shadow-xl shadow-black/60 transition-all hover:border-slate-700">
        <div className="flex items-center gap-2 pr-2 border-r border-slate-800">
          <span className="relative flex h-2 w-2">
            <span
              className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                isSimulationActive ? 'bg-rose-400' : 'bg-slate-500'
              }`}
            />
            <span
              className={`relative inline-flex rounded-full h-2 w-2 ${
                isSimulationActive ? 'bg-rose-500' : 'bg-slate-600'
              }`}
            />
          </span>
          <span className="text-[11px] font-semibold tracking-wider uppercase text-slate-300">
            Threat Sentinel
          </span>
          {toasts.length > 0 && (
            <span className="bg-rose-500/20 text-rose-300 border border-rose-500/30 px-1.5 py-0.2 rounded text-[10px] font-mono font-bold">
              {toasts.length}
            </span>
          )}
        </div>

        {/* Action icons */}
        <button
          onClick={onTriggerTestThreat}
          title="Simuler une alerte de menace immédiate"
          className="p-1 hover:text-cyan-400 text-slate-400 transition-colors rounded hover:bg-slate-800/80 flex items-center gap-1 text-[11px]"
        >
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          <span className="hidden sm:inline">Simuler</span>
        </button>

        <button
          onClick={onToggleSimulation}
          title={isSimulationActive ? 'Mettre en pause la détection continue' : 'Activer le flux de détection continue'}
          className={`p-1 transition-colors rounded hover:bg-slate-800/80 flex items-center gap-1 text-[11px] ${
            isSimulationActive ? 'text-amber-400' : 'text-slate-400'
          }`}
        >
          {isSimulationActive ? (
            <>
              <Pause className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Pause</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Actif</span>
            </>
          )}
        </button>

        {toasts.length > 0 && (
          <>
            <button
              onClick={() => setIsExpandedTray(!isExpandedTray)}
              title={isExpandedTray ? 'Masquer le panneau' : 'Voir tout le journal des alertes'}
              className="p-1 text-slate-400 hover:text-white transition-colors rounded hover:bg-slate-800/80 flex items-center gap-1 text-[11px]"
            >
              <Layers className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{isExpandedTray ? 'Réduire' : 'Historique'}</span>
            </button>

            <button
              onClick={onClearAll}
              title="Acquitter et effacer toutes les alertes"
              className="p-1 text-slate-400 hover:text-rose-400 transition-colors rounded hover:bg-slate-800/80"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </>
        )}
      </div>

      {/* Expanded Tray / Drawer when user clicks to see all past notifications */}
      {isExpandedTray && toasts.length > 0 && (
        <div className="pointer-events-auto mb-3 w-full max-h-80 overflow-y-auto bg-slate-950/95 backdrop-blur-xl border border-slate-800 rounded-xl p-3 shadow-2xl space-y-2.5">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800 text-xs">
            <span className="font-semibold text-white flex items-center gap-1.5">
              <BellRing className="w-3.5 h-3.5 text-cyan-400" />
              Journal des Menaces Récentes ({toasts.length})
            </span>
            <button
              onClick={onClearAll}
              className="text-[11px] text-rose-400 hover:text-rose-300 transition-colors"
            >
              Tout effacer
            </button>
          </div>
          {toasts.map(toast => {
            const style = getSeverityBadge(toast.severity);
            const Icon = style.icon;
            return (
              <div
                key={toast.id}
                className="bg-slate-900/80 border border-slate-800 rounded-lg p-2.5 text-xs hover:border-slate-700 transition-all flex flex-col gap-1.5"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <Icon className={`w-3.5 h-3.5 ${style.accent}`} />
                    <span className="font-semibold text-slate-200">{toast.title}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-slate-400 font-mono">{toast.timestamp}</span>
                    <button
                      onClick={() => onDismiss(toast.id)}
                      className="text-slate-400 hover:text-slate-200"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed font-sans">{toast.description}</p>
                <div className="flex items-center justify-between pt-1">
                  <span className={`text-[9px] uppercase px-1.5 py-0.5 rounded border font-mono ${style.badge}`}>
                    {toast.severity} · {toast.category}
                  </span>
                  <div className="flex items-center gap-2">
                    {toast.actionCommand && (
                      <button
                        onClick={() => {
                          onRunInConsole(toast.actionCommand!);
                          onDismiss(toast.id);
                        }}
                        className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono hover:underline"
                      >
                        <Terminal className="w-3 h-3" />
                        {toast.actionLabel || 'Neutraliser'}
                      </button>
                    )}
                    {toast.targetTab && (
                      <button
                        onClick={() => {
                          onNavigateTab(toast.targetTab!);
                          onDismiss(toast.id);
                        }}
                        className="text-[10px] text-slate-300 hover:text-white flex items-center gap-0.5 hover:underline"
                      >
                        Inspecter <ChevronRight className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Floating Active Non-Intrusive Toasts (Stack in Bottom-Right) */}
      <div className="w-full flex flex-col gap-2.5">
        {visibleToasts.map((toast, index) => {
          const style = getSeverityBadge(toast.severity);
          const Icon = style.icon;

          return (
            <div
              key={toast.id}
              role="alert"
              aria-live="assertive"
              className={`pointer-events-auto transform transition-all duration-300 ease-out translate-y-0 opacity-100 backdrop-blur-xl border ${style.border} ${style.bg} bg-slate-950/90 rounded-xl p-3.5 shadow-2xl relative overflow-hidden group`}
              style={{
                // Subtle staggered scale effect for stacked feel
                transform: `scale(${1 - index * 0.02}) translateY(-${index * 2}px)`,
              }}
            >
              {/* Left pulsing severity indicator strip */}
              <div
                className={`absolute left-0 top-0 bottom-0 w-1 ${style.indicator}`}
              />

              {/* Header row */}
              <div className="flex items-start justify-between gap-2 pl-1.5">
                <div className="flex items-center gap-2 min-w-0">
                  <div className={`p-1.5 rounded-lg bg-slate-900/90 border border-slate-800 ${style.accent}`}>
                    <Icon className="w-4 h-4 animate-pulse" />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className={`text-[10px] font-mono font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${style.badge}`}>
                        {toast.severity}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">
                        {toast.category}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">
                        · {toast.timestamp}
                      </span>
                    </div>
                    <h4 className="text-xs font-bold text-white tracking-tight truncate mt-0.5">
                      {toast.title}
                    </h4>
                  </div>
                </div>

                {/* Close Button */}
                <button
                  onClick={() => onDismiss(toast.id)}
                  aria-label="Fermer la notification"
                  className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors flex-shrink-0"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>

              {/* Body description */}
              <div className="pl-1.5 mt-2">
                <p className="text-xs text-slate-300 font-sans leading-relaxed line-clamp-2">
                  {toast.description}
                </p>
                <div className="flex items-center gap-2 mt-1 text-[11px] font-mono text-slate-400 truncate">
                  <span className="text-slate-400">Source:</span>
                  <span className="text-slate-300 font-medium truncate">{toast.source}</span>
                </div>
              </div>

              {/* Action Toolbar */}
              <div className="pl-1.5 mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between gap-2">
                {toast.actionCommand ? (
                  <button
                    onClick={() => {
                      onRunInConsole(toast.actionCommand!);
                      onDismiss(toast.id);
                    }}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/40 text-rose-300 hover:text-rose-200 text-xs font-mono font-medium transition-all"
                  >
                    <Terminal className="w-3 h-3" />
                    <span>{toast.actionLabel || 'Neutraliser'}</span>
                  </button>
                ) : (
                  <div className="flex items-center gap-1 text-[11px] text-emerald-400 font-mono">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Surveillance active</span>
                  </div>
                )}

                {toast.targetTab && (
                  <button
                    onClick={() => {
                      onNavigateTab(toast.targetTab!);
                      onDismiss(toast.id);
                    }}
                    className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-medium transition-colors hover:underline"
                  >
                    <span>Inspecter</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>
          );
        })}

        {/* Indicator if more than 3 threats exist */}
        {hiddenCount > 0 && (
          <button
            onClick={() => setIsExpandedTray(true)}
            className="pointer-events-auto self-end text-[11px] font-mono text-slate-400 hover:text-cyan-300 bg-slate-900/90 border border-slate-800 px-2.5 py-1 rounded-md shadow-lg transition-colors flex items-center gap-1"
          >
            <span>+{hiddenCount} autre(s) menace(s) en attente</span>
            <ChevronRight className="w-3 h-3" />
          </button>
        )}
      </div>
    </aside>
  );
};
