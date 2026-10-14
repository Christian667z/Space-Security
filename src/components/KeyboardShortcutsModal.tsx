import React, { useState, useEffect } from 'react';
import {
  Keyboard,
  X,
  Play,
  CheckCircle2,
  Terminal,
  Shield,
  FileText,
  Trash2,
  Flame,
  ArrowRight,
  Info,
  Sparkles,
  Command,
} from 'lucide-react';
import { ShortcutDefinition } from '../hooks/useKeyboardShortcuts';

interface KeyboardShortcutsModalProps {
  isOpen: boolean;
  onClose: () => void;
  shortcuts: ShortcutDefinition[];
  onTriggerShortcut: (id: string) => void;
  lastExecutedShortcut: {
    id: string;
    label: string;
    combo: string;
    timestamp: number;
  } | null;
}

export const KeyboardShortcutsModal: React.FC<KeyboardShortcutsModalProps> = ({
  isOpen,
  onClose,
  shortcuts,
  onTriggerShortcut,
  lastExecutedShortcut,
}) => {
  const [pressedKeys, setPressedKeys] = useState<string[]>([]);
  const [testedAction, setTestedAction] = useState<string | null>(null);

  // Keyboard live key tester within modal
  useEffect(() => {
    if (!isOpen) return;

    const handleTestKeyDown = (e: KeyboardEvent) => {
      // Don't intercept Escape or F1 if closing modal
      if (e.key === 'Escape') return;

      const keys: string[] = [];
      if (e.ctrlKey) keys.push('Ctrl');
      if (e.metaKey) keys.push('Cmd');
      if (e.altKey) keys.push('Alt');
      if (e.shiftKey) keys.push('Shift');
      
      const mainKey = e.key.toUpperCase();
      if (!['CONTROL', 'ALT', 'SHIFT', 'META'].includes(mainKey)) {
        keys.push(mainKey);
      }

      setPressedKeys(keys);

      // Check if matches any registered shortcut
      const keyComboString = keys.join(' + ');
      const match = shortcuts.find((s) =>
        s.keyCombo.toUpperCase().includes(keys.join('+')) ||
        (keys.length === 1 && s.keyCombo.toUpperCase().includes(keys[0]))
      );

      if (match) {
        setTestedAction(`Correspondance détectée : ${match.label}`);
      } else {
        setTestedAction(null);
      }
    };

    const handleTestKeyUp = () => {
      // Keep keys briefly for visual feedback
      const timer = setTimeout(() => {
        setPressedKeys([]);
        setTestedAction(null);
      }, 1200);
      return () => clearTimeout(timer);
    };

    window.addEventListener('keydown', handleTestKeyDown);
    window.addEventListener('keyup', handleTestKeyUp);
    return () => {
      window.removeEventListener('keydown', handleTestKeyDown);
      window.removeEventListener('keyup', handleTestKeyUp);
    };
  }, [isOpen, shortcuts]);

  if (!isOpen) return null;

  const coreActions = shortcuts.filter((s) => s.category === 'CORE_ACTIONS');
  const navigationActions = shortcuts.filter((s) => s.category === 'NAVIGATION');
  const systemActions = shortcuts.filter((s) => s.category === 'SYSTEM');

  const renderKeyPill = (keyCombo: string) => {
    // Splits by "ou" to display multiple combinations cleanly
    const variants = keyCombo.split(' ou ');
    return (
      <div className="flex flex-wrap items-center gap-1.5">
        {variants.map((v, idx) => (
          <React.Fragment key={idx}>
            {idx > 0 && <span className="text-[10px] text-slate-500 font-mono">ou</span>}
            <kbd className="px-2 py-1 rounded bg-slate-800 border border-slate-700 text-cyan-300 font-mono text-[11px] font-bold shadow-xs">
              {v.trim()}
            </kbd>
          </React.Fragment>
        ))}
      </div>
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-slate-950/80 backdrop-blur-md animate-in fade-in duration-200">
      <div
        className="relative w-full max-w-4xl max-h-[90vh] bg-slate-900 border border-cyan-500/30 rounded-2xl shadow-2xl shadow-cyan-950/40 flex flex-col overflow-hidden text-slate-100"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-950/80 border border-cyan-800/80 text-cyan-400 shadow-inner">
              <Keyboard className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-white tracking-wide">
                  Gestionnaire de Raccourcis Clavier
                </h2>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800/80">
                  GLOBAL 'KEYDOWN' LISTENER
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Exécutez instantanément les opérations défensives sans passer par la console terminal.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
            title="Fermer (Échap)"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Shortcut Cards Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Quick HUD for Last Executed Shortcut */}
          {lastExecutedShortcut && (
            <div className="flex items-center justify-between p-3.5 bg-gradient-to-r from-cyan-950/60 to-slate-900 border border-cyan-500/40 rounded-xl">
              <div className="flex items-center gap-2.5">
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                <div className="text-xs">
                  <span className="text-slate-400">Dernier raccourci exécuté : </span>
                  <span className="text-white font-bold">{lastExecutedShortcut.label}</span>
                  <span className="ml-2 font-mono text-cyan-300">({lastExecutedShortcut.combo})</span>
                </div>
              </div>
              <span className="text-[10px] text-slate-500 font-mono">
                {new Date(lastExecutedShortcut.timestamp).toLocaleTimeString('fr-FR')}
              </span>
            </div>
          )}

          {/* Interactive Live Keyboard Tester Box */}
          <div className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-slate-300 flex items-center gap-2">
                <Command className="w-3.5 h-3.5 text-cyan-400" />
                <span>Testeur de Touches en Direct :</span>
              </span>
              <span className="text-[11px] text-slate-500">
                Appuyez sur une combinaison (ex: <kbd className="font-mono text-cyan-400">Alt + S</kbd>)
              </span>
            </div>
            <div className="min-h-11 flex items-center justify-between px-3.5 py-2 bg-slate-900/90 border border-slate-800 rounded-lg">
              <div className="flex items-center gap-2">
                {pressedKeys.length > 0 ? (
                  pressedKeys.map((k, i) => (
                    <span
                      key={i}
                      className="px-2 py-1 rounded bg-cyan-950 text-cyan-300 border border-cyan-700 font-mono text-xs font-bold animate-pulse"
                    >
                      {k}
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-slate-500 font-mono italic">
                    En attente d'une frappe clavier...
                  </span>
                )}
              </div>
              {testedAction && (
                <span className="text-xs text-emerald-400 font-medium font-mono flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>{testedAction}</span>
                </span>
              )}
            </div>
          </div>

          {/* SECTION 1: CORE ACTIONS */}
          <div className="space-y-3">
            <div className="flex items-center justify-between pb-1 border-b border-slate-800">
              <h3 className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-2">
                <Flame className="w-4 h-4 text-cyan-400" />
                <span>Actions Défensives & Télémétrie</span>
              </h3>
              <span className="text-[11px] text-slate-500 font-mono">
                Commandes prioritaires directes
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {coreActions.map((shortcut) => (
                <div
                  key={shortcut.id}
                  className="p-3.5 bg-slate-950/60 hover:bg-slate-950 border border-slate-800/90 hover:border-cyan-500/50 rounded-xl transition-all flex flex-col justify-between gap-3 group"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-white group-hover:text-cyan-300 transition-colors">
                          {shortcut.label}
                        </span>
                        {shortcut.actionCommand && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono text-slate-400 bg-slate-900 border border-slate-800">
                            {shortcut.actionCommand}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        {shortcut.description}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
                    {renderKeyPill(shortcut.keyCombo)}
                    <button
                      onClick={() => onTriggerShortcut(shortcut.id)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-600 text-slate-200 hover:text-white text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                      title="Exécuter maintenant"
                    >
                      <Play className="w-3 h-3" />
                      <span>Exécuter</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* SECTION 2: FAST NAVIGATION */}
          <div className="space-y-3">
            <div className="flex items-center justify-between pb-1 border-b border-slate-800">
              <h3 className="text-xs font-mono font-bold text-indigo-400 uppercase tracking-wider flex items-center gap-2">
                <ArrowRight className="w-4 h-4 text-indigo-400" />
                <span>Navigation & Accès Rapide aux Modules</span>
              </h3>
              <span className="text-[11px] text-slate-500 font-mono">
                Bascule d'onglet immédiate
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              {navigationActions.map((shortcut) => (
                <div
                  key={shortcut.id}
                  className="p-3 bg-slate-950/60 hover:bg-slate-950 border border-slate-800/80 hover:border-indigo-500/50 rounded-xl transition-all flex items-center justify-between gap-3 group"
                >
                  <div className="min-w-0">
                    <div className="text-xs font-bold text-white group-hover:text-indigo-300 truncate">
                      {shortcut.label}
                    </div>
                    <div className="text-[11px] text-slate-400 truncate">
                      {shortcut.description}
                    </div>
                  </div>
                  <kbd className="px-2 py-1 rounded bg-slate-800 border border-slate-700 text-indigo-300 font-mono text-[11px] font-bold shrink-0">
                    {shortcut.keyCombo}
                  </kbd>
                </div>
              ))}
            </div>
          </div>

          {/* SECTION 3: SYSTEM & CONTROL */}
          <div className="space-y-3">
            <div className="flex items-center justify-between pb-1 border-b border-slate-800">
              <h3 className="text-xs font-mono font-bold text-rose-400 uppercase tracking-wider flex items-center gap-2">
                <Shield className="w-4 h-4 text-rose-400" />
                <span>Sécurité, Confinement & Contrôles Généraux</span>
              </h3>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {systemActions.map((shortcut) => (
                <div
                  key={shortcut.id}
                  className="p-3 bg-slate-950/60 hover:bg-slate-950 border border-slate-800/80 hover:border-rose-500/50 rounded-xl transition-all flex items-center justify-between gap-3 group"
                >
                  <div>
                    <div className="text-xs font-bold text-white group-hover:text-rose-300">
                      {shortcut.label}
                    </div>
                    <div className="text-[11px] text-slate-400">
                      {shortcut.description}
                    </div>
                  </div>
                  <kbd className="px-2 py-1 rounded bg-slate-800 border border-slate-700 text-rose-300 font-mono text-[11px] font-bold shrink-0">
                    {shortcut.keyCombo}
                  </kbd>
                </div>
              ))}

              <div className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-xl flex items-center justify-between gap-3">
                <div>
                  <div className="text-xs font-bold text-white">
                    Fermer les Fenêtres / Modales
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Ferme toute fenêtre ouverte ou annule la saisie.
                  </div>
                </div>
                <kbd className="px-2 py-1 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono text-[11px] font-bold shrink-0">
                  Échap (Esc)
                </kbd>
              </div>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-6 py-4 border-t border-slate-800 bg-slate-950/60 text-xs text-slate-400 font-mono">
          <div className="flex items-center gap-2">
            <Info className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>
              Les raccourcis <kbd className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300">Alt</kbd> fonctionnent partout, même pendant la saisie.
            </span>
          </div>

          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white font-medium rounded-lg text-xs transition-colors self-end sm:self-auto cursor-pointer"
          >
            Fermer l'Aide
          </button>
        </div>
      </div>
    </div>
  );
};
