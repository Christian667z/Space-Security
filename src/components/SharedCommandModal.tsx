import React, { useState } from 'react';
import {
  Terminal,
  Play,
  X,
  Zap,
  CheckCircle2,
  Copy,
  Check,
  Shield,
  Layers,
  Sparkles,
  Info,
  Code2,
} from 'lucide-react';
import { ThreatItem, SharedCommandPreset } from '../types/cyberdefense';

interface SharedCommandModalProps {
  isOpen: boolean;
  onClose: () => void;
  selectedThreats: ThreatItem[];
  onExecuteSharedCommand: (commandTemplate: string, threats: ThreatItem[]) => void;
}

const PRESET_COMMANDS: SharedCommandPreset[] = [
  {
    id: 'takeown-acl',
    label: 'Appropriation ACL & Déverrouillage Total',
    description: 'Prend la possession depuis TrustedInstaller et accorde le Contrôle Total aux Administrateurs',
    commandTemplate: 'takeown.exe /F "{path}" /A && icacls.exe "{path}" /grant *S-1-5-32-544:F /c /q',
    category: 'KERNEL',
  },
  {
    id: 'pending-delete',
    label: 'Programmation Destruction au Boot Noyau',
    description: 'Enregistre le chemin dans PendingFileRenameOperations et écrase le binaire à 0 octet',
    commandTemplate: 'unlock "{path}"',
    category: 'KERNEL',
  },
  {
    id: 'sha256-hash',
    label: 'Calcul d\'Empreinte Forensique SHA-256',
    description: 'Génère le hash cryptographique pour comparaison aux bases VirusTotal / Threat Intel',
    commandTemplate: 'Get-FileHash -Algorithm SHA256 -Path "{path}" | Select-Object -Property Hash, Path',
    category: 'FORENSICS',
  },
  {
    id: 'reset-attributes',
    label: 'Suppression Attributs Masqué / Système / ReadOnly',
    description: 'Réinitialise les drapeaux de protection de fichiers NTFS pour permettre l\'analyse',
    commandTemplate: 'Set-ItemProperty -Path "{path}" -Name Attributes -Value Normal -ErrorAction SilentlyContinue',
    category: 'FORENSICS',
  },
  {
    id: 'kill-process',
    label: 'Abattage Forcé de Processus Associé (taskkill /F /T)',
    description: 'Tue le processus verrouillant et son arbre d\'exécution complet',
    commandTemplate: 'Stop-Process -Force -ProcessName "{name}" -ErrorAction SilentlyContinue',
    category: 'PROCESS',
  },
];

export const SharedCommandModal: React.FC<SharedCommandModalProps> = ({
  isOpen,
  onClose,
  selectedThreats,
  onExecuteSharedCommand,
}) => {
  const [selectedPresetId, setSelectedPresetId] = useState<string>('pending-delete');
  const [customTemplate, setCustomTemplate] = useState<string>('unlock "{path}"');
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [isExecuting, setIsExecuting] = useState<boolean>(false);

  if (!isOpen) return null;

  const handleSelectPreset = (preset: SharedCommandPreset) => {
    setSelectedPresetId(preset.id);
    setCustomTemplate(preset.commandTemplate);
  };

  const handleInsertToken = (token: string) => {
    setCustomTemplate(prev => prev + ` {${token}}`);
  };

  const handleRun = () => {
    setIsExecuting(true);
    onExecuteSharedCommand(customTemplate, selectedThreats);
    setTimeout(() => {
      setIsExecuting(false);
      onClose();
    }, 600);
  };

  const getInstantiatedCommand = (threat: ThreatItem, template: string) => {
    const fileName = threat.targetPath.split('\\').pop() || threat.name;
    const baseName = fileName.replace(/\.[^/.]+$/, '');
    return template
      .replace(/{path}/g, threat.targetPath)
      .replace(/{name}/g, baseName)
      .replace(/{id}/g, threat.id)
      .replace(/{category}/g, threat.category);
  };

  const handleCopyCommand = (cmd: string, idx: number) => {
    navigator.clipboard.writeText(cmd);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 1800);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-3xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-6 border-b border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-950/80 border border-cyan-800/80 text-cyan-400">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-white tracking-tight">
                  Exécuter une Commande Partagée
                </h2>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                  {selectedThreats.length} Cible{selectedThreats.length > 1 ? 's' : ''}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Applique un modèle de commande unifié sur l'ensemble des menaces sélectionnées avec interpolation des chemins.
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 custom-scrollbar">
          {/* Target List Summary */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                Cibles sélectionnées ({selectedThreats.length})
              </span>
              <span className="text-[11px] text-slate-400 font-mono">
                Variables disponibles : <code className="text-cyan-300">{'{path}'}</code>, <code className="text-cyan-300">{'{name}'}</code>, <code className="text-cyan-300">{'{category}'}</code>
              </span>
            </label>
            <div className="flex flex-wrap gap-2 max-h-24 overflow-y-auto p-2.5 bg-slate-950/80 rounded-xl border border-slate-800">
              {selectedThreats.map(t => (
                <div
                  key={t.id}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 font-mono"
                >
                  <span className="w-2 h-2 rounded-full bg-rose-400 shrink-0" />
                  <span className="font-semibold text-slate-100">{t.name}</span>
                  <span className="text-slate-400 text-[10px]">({t.id})</span>
                </div>
              ))}
            </div>
          </div>

          {/* Preset Buttons */}
          <div className="space-y-2.5">
            <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-amber-400" />
              Sélectionner un Modèle Prédéfini
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              {PRESET_COMMANDS.map(preset => {
                const isSelected = selectedPresetId === preset.id;
                return (
                  <button
                    key={preset.id}
                    onClick={() => handleSelectPreset(preset)}
                    className={`p-3 rounded-xl text-left transition-all border ${
                      isSelected
                        ? 'bg-cyan-950/60 border-cyan-500 shadow-md shadow-cyan-950/50 ring-1 ring-cyan-500/40'
                        : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 hover:bg-slate-950'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs font-bold">
                      <span className={isSelected ? 'text-cyan-300' : 'text-slate-200'}>
                        {preset.label}
                      </span>
                      <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-slate-800 text-slate-400">
                        {preset.category}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                      {preset.description}
                    </p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Command Template Input */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <Code2 className="w-3.5 h-3.5 text-cyan-400" />
                Modèle de Commande (Interpolé pour chaque cible)
              </label>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => handleInsertToken('path')}
                  className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700"
                >
                  + {'{path}'}
                </button>
                <button
                  type="button"
                  onClick={() => handleInsertToken('name')}
                  className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700"
                >
                  + {'{name}'}
                </button>
              </div>
            </div>

            <textarea
              rows={2}
              value={customTemplate}
              onChange={e => {
                setCustomTemplate(e.target.value);
                setSelectedPresetId('custom');
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/50"
              placeholder="ex: unlock &quot;{path}&quot; ou Stop-Process -Name &quot;{name}&quot;"
            />
          </div>

          {/* Live Preview of Instantiated Commands */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-emerald-400" />
              Aperçu des Commandes Générées ({selectedThreats.length})
            </label>

            <div className="space-y-2 max-h-48 overflow-y-auto p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono text-[11px]">
              {selectedThreats.map((threat, idx) => {
                const cmd = getInstantiatedCommand(threat, customTemplate);
                return (
                  <div
                    key={threat.id}
                    className="flex items-center justify-between gap-3 p-2 rounded-lg bg-slate-900/90 border border-slate-800/80 hover:border-slate-700 group"
                  >
                    <div className="truncate flex-1">
                      <span className="text-slate-500 mr-2">[{idx + 1}]</span>
                      <span className="text-emerald-400 font-bold">&gt; </span>
                      <span className="text-slate-200 select-all">{cmd}</span>
                    </div>

                    <button
                      onClick={() => handleCopyCommand(cmd, idx)}
                      className="text-slate-400 hover:text-cyan-300 p-1 rounded hover:bg-slate-800 shrink-0 transition-colors"
                      title="Copier la commande"
                    >
                      {copiedIndex === idx ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="p-4 bg-slate-950 border-t border-slate-800 flex items-center justify-between">
          <div className="text-xs text-slate-400 flex items-center gap-1.5">
            <Info className="w-3.5 h-3.5 text-cyan-400" />
            <span>Exécution séquentielle retransmise en direct dans le terminal et synchronisée multi-utilisateurs.</span>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              Annuler
            </button>
            <button
              onClick={handleRun}
              disabled={isExecuting || !customTemplate.trim()}
              className="px-5 py-2 rounded-xl text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 shadow-md shadow-cyan-950 flex items-center gap-2 transition-all disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{isExecuting ? 'Exécution en cours...' : `Exécuter pour les ${selectedThreats.length} menaces`}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
