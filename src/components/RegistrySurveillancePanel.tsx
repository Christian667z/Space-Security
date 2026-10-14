import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  FileText,
  AlertTriangle,
  CheckCircle2,
  Trash2,
  Copy,
  Check,
  RotateCcw,
  ShieldAlert,
  Search,
  Terminal,
  Zap,
  Lock,
  Layers,
  ArrowRight,
  Filter
} from 'lucide-react';
import { RegistryPersistenceItem } from '../types/cyberdefense';
import { apiFetch } from '../utils/api';

interface RegistrySurveillancePanelProps {
  onRunInConsole?: (command: string) => void;
  onAddLog?: (level: 'OK' | 'INFO' | 'WARN' | 'ERROR' | 'KERNEL', text: string, tag?: string) => void;
}

export const RegistrySurveillancePanel: React.FC<RegistrySurveillancePanelProps> = ({
  onRunInConsole,
  onAddLog,
}) => {
  const [items, setItems] = useState<RegistryPersistenceItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [activeCategory, setActiveCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [lastScanTime, setLastScanTime] = useState<string>('');

  const fetchRegistryPersistence = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await apiFetch('/api/system/registry/persistence');
      if (res.ok) {
        const data = await res.json();
        if (data.success && Array.isArray(data.items)) {
          setItems(data.items);
          setLastScanTime(data.timestamp || new Date().toLocaleTimeString('fr-FR'));

          const suspiciousCount = data.items.filter((i: RegistryPersistenceItem) => i.status === 'SUSPICIOUS').length;
          if (suspiciousCount > 0) {
            onAddLog?.(
              'ERROR',
              `[REGISTRE-SURVEILLANCE] ${suspiciousCount} clé(s) de persistance suspecte(s) détectée(s) dans le Registre Windows !`,
              'REGISTRY'
            );
          }
        }
      }
    } catch (e) {
      console.error('Error fetching registry persistence:', e);
    } finally {
      setIsLoading(false);
    }
  }, [onAddLog]);

  useEffect(() => {
    fetchRegistryPersistence();
  }, [fetchRegistryPersistence]);

  const handleDeleteKey = async (item: RegistryPersistenceItem) => {
    try {
      const res = await apiFetch('/api/system/registry/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: item.id, keyPath: item.keyPath, entryName: item.entryName }),
      });

      if (res.ok) {
        setItems(prev => prev.filter(i => i.id !== item.id));
        onAddLog?.(
          'OK',
          `[REGISTRE-SUPPRESSION] Clé de persistance suspecte éliminée : ${item.entryName} (${item.keyPath})`,
          'REG-PURGE'
        );
      }
    } catch (e) {
      console.error('Error deleting registry key:', e);
    }
  };

  const handleCopyCommand = (item: RegistryPersistenceItem) => {
    navigator.clipboard.writeText(item.remediationCmd);
    setCopiedId(item.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredItems = useMemo(() => {
    return items.filter(item => {
      if (activeCategory === 'RUN' && item.category !== 'RUN' && item.category !== 'RUNONCE') {
        return false;
      }
      if (activeCategory === 'WINLOGON' && item.category !== 'WINLOGON') {
        return false;
      }
      if (activeCategory === 'SERVICES' && item.category !== 'SERVICES') {
        return false;
      }
      if (activeCategory === 'TASKS' && item.category !== 'SCHEDULED_TASK') {
        return false;
      }
      if (activeCategory === 'IFEO' && item.category !== 'IFEO') {
        return false;
      }

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          item.entryName.toLowerCase().includes(q) ||
          item.commandValue.toLowerCase().includes(q) ||
          item.keyPath.toLowerCase().includes(q) ||
          item.reason.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [items, activeCategory, searchQuery]);

  const suspiciousCount = items.filter(i => i.status === 'SUSPICIOUS').length;
  const safeCount = items.filter(i => i.status === 'LEGITIMATE').length;

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Title & Explanatory Banner */}
      <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-semibold text-cyan-400">
              <Zap className="w-4 h-4" />
              <span>SURVEILLANCE DU REGISTRE WINDOWS EN TEMPS RÉEL</span>
              <span className="text-slate-500">·</span>
              <span className="text-slate-400 font-mono">HKCU & HKLM Persistence Guard</span>
            </div>
            <h2 className="text-lg md:text-xl font-bold text-white tracking-tight mt-1">
              Surveillance des Clés de Persistance Critiques (Run, RunOnce, Winlogon, Services)
            </h2>
            <p className="text-xs text-slate-300 max-w-3xl leading-relaxed mt-1">
              Surveille et audite en permanence les points d'ancrage de persistance du système d'exploitation Windows :
              clés de démarrage automatique <code>Run</code>/<code>RunOnce</code>, détournements de <code>Winlogon Shell</code>,
              pièges de débogueur <code>IFEO</code>, tâches planifiées et services suspects.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={fetchRegistryPersistence}
              disabled={isLoading}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 text-cyan-200 transition-colors flex items-center gap-1.5"
            >
              <RotateCcw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
              <span>Actualiser Audit</span>
            </button>
          </div>
        </div>

        {/* Counter KPIs */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-800/80">
          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg">
            <div className="text-[11px] text-slate-400 font-mono">Clés Inspectées</div>
            <div className="text-xl font-bold font-mono text-white mt-0.5">{items.length}</div>
          </div>
          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg">
            <div className="text-[11px] text-slate-400 font-mono">Persistances Suspectes</div>
            <div className={`text-xl font-bold font-mono mt-0.5 ${suspiciousCount > 0 ? 'text-rose-400 animate-pulse' : 'text-slate-300'}`}>
              {suspiciousCount}
            </div>
          </div>
          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg">
            <div className="text-[11px] text-slate-400 font-mono">Entrées Conformes</div>
            <div className="text-xl font-bold font-mono text-emerald-400 mt-0.5">{safeCount}</div>
          </div>
          <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg">
            <div className="text-[11px] text-slate-400 font-mono">Dernière Synchronisation</div>
            <div className="text-sm font-semibold font-mono text-slate-300 mt-1">{lastScanTime || 'Temps réel'}</div>
          </div>
        </div>
      </div>

      {/* Alert Banner if Rogue Persistence Detected */}
      {suspiciousCount > 0 && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/80 rounded-xl flex items-center justify-between gap-4 animate-in slide-in-from-top-1 duration-200 shadow-lg shadow-rose-950/30">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-rose-900/80 border border-rose-700 flex items-center justify-center text-rose-300 shrink-0">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
            </div>
            <div>
              <div className="text-xs font-bold text-rose-300 font-mono uppercase tracking-wide">
                Alerte de Persistance Détectée ({suspiciousCount} entrée hostile)
              </div>
              <p className="text-xs text-rose-200/90 mt-0.5">
                Une clé non autorisée cible un script ou un binaire exécutable dans un dossier utilisateur temporaire.
                Vous pouvez purger la clé immédiatement ou exécuter la commande de remédiation.
              </p>
            </div>
          </div>

          <button
            onClick={() => onRunInConsole?.('scan --deep')}
            className="px-3 py-1.5 bg-rose-900 hover:bg-rose-800 border border-rose-600 rounded-lg text-xs font-bold text-white shrink-0 transition-colors"
          >
            Auditer en Console
          </button>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        {/* Category Filters */}
        <div className="flex flex-wrap items-center gap-1.5 p-1 bg-slate-900 rounded-lg border border-slate-800">
          <button
            onClick={() => setActiveCategory('ALL')}
            className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
              activeCategory === 'ALL'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Toutes ({items.length})
          </button>
          <button
            onClick={() => setActiveCategory('RUN')}
            className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
              activeCategory === 'RUN'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Run & RunOnce
          </button>
          <button
            onClick={() => setActiveCategory('WINLOGON')}
            className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
              activeCategory === 'WINLOGON'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Winlogon (Shell/Userinit)
          </button>
          <button
            onClick={() => setActiveCategory('SERVICES')}
            className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
              activeCategory === 'SERVICES'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Services
          </button>
          <button
            onClick={() => setActiveCategory('TASKS')}
            className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
              activeCategory === 'TASKS'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Tâches Planifiées
          </button>
          <button
            onClick={() => setActiveCategory('IFEO')}
            className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
              activeCategory === 'IFEO'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            IFEO (Debugger)
          </button>
        </div>

        {/* Search Input */}
        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filtrer une clé, un chemin..."
            className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Items List */}
      <div className="space-y-3">
        {filteredItems.length === 0 ? (
          <div className="p-8 text-center bg-slate-900/60 border border-slate-800 rounded-xl text-slate-400 font-mono text-xs">
            Aucune clé de Registre ne correspond aux critères de recherche.
          </div>
        ) : (
          filteredItems.map((item) => {
            const isSuspicious = item.status === 'SUSPICIOUS';

            return (
              <div
                key={item.id}
                className={`p-4 rounded-xl border transition-all ${
                  isSuspicious
                    ? 'bg-rose-950/20 border-rose-800/80 shadow-md shadow-rose-950/20 hover:border-rose-600'
                    : 'bg-slate-900/70 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  {/* Left: Info */}
                  <div className="space-y-1.5 min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border font-bold ${
                        item.hive === 'HKLM'
                          ? 'text-cyan-300 bg-cyan-950 border-cyan-800'
                          : 'text-purple-300 bg-purple-950 border-purple-800'
                      }`}>
                        {item.hive}
                      </span>
                      <span className="font-mono text-xs font-bold text-white">
                        {item.entryName}
                      </span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${
                        isSuspicious
                          ? 'text-rose-400 bg-rose-950 border-rose-800 animate-pulse'
                          : 'text-emerald-400 bg-emerald-950 border-emerald-800'
                      }`}>
                        {isSuspicious ? 'PERSISTANCE SUSPECTE' : 'LÉGITIME'}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500">
                        {item.category} · {item.mitreTechnique}
                      </span>
                    </div>

                    {/* Registry Key Path */}
                    <div className="text-[11px] font-mono text-slate-400 truncate">
                      Chemin : <span className="text-slate-300">{item.keyPath}</span>
                    </div>

                    {/* Command / Value */}
                    <div className="p-2 rounded bg-slate-950 border border-slate-800/80 font-mono text-xs break-all">
                      <span className="text-slate-500 select-none">&gt; </span>
                      <span className={isSuspicious ? 'text-rose-300 font-semibold' : 'text-cyan-300'}>
                        {item.commandValue}
                      </span>
                    </div>

                    {/* Reason */}
                    <p className="text-xs text-slate-300">
                      {item.reason}
                    </p>
                  </div>

                  {/* Right: Actions */}
                  <div className="flex flex-wrap lg:flex-col items-end gap-2 shrink-0">
                    {isSuspicious && (
                      <button
                        onClick={() => handleDeleteKey(item)}
                        className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-900 hover:bg-rose-800 text-white border border-rose-700 transition-colors flex items-center gap-1.5 shadow-xs"
                        title="Supprimer cette clé de démarrage suspecte du Registre"
                      >
                        <Trash2 className="w-3.5 h-3.5 text-rose-200" />
                        <span>Supprimer la Clé</span>
                      </button>
                    )}

                    <button
                      onClick={() => handleCopyCommand(item)}
                      className="px-2.5 py-1.5 rounded-lg text-xs font-mono text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 transition-colors flex items-center gap-1.5"
                      title="Copier la commande PowerShell Remove-ItemProperty"
                    >
                      {copiedId === item.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedId === item.id ? 'Copié' : 'Commande PS1'}</span>
                    </button>

                    <button
                      onClick={() => onRunInConsole?.(item.remediationCmd)}
                      className="px-2.5 py-1.5 rounded-lg text-xs font-mono text-cyan-300 hover:text-white bg-cyan-950/70 hover:bg-cyan-900 border border-cyan-800/80 transition-colors flex items-center gap-1.5"
                      title="Exécuter dans la Console Live"
                    >
                      <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Exécuter</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
