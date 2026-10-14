import React from 'react';
import { Shield, Loader2 } from 'lucide-react';

interface TabLoadingSkeletonProps {
  tabName?: string;
}

const TAB_TITLES: Record<string, string> = {
  overview: "Tableau de Bord & Vue d'Ensemble",
  timeline: 'Chronologie Tactique des Menaces',
  'task-manager': 'Gestionnaire de Processus Live',
  bits: 'Moniteur de Tâches BITS & Persistance',
  heuristic: 'Moteur Heuristique & Analyse Comportementale',
  console: "Console d'Analyse en Temps Réel",
  'deep-excision': "Module d'Éradication Kernel & Déverrouillage",
  forensics: 'Forensique Mémoire & Dump RAM',
  network: 'Surveillance C2 & Télémétrie Réseau',
  wifi: 'Scanner Wi-Fi & Analyse BSSID 802.11',
  'deep-detection': 'Détection Profonde & Analyse Heuristique',
  'themes-hunter': 'Chasseur de Menaces Thèmes Windows',
  'sandbox-isolation': 'Isolement Sandbox & Kill-Switch Réseau',
  remediation: 'Restauration & Réparation Post-Infection',
  hardening: 'Durcissement Système & Protection Windows Defender',
  'script-hub': 'Atelier de Scripts & Export ZIP',
  'ip-locator': 'Géolocalisation IP & Traçage Forensique',
};

export const TabLoadingSkeleton: React.FC<TabLoadingSkeletonProps> = ({ tabName }) => {
  const displayTitle = tabName && TAB_TITLES[tabName] ? TAB_TITLES[tabName] : 'Module CyberDéfense';

  return (
    <div className="space-y-6 animate-pulse">
      {/* Top Banner Skeleton */}
      <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-6 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/20 rounded-lg text-cyan-400">
            <Loader2 className="w-5 h-5 animate-spin" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 font-bold bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-800/50">
                Chargement Asynchrone
              </span>
              <span className="text-xs text-slate-500 font-mono">CODE-SPLIT ACTIVE</span>
            </div>
            <h2 className="text-lg font-bold text-white mt-1">
              {displayTitle}
            </h2>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="h-8 w-28 bg-slate-800 rounded-lg" />
          <div className="h-8 w-24 bg-slate-800 rounded-lg" />
        </div>
      </div>

      {/* Grid Cards Skeleton */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="bg-slate-900/40 border border-slate-800/60 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="h-3 w-20 bg-slate-800 rounded" />
              <div className="h-6 w-6 bg-slate-800 rounded-lg" />
            </div>
            <div className="h-7 w-28 bg-slate-800 rounded" />
            <div className="h-2 w-full bg-slate-800/60 rounded" />
          </div>
        ))}
      </div>

      {/* Main Panel Content Skeleton */}
      <div className="bg-slate-900/40 border border-slate-800/60 rounded-xl p-6 space-y-4">
        <div className="h-4 w-48 bg-slate-800 rounded" />
        <div className="space-y-2.5">
          <div className="h-3 w-full bg-slate-800/50 rounded" />
          <div className="h-3 w-5/6 bg-slate-800/50 rounded" />
          <div className="h-3 w-4/6 bg-slate-800/50 rounded" />
        </div>
        <div className="h-48 bg-slate-950/50 border border-slate-800/40 rounded-lg flex items-center justify-center">
          <div className="flex flex-col items-center gap-2 text-slate-600">
            <Shield className="w-8 h-8 animate-pulse text-cyan-500/40" />
            <span className="text-xs font-mono text-slate-500">Initialisation de la mémoire et des heuristiques...</span>
          </div>
        </div>
      </div>
    </div>
  );
};
