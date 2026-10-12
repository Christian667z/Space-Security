import React from 'react';
import { Shield, ShieldAlert, Cpu, Network, Lock, Terminal, AlertTriangle, ArrowRight, CheckCircle2, Play, Download, Archive } from 'lucide-react';
import { TabId, ThreatItem } from '../types/cyberdefense';
import { ThreatHeatmap } from './ThreatHeatmap';

interface OverviewDashboardProps {
  onNavigateTab: (tab: TabId) => void;
  onRunInConsole: (command: string) => void;
  threats: ThreatItem[];
  onDownloadZip: () => void;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  onNavigateTab,
  onRunInConsole,
  threats,
  onDownloadZip,
}) => {
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

      {/* Main Grid: Active Threats + Modular Navigator */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Active Threat Watchlist */}
        <div className="lg:col-span-2 p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <h3 className="text-base font-semibold text-slate-100">
                Menaces Détectées en Attente d'Action
              </h3>
            </div>
            <span className="text-xs text-slate-500 font-mono">
              MITRE ATT&CK Matrix Grounded
            </span>
          </div>

          <div className="space-y-3">
            {threats.map(threat => (
              <div
                key={threat.id}
                className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl hover:border-slate-700 transition-colors space-y-2.5"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-xs text-rose-400">
                      [{threat.severity}]
                    </span>
                    <span className="font-semibold text-sm text-slate-100">
                      {threat.name}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400 font-mono">
                      {threat.category}
                    </span>
                  </div>

                  <div className="text-[11px] font-mono text-cyan-400">
                    {threat.mitreTechnique}
                  </div>
                </div>

                <div className="text-xs text-slate-300 leading-relaxed font-sans">
                  {threat.description}
                </div>

                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-2 border-t border-slate-900 text-xs">
                  <div className="text-[11px] font-mono text-slate-400 truncate max-w-md">
                    Cible : <span className="text-slate-200">{threat.targetPath}</span>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => onRunInConsole(`unlock "${threat.targetPath}"`)}
                      className="px-3 py-1 bg-rose-600 hover:bg-rose-500 text-white font-semibold rounded text-xs transition-colors"
                    >
                      Éradiquer au Niveau Kernel
                    </button>
                  </div>
                </div>
              </div>
            ))}
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
