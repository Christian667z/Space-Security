import React from 'react';
import { Shield, Terminal, Download, Cpu, Activity, Network, Lock, FileCode, Archive } from 'lucide-react';
import { TabId } from '../types/cyberdefense';

interface TopNavProps {
  activeTab: TabId;
  onSelectTab: (tab: TabId) => void;
  onDownloadScript: () => void;
  onDownloadZip: () => void;
}

export const TopNav: React.FC<TopNavProps> = ({
  activeTab,
  onSelectTab,
  onDownloadScript,
  onDownloadZip,
}) => {
  return (
    <header className="flex items-center justify-between gap-8 px-6 py-4 border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-50">
      {/* Zone 1: Single text element wordmark */}
      <div 
        onClick={() => onSelectTab('overview')}
        className="flex items-center gap-2.5 cursor-pointer text-slate-100 whitespace-nowrap shrink-0 group"
      >
        <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800/60 flex items-center justify-center text-cyan-400 group-hover:border-cyan-500 transition-colors">
          <Shield className="w-4 h-4 text-cyan-400" />
        </div>
        <span className="text-base font-bold tracking-tight text-white font-['Plus_Jakarta_Sans']">
          SpaceSec Ultra <span className="text-cyan-400 text-xs uppercase tracking-wider font-mono px-1.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-800/40">Kernel v3.0</span>
        </span>
      </div>

      {/* Zone 2: Concise single-line navigation links */}
      <nav className="hidden lg:flex items-center gap-6 text-sm font-medium text-slate-300">
        <button
          onClick={() => onSelectTab('overview')}
          className={`flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'overview' ? 'text-cyan-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Vue Centrale</span>
        </button>

        <button
          onClick={() => onSelectTab('task-manager')}
          className={`flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'task-manager' ? 'text-cyan-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Cpu className="w-3.5 h-3.5" />
          <span>Gestionnaire des Tâches</span>
        </button>

        <button
          onClick={() => onSelectTab('console')}
          className={`flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'console' ? 'text-cyan-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>Console Live</span>
        </button>

        <button
          onClick={() => onSelectTab('deep-excision')}
          className={`flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'deep-excision' ? 'text-cyan-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Cpu className="w-3.5 h-3.5" />
          <span>Éradication OS & Kernel</span>
        </button>

        <button
          onClick={() => onSelectTab('forensics')}
          className={`flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'forensics' ? 'text-cyan-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Forensique RAM</span>
        </button>

        <button
          onClick={() => onSelectTab('network')}
          className={`flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'network' ? 'text-cyan-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          <span>Réseau C2</span>
        </button>

        <button
          onClick={() => onSelectTab('hardening')}
          className={`flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'hardening' ? 'text-cyan-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Lock className="w-3.5 h-3.5" />
          <span>Durcissement</span>
        </button>

        <button
          onClick={() => onSelectTab('script-hub')}
          className={`flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'script-hub' ? 'text-cyan-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileCode className="w-3.5 h-3.5" />
          <span>Script Hub (.ps1)</span>
        </button>
      </nav>

      {/* Zone 3: 1 primary action */}
      <div className="flex items-center gap-3 shrink-0">
        <button
          onClick={onDownloadZip}
          className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 rounded-lg hover:bg-cyan-300 transition-colors whitespace-nowrap shrink-0 shadow-sm shadow-cyan-500/20 active:translate-y-px"
        >
          <Archive className="w-3.5 h-3.5" />
          <span>Télécharger ZIP (.zip)</span>
        </button>
      </div>
    </header>
  );
};
