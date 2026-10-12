import React, { useState, useRef, useEffect } from 'react';
import { Terminal, Play, Trash2, Download, Filter, CornerDownLeft, ShieldAlert, Cpu } from 'lucide-react';
import { ConsoleLogMessage } from '../types/cyberdefense';

interface ConsoleTerminalProps {
  logs: ConsoleLogMessage[];
  onExecuteCommand: (command: string) => void;
  onClearLogs: () => void;
  onExportReport: () => void;
}

export const ConsoleTerminal: React.FC<ConsoleTerminalProps> = ({
  logs,
  onExecuteCommand,
  onClearLogs,
  onExportReport,
}) => {
  const [inputCommand, setInputCommand] = useState('');
  const [filterLevel, setFilterLevel] = useState<string>('ALL');
  const [commandHistory, setCommandHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const logContainerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cmd = inputCommand.trim();
    if (!cmd) return;

    setCommandHistory(prev => [...prev, cmd]);
    setHistoryIndex(-1);
    setInputCommand('');
    onExecuteCommand(cmd);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (commandHistory.length > 0) {
        const nextIdx = historyIndex === -1 ? commandHistory.length - 1 : Math.max(0, historyIndex - 1);
        setHistoryIndex(nextIdx);
        setInputCommand(commandHistory[nextIdx]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex !== -1) {
        const nextIdx = historyIndex + 1;
        if (nextIdx >= commandHistory.length) {
          setHistoryIndex(-1);
          setInputCommand('');
        } else {
          setHistoryIndex(nextIdx);
          setInputCommand(commandHistory[nextIdx]);
        }
      }
    }
  };

  const filteredLogs = logs.filter(log => {
    if (filterLevel === 'ALL') return true;
    return log.level === filterLevel;
  });

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'OK':
        return 'text-emerald-400';
      case 'WARN':
        return 'text-amber-400';
      case 'ERROR':
        return 'text-rose-400 font-semibold';
      case 'KERNEL':
        return 'text-fuchsia-400 font-bold';
      case 'INFO':
      default:
        return 'text-cyan-400';
    }
  };

  const quickCommands = [
    { label: 'Deep Scan Kernel', cmd: 'scan --deep' },
    { label: 'Traquer & Purger BITS (T1197)', cmd: 'bits' },
    { label: 'Audit Exclusions Defender', cmd: 'defendersync' },
    { label: 'Audit Vulnérabilités (Get-HotFix)', cmd: 'vulnscan' },
    { label: 'Parser EventLog (WinEvent)', cmd: 'eventlog' },
    { label: 'Scanner Ports (Localhost)', cmd: 'ports' },
    { label: 'Eradication Fichier Bloqué', cmd: 'unlock C:\\Windows\\System32\\drivers\\suspicious_rootkit.sys' },
    { label: 'Audit IFEO Hijacks', cmd: 'ifeo' },
    { label: 'Suspension Watchdogs', cmd: 'suspend swisyn' },
    { label: 'Audit Pilotes Kernel', cmd: 'drivers' },
    { label: 'Sockets C2 Actifs', cmd: 'sockets' },
    { label: 'Reparation Defender', cmd: 'defender-repair' },
  ];

  return (
    <div className="flex flex-col h-[750px] bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl font-mono text-xs">
      {/* Terminal Title Bar */}
      <div className="flex items-center justify-between px-4 py-3 bg-slate-900 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 mr-2">
            <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
          </div>
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span className="text-slate-200 font-semibold tracking-wide">
            SpaceSec Live CyberDefense Shell · Windows NT [Root / TrustedInstaller Access]
          </span>
        </div>

        <div className="flex items-center gap-3">
          {/* Filter options */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-md border border-slate-800">
            <Filter className="w-3 h-3 text-slate-500 ml-1 mr-0.5" />
            {(['ALL', 'KERNEL', 'ERROR', 'WARN', 'OK', 'INFO'] as const).map(lvl => (
              <button
                key={lvl}
                onClick={() => setFilterLevel(lvl)}
                className={`px-2 py-0.5 rounded text-[11px] transition-colors ${
                  filterLevel === lvl
                    ? 'bg-cyan-950 text-cyan-300 font-semibold border border-cyan-800/60'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>

          <button
            onClick={onClearLogs}
            title="Effacer les logs de la console"
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded transition-colors"
          >
            <Trash2 className="w-4 h-4" />
          </button>

          <button
            onClick={onExportReport}
            title="Exporter le rapport d'analyse"
            className="flex items-center gap-1.5 px-2.5 py-1 text-slate-200 bg-slate-800 hover:bg-slate-700 rounded transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Rapport</span>
          </button>
        </div>
      </div>

      {/* Quick Launch Shortcuts */}
      <div className="flex items-center gap-2 px-4 py-2 bg-slate-900/60 border-b border-slate-800/80 overflow-x-auto text-[11px] scrollbar-thin">
        <span className="text-slate-500 whitespace-nowrap flex items-center gap-1">
          <Play className="w-3 h-3 text-cyan-400" />
          Actions Rapides:
        </span>
        {quickCommands.map(item => (
          <button
            key={item.cmd}
            onClick={() => onExecuteCommand(item.cmd)}
            className="px-2.5 py-1 bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700/60 rounded text-slate-300 hover:text-cyan-300 whitespace-nowrap transition-colors"
          >
            {item.label}
          </button>
        ))}
      </div>

      {/* Log Output Area */}
      <div
        ref={logContainerRef}
        className="flex-1 p-4 overflow-y-auto space-y-1 bg-black/60 scrollbar-thin scrollbar-thumb-slate-800"
      >
        <div className="text-slate-500 mb-3 pb-2 border-b border-slate-900">
          <span className="text-cyan-400 font-bold">SpaceSec Ultra Engine v3.0</span> - Initialisation des privilèges SeDebugPrivilege et SeTakeOwnershipPrivilege terminée.
          <br />
          Prêt pour l'analyse forensique, interception C2 et éradication racine de malwares OS/Kernel. Tapez <span className="text-amber-300">'help'</span> pour la liste des commandes.
        </div>

        {filteredLogs.map(log => (
          <div key={log.id} className="flex items-start gap-2 leading-relaxed hover:bg-slate-900/40 px-1 py-0.5 rounded">
            <span className="text-slate-600 select-none tabular-nums shrink-0">
              [{log.timestamp}]
            </span>
            <span className={`shrink-0 font-bold ${getLevelColor(log.level)}`}>
              [{log.level}]
            </span>
            {log.tag && (
              <span className="text-slate-400 font-medium shrink-0">
                [{log.tag}]
              </span>
            )}
            <span className="text-slate-200 break-all whitespace-pre-wrap">
              {log.text}
            </span>
          </div>
        ))}
      </div>

      {/* Command Prompt Input */}
      <form
        onSubmit={handleSubmit}
        className="flex items-center gap-2 px-4 py-3 bg-slate-900 border-t border-slate-800"
      >
        <span className="text-cyan-400 font-bold select-none shrink-0">
          SpaceSec#
        </span>
        <input
          ref={inputRef}
          type="text"
          value={inputCommand}
          onChange={e => setInputCommand(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Entrez une commande (ex: scan --deep, unlock C:\path\file.exe, ifeo, help)..."
          className="flex-1 bg-transparent text-slate-100 placeholder-slate-600 focus:outline-none text-xs"
          autoFocus
        />
        <button
          type="submit"
          className="flex items-center gap-1 px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded transition-colors text-xs"
        >
          <span>Exécuter</span>
          <CornerDownLeft className="w-3 h-3" />
        </button>
      </form>
    </div>
  );
};
