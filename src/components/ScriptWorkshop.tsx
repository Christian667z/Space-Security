import React, { useState } from 'react';
import { FileCode, Download, Copy, Check, Terminal, Shield, CheckCircle2, AlertTriangle, Cpu, Archive, Code } from 'lucide-react';
import { BOOSTED_POWERSHELL_SCRIPT, ELEVATED_BATCH_LAUNCHER, EMERGENCY_SAFEBOOT_LAUNCHER } from '../data/powershellScript';
import { CSHARP_EXTIRPATOR_CODE } from '../data/csharpExtirpator';
import { generateAndDownloadZip } from '../utils/zipGenerator';

interface ScriptWorkshopProps {
  onDownloadZip?: () => void;
}

export const ScriptWorkshop: React.FC<ScriptWorkshopProps> = ({ onDownloadZip }) => {
  const [activeFile, setActiveFile] = useState<'ps1' | 'cs' | 'bat' | 'safeboot'>('ps1');
  const [copied, setCopied] = useState(false);
  const [isZipping, setIsZipping] = useState(false);

  const triggerZip = async () => {
    setIsZipping(true);
    try {
      if (onDownloadZip) {
        onDownloadZip();
      } else {
        await generateAndDownloadZip();
      }
    } finally {
      setIsZipping(false);
    }
  };

  const currentContent = activeFile === 'ps1'
    ? BOOSTED_POWERSHELL_SCRIPT
    : activeFile === 'cs'
    ? CSHARP_EXTIRPATOR_CODE
    : activeFile === 'bat'
    ? ELEVATED_BATCH_LAUNCHER
    : EMERGENCY_SAFEBOOT_LAUNCHER;

  const currentFilename = activeFile === 'ps1'
    ? 'SpaceSecurity_ULTRA_v3_Kernel.ps1'
    : activeFile === 'cs'
    ? 'KernelFileExtirpator.cs'
    : activeFile === 'bat'
    ? 'RunAs_SpaceSecurity_Admin.bat'
    : 'Emergency_SafeBoot_Clean.bat';

  const handleCopy = () => {
    navigator.clipboard.writeText(currentContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = (filename: string, content: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-2">
              <FileCode className="w-4 h-4" />
              <span>Générateur & Export de Code Source Réel</span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
              Suite PowerShell v3.0 KERNEL & Pack ZIP Complet
            </h2>
            <p className="mt-1 text-sm text-slate-300">
              Téléchargez l'archive ZIP prête à l'emploi contenant le script PowerShell boosté, le lanceur .bat avec élévation automatique et le guide d'utilisation.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              onClick={triggerZip}
              disabled={isZipping}
              className="flex items-center gap-2 px-5 py-2.5 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold rounded-lg text-xs transition-colors shadow-lg shadow-cyan-500/20 active:translate-y-px"
            >
              <Archive className="w-4 h-4" />
              <span>{isZipping ? 'Création de l\'archive...' : 'Télécharger l\'Archive ZIP (.zip)'}</span>
            </button>
            <button
              onClick={() => handleDownload('SpaceSecurity_ULTRA_v3_Kernel.ps1', BOOSTED_POWERSHELL_SCRIPT)}
              className="flex items-center gap-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-semibold rounded-lg text-xs transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Fichier .ps1 Seul</span>
            </button>
          </div>
        </div>
      </div>

      {/* ZIP Archive Content Breakdown */}
      <div className="p-5 bg-gradient-to-r from-cyan-950/40 via-slate-900 to-slate-950 border border-cyan-800/40 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-cyan-950 border border-cyan-800/80 flex items-center justify-center text-cyan-400 shrink-0">
            <Archive className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white font-mono">
              SpaceSec_CyberDefense_Ultra_v3.zip
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Pack tout-en-un comprenant <strong>.ps1</strong> + <strong>.bat administrateur</strong> + <strong>outil SafeBoot</strong> + <strong>manuel d'éradication</strong>.
            </p>
          </div>
        </div>

        <button
          onClick={triggerZip}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-lg text-xs transition-colors shrink-0"
        >
          <Download className="w-4 h-4" />
          <span>Obtenir le ZIP</span>
        </button>
      </div>

      {/* Guide for Developers & Security Engineers */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm">
            <Shield className="w-4 h-4" />
            <span>1. Droits & Privilèges Système</span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Le script active <code className="text-cyan-300">SeDebugPrivilege</code> et <code className="text-cyan-300">SeTakeOwnershipPrivilege</code> via des structures P/Invoke Win32, permettant de déposséder même le compte TrustedInstaller.
          </p>
        </div>

        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center gap-2 text-amber-400 font-semibold text-sm">
            <Cpu className="w-4 h-4" />
            <span>2. Destruction au Reboot Noyau</span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Si un fichier est verrouillé par un pilote ou un service en cours, le script le programme dans <code className="text-amber-300">PendingFileRenameOperations</code> afin que le noyau l'efface avant tout chargement.
          </p>
        </div>

        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
            <CheckCircle2 className="w-4 h-4" />
            <span>3. Compatibilité 100% Machine Réelle</span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Compatible Windows 10, Windows 11 et Windows Server. Fonctionne en mode hors-ligne sans dépendance externe ni module PowerShell tiers requis.
          </p>
        </div>
      </div>

      {/* Code Viewer */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
        {/* File tabs & actions */}
        <div className="flex items-center justify-between px-4 py-3 bg-slate-900 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveFile('ps1')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                activeFile === 'ps1'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              SpaceSecurity_ULTRA_v3_Kernel.ps1
            </button>
            <button
              onClick={() => setActiveFile('cs')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                activeFile === 'cs'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              KernelFileExtirpator.cs (C#)
            </button>
            <button
              onClick={() => setActiveFile('bat')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                activeFile === 'bat'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              RunAs_SpaceSecurity_Admin.bat
            </button>
            <button
              onClick={() => setActiveFile('safeboot')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                activeFile === 'safeboot'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Emergency_SafeBoot_Clean.bat
            </button>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copié dans le presse-papiers !' : 'Copier Tout'}</span>
            </button>

            <button
              onClick={() => handleDownload(currentFilename, currentContent)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded-lg text-xs transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Télécharger Fichier</span>
            </button>
          </div>
        </div>

        {/* Code Content */}
        <div className="p-4 overflow-x-auto max-h-[600px] scrollbar-thin scrollbar-thumb-slate-800 font-mono text-xs text-slate-300 leading-relaxed whitespace-pre">
          {currentContent}
        </div>
      </div>

      {/* Execution Instructions Banner */}
      <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
        <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          Instructions d'Exécution sur la Machine Cible :
        </h3>
        <ol className="text-xs text-slate-300 space-y-2 list-decimal list-inside font-mono">
          <li>
            <span className="font-sans">Téléchargez le fichier </span>
            <code className="text-cyan-300 font-bold">SpaceSecurity_ULTRA_v3_Kernel.ps1</code>
            <span className="font-sans"> et le lanceur </span>
            <code className="text-cyan-300">RunAs_SpaceSecurity_Admin.bat</code>
            <span className="font-sans"> dans le même dossier (par exemple sur le Bureau).</span>
          </li>
          <li>
            <span className="font-sans">Faites un clic droit sur </span>
            <code className="text-amber-300">RunAs_SpaceSecurity_Admin.bat</code>
            <span className="font-sans"> et choisissez </span>
            <strong className="text-white font-sans">"Exécuter en tant qu'administrateur"</strong>.
          </li>
          <li>
            <span className="font-sans">Ou bien dans une console PowerShell Administrateur, lancez directement :</span>
            <div className="my-1.5 p-2.5 bg-slate-950 rounded border border-slate-800 text-cyan-300">
              powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SpaceSecurity_ULTRA_v3_Kernel.ps1
            </div>
          </li>
          <li>
            <span className="font-sans">Pour les malwares les plus tenaces, utilisez l'option </span>
            <strong className="text-rose-400 font-sans">[1] KERNEL EXTIRPATOR</strong>
            <span className="font-sans"> suivie d'un redémarrage de la machine pour achever la suppression au niveau du noyau.</span>
          </li>
        </ol>
      </div>
    </div>
  );
};
