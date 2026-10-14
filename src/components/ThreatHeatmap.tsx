import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle2, Cpu, Database, HardDrive, PlayCircle, Terminal, Layers, Info } from 'lucide-react';

export type SystemArea = 'Kernel' | 'Registry' | 'Filesystem' | 'Startup';
export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'NOMINAL';

export interface HeatmapNode {
  id: string;
  name: string;
  area: SystemArea;
  targetPath: string;
  riskLevel: RiskLevel;
  riskScore: number; // 0 - 100
  mitreTechnique: string;
  statusText: string;
  remediationCmd: string;
}

interface ThreatHeatmapProps {
  onRunInConsole: (command: string) => void;
}

export const ThreatHeatmap: React.FC<ThreatHeatmapProps> = ({ onRunInConsole }) => {
  const [selectedArea, setSelectedArea] = useState<string>('ALL');
  const [activeNode, setActiveNode] = useState<HeatmapNode | null>(null);

  const heatmapNodes: HeatmapNode[] = [
    // 1. KERNEL & DRIVERS
    {
      id: 'k1',
      name: 'Mini-Filter Drivers (fltmc)',
      area: 'Kernel',
      targetPath: 'C:\\Windows\\System32\\drivers\\fltmgr.sys',
      riskLevel: 'NOMINAL',
      riskScore: 10,
      mitreTechnique: 'T1014 - Kernel Filter Inspection',
      statusText: 'Gestionnaire de filtres de système de fichiers Microsoft intègre',
      remediationCmd: 'fltmc filters',
    },
    {
      id: 'k2',
      name: 'Session Manager Boot Delete',
      area: 'Kernel',
      targetPath: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations',
      riskLevel: 'NOMINAL',
      riskScore: 8,
      mitreTechnique: 'T1547.001 - Boot / Logon Initialization',
      statusText: 'Aucune suppression différée de pilote suspect en attente de reboot',
      remediationCmd: 'registry-audit',
    },
    {
      id: 'k3',
      name: 'Pilotes Non-Signés (BYOVD)',
      area: 'Kernel',
      targetPath: 'driverquery /v /fo csv (Vérification des signatures numériques)',
      riskLevel: 'NOMINAL',
      riskScore: 12,
      mitreTechnique: 'T1068 - Privilege Escalation Boundary',
      statusText: 'Tous les pilotes résidents possèdent une signature WHQL valide',
      remediationCmd: 'driverquery /v',
    },
    {
      id: 'k4',
      name: 'Intégrité SafeBoot Minimal',
      area: 'Kernel',
      targetPath: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal',
      riskLevel: 'NOMINAL',
      riskScore: 10,
      mitreTechnique: 'T1562.001 - Disable Security Tools',
      statusText: 'Services de secours WinDefend & VSS déclarés dans SafeBoot',
      remediationCmd: 'safemode-prepare',
    },

    // 2. REGISTRY & PERSISTANCE
    {
      id: 'r1',
      name: 'Détournements IFEO (Debugger)',
      area: 'Registry',
      targetPath: 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options',
      riskLevel: 'NOMINAL',
      riskScore: 8,
      mitreTechnique: 'T1546.012 - Image File Execution Options Inspection',
      statusText: 'Aucune clé Debugger malveillante sur Taskmgr ou Defender',
      remediationCmd: 'ifeo',
    },
    {
      id: 'r2',
      name: 'Abonnements WMI (root\\subscription)',
      area: 'Registry',
      targetPath: 'root\\subscription:__EventFilter & __EventConsumer',
      riskLevel: 'NOMINAL',
      riskScore: 12,
      mitreTechnique: 'T1546.003 - WMI Event Subscription',
      statusText: 'Aucun filtre WMI persistant suspect détecté dans l\'espace de noms',
      remediationCmd: 'wmi-clean',
    },
    {
      id: 'r3',
      name: 'Injection AppInit_DLLs',
      area: 'Registry',
      targetPath: 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs',
      riskLevel: 'NOMINAL',
      riskScore: 5,
      mitreTechnique: 'T1546.010 - AppInit DLLs Injection',
      statusText: 'LoadAppInit_DLLs = 0, aucune DLL injectée dans les processus GUI',
      remediationCmd: 'scan --deep',
    },
    {
      id: 'r4',
      name: 'Clés Run & RunOnce (Autorun)',
      area: 'Registry',
      targetPath: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      riskLevel: 'NOMINAL',
      riskScore: 14,
      mitreTechnique: 'T1547.001 - Registry Run Keys',
      statusText: 'Entrées de démarrage standard validées sans binaire masqué',
      remediationCmd: 'scan --deep',
    },

    // 3. STARTUP & SERVICES
    {
      id: 's1',
      name: 'Surveillance des Processus Système',
      area: 'Startup',
      targetPath: 'services.exe -> svchost.exe (Hiérarchie standard)',
      riskLevel: 'NOMINAL',
      riskScore: 10,
      mitreTechnique: 'T1059 - Process Hierarchy Validation',
      statusText: 'Arborescence des processus système Windows conforme aux baselines',
      remediationCmd: 'sockets',
    },
    {
      id: 's2',
      name: 'Contrôle des LOLBins Système',
      area: 'Startup',
      targetPath: 'certutil.exe, powershell.exe, mshta.exe',
      riskLevel: 'NOMINAL',
      riskScore: 12,
      mitreTechnique: 'T1105 - Ingress Tool Transfer (LOLBAS)',
      statusText: 'Aucun téléchargement distant ni script obfusqué actif',
      remediationCmd: 'powershell Get-Process',
    },
    {
      id: 's3',
      name: 'Tâches Planifiées Windows',
      area: 'Startup',
      targetPath: 'Get-ScheduledTask',
      riskLevel: 'NOMINAL',
      riskScore: 15,
      mitreTechnique: 'T1053.005 - Scheduled Task',
      statusText: 'Tâches planifiées homologuées Microsoft et OEM',
      remediationCmd: 'schtasks /query /fo list',
    },
    {
      id: 's4',
      name: 'Services Windows Defender (WinDefend)',
      area: 'Startup',
      targetPath: 'Services: WinDefend, WdNisSvc, WdFilter, SecurityHealthService',
      riskLevel: 'NOMINAL',
      riskScore: 10,
      mitreTechnique: 'T1562.001 - Impair Defenses',
      statusText: 'Services de protection antivirale opérationnels et intègres',
      remediationCmd: 'defender-repair',
    },

    // 4. FILESYSTEM & STOCKAGE
    {
      id: 'f1',
      name: 'Intégrité des Permissions NTFS',
      area: 'Filesystem',
      targetPath: 'C:\\Windows\\System32\\drivers',
      riskLevel: 'NOMINAL',
      riskScore: 8,
      mitreTechnique: 'T1222.001 - File Permissions Audit',
      statusText: 'DACL et contrôle d\'accès des répertoires système conformes',
      remediationCmd: 'icacls C:\\Windows\\System32',
    },
    {
      id: 'f2',
      name: 'Flux Cachés NTFS (ADS)',
      area: 'Filesystem',
      targetPath: '%USERPROFILE%\\Desktop & %TEMP% (:Zone.Identifier)',
      riskLevel: 'NOMINAL',
      riskScore: 10,
      mitreTechnique: 'T1564.004 - NTFS File Attributes: Alternate Data Streams',
      statusText: 'Aucun exécutable masqué en flux de données alternatif',
      remediationCmd: 'scan --deep',
    },
    {
      id: 'f3',
      name: 'Dossiers Temporaires %TEMP%',
      area: 'Filesystem',
      targetPath: 'C:\\Users\\*\\AppData\\Local\\Temp',
      riskLevel: 'NOMINAL',
      riskScore: 12,
      mitreTechnique: 'T1036.005 - Masquerading Audit',
      statusText: 'Répertoire temporaire sain sans binaire suspect persistant',
      remediationCmd: 'temp-clean',
    },
    {
      id: 'f4',
      name: 'Clichés Instantanés VSS',
      area: 'Filesystem',
      targetPath: 'vssadmin list shadows',
      riskLevel: 'NOMINAL',
      riskScore: 14,
      mitreTechnique: 'T1490 - Inhibit System Recovery',
      statusText: 'Service VSS opérationnel pour la résilience du système',
      remediationCmd: 'vss-create',
    },
  ];

  const filteredNodes = selectedArea === 'ALL'
    ? heatmapNodes
    : heatmapNodes.filter(n => n.area === selectedArea);

  // Compute aggregated scores per area
  const areasList: SystemArea[] = ['Kernel', 'Registry', 'Startup', 'Filesystem'];
  const getAreaScore = (area: SystemArea) => {
    const nodes = heatmapNodes.filter(n => n.area === area);
    const avg = Math.round(nodes.reduce((acc, curr) => acc + curr.riskScore, 0) / nodes.length);
    return avg;
  };

  const getRiskColor = (level: RiskLevel) => {
    switch (level) {
      case 'CRITICAL':
        return {
          bg: 'bg-rose-950/80 hover:bg-rose-900',
          border: 'border-rose-600/80',
          text: 'text-rose-400',
          badge: 'bg-rose-900/80 text-rose-200 border-rose-700',
          pulse: 'bg-rose-500',
        };
      case 'HIGH':
        return {
          bg: 'bg-amber-950/70 hover:bg-amber-900/80',
          border: 'border-amber-600/70',
          text: 'text-amber-400',
          badge: 'bg-amber-900/80 text-amber-200 border-amber-700',
          pulse: 'bg-amber-500',
        };
      case 'MEDIUM':
        return {
          bg: 'bg-yellow-950/50 hover:bg-yellow-900/60',
          border: 'border-yellow-600/60',
          text: 'text-yellow-400',
          badge: 'bg-yellow-900/80 text-yellow-200 border-yellow-700',
          pulse: 'bg-yellow-500',
        };
      case 'NOMINAL':
      default:
        return {
          bg: 'bg-emerald-950/40 hover:bg-emerald-900/50',
          border: 'border-emerald-700/50',
          text: 'text-emerald-400',
          badge: 'bg-emerald-900/80 text-emerald-200 border-emerald-700',
          pulse: 'bg-emerald-500',
        };
    }
  };

  return (
    <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-6 shadow-xl">
      {/* Heatmap Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <h3 className="text-base font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
              Threat Heatmap : Cartographie des Risques par Zone Système
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Visualiseur matriciel dynamique des surfaces d'attaque Windows (Noyau, Registre, Démarrage, Système de fichiers). Cliquez sur une cellule pour inspecter le vecteur et lancer l'éradication.
          </p>
        </div>

        {/* Area Filter Segmented Control */}
        <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800 text-xs shrink-0 overflow-x-auto">
          <button
            onClick={() => setSelectedArea('ALL')}
            className={`px-3 py-1 rounded transition-colors whitespace-nowrap ${
              selectedArea === 'ALL'
                ? 'bg-slate-800 text-cyan-300 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Toutes les Zones
          </button>
          {areasList.map(area => (
            <button
              key={area}
              onClick={() => setSelectedArea(area)}
              className={`px-2.5 py-1 rounded transition-colors whitespace-nowrap ${
                selectedArea === area
                  ? 'bg-slate-800 text-cyan-300 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {area === 'Kernel' ? 'Noyau (Kernel)' : area === 'Registry' ? 'Registre' : area === 'Startup' ? 'Démarrage' : 'Fichiers'}
            </button>
          ))}
        </div>
      </div>

      {/* Area Aggregation Bar Strips */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
        {areasList.map(area => {
          const score = getAreaScore(area);
          const isCritical = score >= 80;
          const isHigh = score >= 60 && score < 80;
          const isMed = score >= 35 && score < 60;

          const colorClass = isCritical
            ? 'text-rose-400 bg-rose-950/60 border-rose-800/80'
            : isHigh
            ? 'text-amber-400 bg-amber-950/60 border-amber-800/80'
            : isMed
            ? 'text-yellow-400 bg-yellow-950/50 border-yellow-800/60'
            : 'text-emerald-400 bg-emerald-950/50 border-emerald-800/60';

          return (
            <div
              key={area}
              onClick={() => setSelectedArea(area)}
              className={`p-3 rounded-lg border cursor-pointer transition-all ${colorClass} ${
                selectedArea === area ? 'ring-1 ring-cyan-400 shadow-md' : 'opacity-90 hover:opacity-100'
              }`}
            >
              <div className="flex items-center justify-between text-[11px] font-sans">
                <span className="font-semibold text-slate-200">
                  {area === 'Kernel' ? 'Noyau OS (Ring 0)' : area === 'Registry' ? 'Registre & GPO' : area === 'Startup' ? 'Démarrage & RAM' : 'Stockage NTFS'}
                </span>
                <span className="font-bold font-mono tabular-nums">
                  {score}%
                </span>
              </div>
              <div className="w-full bg-slate-900 rounded-full h-1.5 mt-2 overflow-hidden">
                <div
                  className={`h-full rounded-full ${
                    isCritical ? 'bg-rose-500' : isHigh ? 'bg-amber-500' : isMed ? 'bg-yellow-500' : 'bg-emerald-500'
                  }`}
                  style={{ width: `${score}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>

      {/* Heatmap Matrix Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {filteredNodes.map(node => {
          const colors = getRiskColor(node.riskLevel);
          const isSelected = activeNode?.id === node.id;

          return (
            <div
              key={node.id}
              onClick={() => setActiveNode(node)}
              className={`p-4 rounded-xl border transition-all cursor-pointer flex flex-col justify-between space-y-3 ${colors.bg} ${colors.border} ${
                isSelected ? 'ring-2 ring-cyan-400 shadow-lg scale-[1.01]' : 'shadow-sm'
              }`}
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between gap-1">
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                    {node.area}
                  </span>
                  <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded border ${colors.badge}`}>
                    {node.riskLevel} ({node.riskScore}%)
                  </span>
                </div>

                <div className="font-bold text-sm text-slate-100 font-['Plus_Jakarta_Sans'] leading-snug">
                  {node.name}
                </div>

                <p className="text-[11px] text-slate-300 line-clamp-2 leading-relaxed">
                  {node.statusText}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono">
                <span className="text-slate-400 truncate max-w-[150px]">
                  {node.mitreTechnique.split(' - ')[0]}
                </span>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onRunInConsole(node.remediationCmd);
                  }}
                  className="text-cyan-300 hover:text-white font-semibold underline text-[11px] transition-colors"
                >
                  Corriger
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Selected Node Deep Inspector Overlay Card */}
      {activeNode && (
        <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3 animate-in fade-in duration-200">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-900 pb-2">
            <div className="flex items-center gap-2">
              <Info className="w-4 h-4 text-cyan-400" />
              <span className="font-bold text-slate-100 text-sm font-['Plus_Jakarta_Sans']">
                Détails du Vecteur : {activeNode.name}
              </span>
              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${getRiskColor(activeNode.riskLevel).badge}`}>
                {activeNode.riskLevel} · Indice de risque : {activeNode.riskScore}/100
              </span>
            </div>

            <button
              onClick={() => setActiveNode(null)}
              className="text-xs text-slate-400 hover:text-slate-200"
            >
              Fermer
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <div className="text-slate-400 text-[11px]">Cible / Clé Système :</div>
              <div className="text-slate-200 font-semibold truncate mt-0.5" title={activeNode.targetPath}>
                {activeNode.targetPath}
              </div>
              <div className="text-slate-400 text-[11px] mt-2">Référence MITRE ATT&CK :</div>
              <div className="text-cyan-400 mt-0.5">{activeNode.mitreTechnique}</div>
            </div>

            <div>
              <div className="text-slate-400 text-[11px]">Diagnostic Technique :</div>
              <div className="text-slate-300 font-sans mt-0.5">{activeNode.statusText}</div>

              <div className="mt-3 flex items-center gap-2">
                <button
                  onClick={() => onRunInConsole(activeNode.remediationCmd)}
                  className="px-3.5 py-1.5 bg-rose-600 hover:bg-rose-500 text-white font-semibold rounded text-xs transition-colors flex items-center gap-1.5"
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Exécuter dans la Console</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Heatmap Legend */}
      <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-slate-800 text-[11px] text-slate-400 font-mono">
        <span className="font-semibold text-slate-300">Légende des Niveaux de Risque :</span>
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-rose-500 inline-block" />
            <span>Critique (80-100% · Kernel Lock / Rootkit)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-amber-500 inline-block" />
            <span>Élevé (60-79% · Persistance / C2)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-yellow-500 inline-block" />
            <span>Moyen (35-59% · Vulnérabilité Système)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500 inline-block" />
            <span>Nominal (&lt; 35% · Protégé)</span>
          </div>
        </div>
      </div>
    </div>
  );
};
