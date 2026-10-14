import React, { useState, useMemo } from 'react';
import {
  Layers,
  Info,
  Terminal,
  ExternalLink,
} from 'lucide-react';
import { TabId, ThreatItem } from '../types/cyberdefense';

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
  associatedThreatId?: string;
  targetTab?: TabId;
}

interface ThreatHeatmapProps {
  onRunInConsole: (command: string) => void;
  onNavigateTab?: (tab: TabId) => void;
  threats?: ThreatItem[];
}

export const ThreatHeatmap: React.FC<ThreatHeatmapProps> = ({
  onRunInConsole,
  onNavigateTab,
  threats = [],
}) => {
  const [selectedArea, setSelectedArea] = useState<string>('ALL');
  const [activeNode, setActiveNode] = useState<HeatmapNode | null>(null);

  // Dynamically map real threats into the heatmap matrix
  const heatmapNodes: HeatmapNode[] = useMemo(() => {
    const activeThreats = threats.filter(t => t.status === 'ACTIVE');

    // 1. KERNEL NODES
    const kernelDriverThreat = activeThreats.find(t =>
      t.category === 'Kernel' || t.category === 'Rootkit' || t.targetPath.toLowerCase().includes('.sys')
    );
    const bootDeleteThreat = activeThreats.find(t =>
      t.status === 'SCHEDULED_BOOT_DELETE' || t.trustedInstallerLocked
    );
    const vadMemoryThreat = activeThreats.find(t =>
      t.category === 'Memory' || t.targetPath.toLowerCase().includes('vad') || t.targetPath.toLowerCase().includes('lsass')
    );

    // 2. REGISTRY NODES
    const ifeoThreat = activeThreats.find(t =>
      t.category === 'Privilege' || t.targetPath.toLowerCase().includes('ifeo') || t.name.toLowerCase().includes('ifeo')
    );
    const wmiThreat = activeThreats.find(t =>
      t.mitreTechnique.includes('T1546.003') || t.targetPath.toLowerCase().includes('wmi') || t.targetPath.toLowerCase().includes('eventconsumer')
    );
    const runKeyThreat = activeThreats.find(t =>
      t.targetPath.toLowerCase().includes('\\run') || t.name.toLowerCase().includes('runonce')
    );

    // 3. STARTUP & SERVICES NODES
    const procThreat = activeThreats.find(t =>
      t.category === 'Trojan' || t.targetPath.toLowerCase().includes('pid:') || t.targetPath.toLowerCase().includes('.exe')
    );
    const bitsThreat = activeThreats.find(t =>
      t.category === 'Persistence' || t.mitreTechnique.includes('T1197') || t.targetPath.toLowerCase().includes('bits')
    );
    const defenderThreat = activeThreats.find(t =>
      t.category === 'Defender' || t.targetPath.toLowerCase().includes('defender') || t.targetPath.toLowerCase().includes('mppreference')
    );

    // 4. FILESYSTEM NODES
    const themesThreat = activeThreats.find(t =>
      t.targetPath.toLowerCase().includes('themes') || t.name.toLowerCase().includes('thèmes') || t.name.toLowerCase().includes('explorer.exe')
    );
    const adsThreat = activeThreats.find(t =>
      t.targetPath.toLowerCase().includes(':ads') || t.targetPath.toLowerCase().includes(':zone')
    );

    const baseNodes: HeatmapNode[] = [
      // 1. KERNEL & DRIVERS
      {
        id: 'k1',
        name: 'Pilotes Mini-Filter (fltmc) & Hooks IRP',
        area: 'Kernel',
        targetPath: kernelDriverThreat ? kernelDriverThreat.targetPath : 'C:\\Windows\\System32\\drivers\\fltmgr.sys',
        riskLevel: kernelDriverThreat ? 'CRITICAL' : 'NOMINAL',
        riskScore: kernelDriverThreat ? 95 : 10,
        mitreTechnique: kernelDriverThreat ? kernelDriverThreat.mitreTechnique : 'T1014 - Kernel Filter Inspection',
        statusText: kernelDriverThreat
          ? `[ANOMALIE ACTIVE] ${kernelDriverThreat.name} : ${kernelDriverThreat.description}`
          : 'Gestionnaire de filtres de système de fichiers Microsoft certifié et intègre',
        remediationCmd: kernelDriverThreat
          ? `unlock "${kernelDriverThreat.targetPath}"`
          : 'fltmc filters',
        associatedThreatId: kernelDriverThreat?.id,
        targetTab: 'deep-excision',
      },
      {
        id: 'k2',
        name: 'Session Manager Boot Delete (Ring 0)',
        area: 'Kernel',
        targetPath: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations',
        riskLevel: bootDeleteThreat ? 'HIGH' : 'NOMINAL',
        riskScore: bootDeleteThreat ? 75 : 8,
        mitreTechnique: 'T1547.001 - Boot / Logon Initialization',
        statusText: bootDeleteThreat
          ? `Suppression différée au redémarrage programmée sur : ${bootDeleteThreat.targetPath}`
          : 'Aucune suppression différée de pilote suspect en attente de redémarrage',
        remediationCmd: 'registry-audit',
        associatedThreatId: bootDeleteThreat?.id,
        targetTab: 'deep-excision',
      },
      {
        id: 'k3',
        name: 'Mémoire VAD & Injection Volatile',
        area: 'Kernel',
        targetPath: vadMemoryThreat ? vadMemoryThreat.targetPath : 'Descripteurs VAD (NtQueryVirtualMemory)',
        riskLevel: vadMemoryThreat ? 'CRITICAL' : 'NOMINAL',
        riskScore: vadMemoryThreat ? 92 : 12,
        mitreTechnique: vadMemoryThreat ? vadMemoryThreat.mitreTechnique : 'T1055.001 - Dynamic-link Library Injection',
        statusText: vadMemoryThreat
          ? `[INJECTION DÉTECTÉE] ${vadMemoryThreat.description}`
          : 'Mémoire virtuelle protégée, 0 injection RWX sans fichier sur disque',
        remediationCmd: 'dump-ram',
        associatedThreatId: vadMemoryThreat?.id,
        targetTab: 'forensics',
      },
      {
        id: 'k4',
        name: 'Intégrité SafeBoot Minimal & PatchGuard',
        area: 'Kernel',
        targetPath: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal',
        riskLevel: 'NOMINAL',
        riskScore: 10,
        mitreTechnique: 'T1562.001 - Disable Security Tools',
        statusText: 'Services de secours WinDefend & VSS déclarés dans SafeBoot',
        remediationCmd: 'safemode-prepare',
        targetTab: 'hardening',
      },

      // 2. REGISTRY & PERSISTANCE
      {
        id: 'r1',
        name: 'Détournements IFEO (Debugger Traps)',
        area: 'Registry',
        targetPath: ifeoThreat ? ifeoThreat.targetPath : 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options',
        riskLevel: ifeoThreat ? 'HIGH' : 'NOMINAL',
        riskScore: ifeoThreat ? 85 : 8,
        mitreTechnique: ifeoThreat ? ifeoThreat.mitreTechnique : 'T1546.012 - Image File Execution Options',
        statusText: ifeoThreat
          ? `[DÉTOURNEMENT ACTIF] ${ifeoThreat.description}`
          : 'Aucune clé Debugger malveillante sur Taskmgr ou Defender',
        remediationCmd: 'ifeo',
        associatedThreatId: ifeoThreat?.id,
        targetTab: 'hardening',
      },
      {
        id: 'r2',
        name: 'Abonnements WMI (root\\subscription)',
        area: 'Registry',
        targetPath: wmiThreat ? wmiThreat.targetPath : 'root\\subscription:__EventFilter & __EventConsumer',
        riskLevel: wmiThreat ? 'HIGH' : 'NOMINAL',
        riskScore: wmiThreat ? 80 : 12,
        mitreTechnique: wmiThreat ? wmiThreat.mitreTechnique : 'T1546.003 - WMI Event Subscription',
        statusText: wmiThreat
          ? `[PERSISTANCE WMI DÉTECTÉE] ${wmiThreat.description}`
          : 'Aucun filtre WMI persistant suspect détecté dans l\'espace de noms',
        remediationCmd: 'wmi-clean',
        associatedThreatId: wmiThreat?.id,
        targetTab: 'hardening',
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
        targetTab: 'hardening',
      },
      {
        id: 'r4',
        name: 'Clés Run & RunOnce (Autorun)',
        area: 'Registry',
        targetPath: runKeyThreat ? runKeyThreat.targetPath : 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        riskLevel: runKeyThreat ? 'HIGH' : 'NOMINAL',
        riskScore: runKeyThreat ? 78 : 14,
        mitreTechnique: 'T1547.001 - Registry Run Keys',
        statusText: runKeyThreat
          ? `[AUTORUN SUSPECT] ${runKeyThreat.description}`
          : 'Entrées de démarrage standard validées sans binaire masqué',
        remediationCmd: 'audit-persistence',
        associatedThreatId: runKeyThreat?.id,
        targetTab: 'hardening',
      },
      {
        id: 'r5',
        name: 'Clés de Persistance Winlogon',
        area: 'Registry',
        targetPath: 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit',
        riskLevel: 'NOMINAL',
        riskScore: 8,
        mitreTechnique: 'T1547.004 - Winlogon Helper DLL & Userinit',
        statusText: 'Chaîne Userinit et Shell standard conformes (userinit.exe)',
        remediationCmd: 'scan --deep',
        targetTab: 'hardening',
      },

      // 3. STARTUP & SERVICES
      {
        id: 's1',
        name: 'Surveillance des Processus & Watchdogs',
        area: 'Startup',
        targetPath: procThreat ? procThreat.targetPath : 'services.exe -> svchost.exe (Hiérarchie standard)',
        riskLevel: procThreat ? 'CRITICAL' : 'NOMINAL',
        riskScore: procThreat ? 94 : 10,
        mitreTechnique: procThreat ? procThreat.mitreTechnique : 'T1059 - Process Hierarchy Validation',
        statusText: procThreat
          ? `[PROCESSUS ACTIF] ${procThreat.name} : ${procThreat.description}`
          : 'Arborescence des processus système Windows conforme aux baselines',
        remediationCmd: procThreat ? `kill ${procThreat.targetPath.replace(/[^0-9]/g, '') || '3128'}` : 'tasklist',
        associatedThreatId: procThreat?.id,
        targetTab: 'task-manager',
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
        targetTab: 'task-manager',
      },
      {
        id: 's3',
        name: 'Tâches BITS d\'Exfiltration (T1197)',
        area: 'Startup',
        targetPath: bitsThreat ? bitsThreat.targetPath : 'bitsadmin /list /allusers',
        riskLevel: bitsThreat ? 'HIGH' : 'NOMINAL',
        riskScore: bitsThreat ? 88 : 15,
        mitreTechnique: bitsThreat ? bitsThreat.mitreTechnique : 'T1197 - BITS Jobs',
        statusText: bitsThreat
          ? `[TÂCHE BITS HOSTILE] ${bitsThreat.name} : ${bitsThreat.description}`
          : 'Transferts d\'arrière-plan BITS homologués Microsoft',
        remediationCmd: 'bitsadmin /cancel WindowsHealthUpdate',
        associatedThreatId: bitsThreat?.id,
        targetTab: 'bits',
      },
      {
        id: 's4',
        name: 'Protection Microsoft Defender (WinDefend)',
        area: 'Startup',
        targetPath: defenderThreat ? defenderThreat.targetPath : 'WinDefend / MpPreference',
        riskLevel: defenderThreat ? 'HIGH' : 'NOMINAL',
        riskScore: defenderThreat ? 82 : 10,
        mitreTechnique: 'T1562.001 - Disable Security Tools',
        statusText: defenderThreat
          ? `[ANOMALIE DEFENDER] ${defenderThreat.description}`
          : 'Protection en temps réel active et exclusions auditées',
        remediationCmd: 'defender-repair',
        associatedThreatId: defenderThreat?.id,
        targetTab: 'hardening',
      },

      // 4. FILESYSTEM & STOCKAGE
      {
        id: 'f1',
        name: 'Dossier Thèmes & Faux Explorer (Claude Protocol)',
        area: 'Filesystem',
        targetPath: themesThreat ? themesThreat.targetPath : 'C:\\Windows\\Resources\\Themes\\explorer.exe',
        riskLevel: themesThreat ? 'CRITICAL' : 'NOMINAL',
        riskScore: themesThreat ? 96 : 8,
        mitreTechnique: 'T1036.005 - Masquerading Audit',
        statusText: themesThreat
          ? `[MALWARE DÉTECTÉ] ${themesThreat.name} dans C:\\Windows\\Resources\\Themes`
          : 'Répertoire Themes intègre : seuls les thèmes Windows aero officiels sont présents',
        remediationCmd: 'clean-themes',
        associatedThreatId: themesThreat?.id,
        targetTab: 'themes-hunter',
      },
      {
        id: 'f2',
        name: 'Flux Cachés NTFS (Alternate Data Streams)',
        area: 'Filesystem',
        targetPath: adsThreat ? adsThreat.targetPath : '%USERPROFILE%\\Desktop & %TEMP% (:Zone.Identifier)',
        riskLevel: adsThreat ? 'HIGH' : 'NOMINAL',
        riskScore: adsThreat ? 70 : 10,
        mitreTechnique: 'T1564.004 - NTFS File Attributes: Alternate Data Streams',
        statusText: adsThreat
          ? `[FLUX ADS HOSTILE] ${adsThreat.description}`
          : 'Aucun exécutable masqué en flux de données alternatif',
        remediationCmd: 'scan --deep',
        associatedThreatId: adsThreat?.id,
        targetTab: 'deep-detection',
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
        targetTab: 'deep-detection',
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
        targetTab: 'deep-detection',
      },
    ];

    // Append any active threat from live threats state not already represented
    const existingAssociatedIds = new Set(baseNodes.map(n => n.associatedThreatId).filter(Boolean));
    activeThreats.forEach(t => {
      if (!existingAssociatedIds.has(t.id)) {
        let area: SystemArea = 'Filesystem';
        if (t.category === 'Kernel' || t.category === 'Rootkit' || t.category === 'Memory' || t.targetPath.includes('.sys')) {
          area = 'Kernel';
        } else if (t.category === 'Privilege' || t.mitreTechnique.includes('T1546') || t.targetPath.includes('HKLM') || t.targetPath.includes('HKCU')) {
          area = 'Registry';
        } else if (t.category === 'Persistence' || t.category === 'Defender' || t.targetPath.includes('bits') || t.targetPath.includes('PID')) {
          area = 'Startup';
        }

        const riskLevel: RiskLevel = t.severity === 'CRITICAL' ? 'CRITICAL' : t.severity === 'HIGH' ? 'HIGH' : 'MEDIUM';
        const riskScore = t.severity === 'CRITICAL' ? 95 : t.severity === 'HIGH' ? 82 : 65;

        baseNodes.push({
          id: `threat-node-${t.id}`,
          name: t.name,
          area,
          targetPath: t.targetPath,
          riskLevel,
          riskScore,
          mitreTechnique: t.mitreTechnique,
          statusText: `[MENACE ACTIVE] ${t.description}`,
          remediationCmd: t.targetPath.includes('Themes')
            ? 'clean-themes'
            : t.trustedInstallerLocked
            ? `unlock "${t.targetPath}"`
            : `scan --deep`,
          associatedThreatId: t.id,
          targetTab: t.trustedInstallerLocked ? 'deep-excision' : 'overview',
        });
      }
    });

    return baseNodes;
  }, [threats]);

  const filteredNodes = selectedArea === 'ALL'
    ? heatmapNodes
    : heatmapNodes.filter(n => n.area === selectedArea);

  // Compute aggregated scores per area dynamically
  const areasList: SystemArea[] = ['Kernel', 'Registry', 'Startup', 'Filesystem'];
  const getAreaScore = (area: SystemArea) => {
    const nodes = heatmapNodes.filter(n => n.area === area);
    if (nodes.length === 0) return 0;
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
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800/60">
              Synchronisée en Temps Réel
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Visualiseur matriciel dynamique des surfaces d'attaque Windows (Noyau, Registre, Démarrage, Fichiers). Les cellules reflètent immédiatement les menaces réelles détectées par les scans.
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
          const isCritical = score >= 75;
          const isHigh = score >= 50 && score < 75;
          const isMed = score >= 25 && score < 50;

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
                  className={`h-full rounded-full transition-all duration-500 ${
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
                <span className="text-slate-400 truncate max-w-[140px]" title={node.mitreTechnique}>
                  {node.mitreTechnique.split(' - ')[0]}
                </span>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    if (node.targetTab && onNavigateTab && node.riskLevel !== 'NOMINAL') {
                      onNavigateTab(node.targetTab);
                    } else {
                      onRunInConsole(node.remediationCmd);
                    }
                  }}
                  className="text-cyan-300 hover:text-white font-semibold underline text-[11px] transition-colors"
                >
                  {node.riskLevel !== 'NOMINAL' ? 'Inspecter / Corriger' : 'Auditer'}
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

              <div className="mt-3 flex flex-wrap items-center gap-2">
                <button
                  onClick={() => onRunInConsole(activeNode.remediationCmd)}
                  className="px-3.5 py-1.5 bg-rose-600 hover:bg-rose-500 text-white font-semibold rounded text-xs transition-colors flex items-center gap-1.5"
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Exécuter dans la Console</span>
                </button>

                {activeNode.targetTab && onNavigateTab && (
                  <button
                    onClick={() => onNavigateTab(activeNode.targetTab!)}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded text-xs transition-colors flex items-center gap-1"
                  >
                    <span>Ouvrir l'onglet dédié</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                )}
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
            <span>Critique (75-100% · Menace Réelle Détectée)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-amber-500 inline-block" />
            <span>Élevé (50-74% · Persistance / Alerte)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-yellow-500 inline-block" />
            <span>Moyen (25-49% · Surveillance Requise)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500 inline-block" />
            <span>Nominal (&lt; 25% · Protégé & Intègre)</span>
          </div>
        </div>
      </div>
    </div>
  );
};
