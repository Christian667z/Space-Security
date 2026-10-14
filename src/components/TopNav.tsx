import React, { useState, useRef, useEffect } from 'react';
import {
  Shield,
  Terminal,
  Download,
  Cpu,
  Activity,
  Network,
  Server,
  Lock,
  FileCode,
  Archive,
  Clock,
  Radio,
  LayoutGrid,
  ChevronDown,
  Zap,
  Search,
  X,
  CheckCircle2,
  ArrowRight,
  FileText,
  Binary,
  Users,
  Globe,
  Wifi,
  WifiOff,
  Wrench,
  ShieldAlert,
  Flame,
  Keyboard,
  MoreHorizontal,
} from 'lucide-react';
import { TabId } from '../types/cyberdefense';

interface TopNavProps {
  activeTab: TabId;
  onSelectTab: (tab: TabId) => void;
  onDownloadScript: () => void;
  onDownloadZip: () => void;
  onOpenPdfReport: () => void;
  activeUsersCount?: number;
  connectionStatus?: 'connected' | 'connecting' | 'disconnected';
  onOpenCollabModal?: () => void;
  onRunInConsole?: (command: string) => void;
  onOpenShortcutsModal?: () => void;
}

interface NavItem {
  id: TabId;
  title: string;
  category: string;
  shortDesc: string;
  icon: React.ComponentType<{ className?: string }>;
  tag: string;
  tagClass: string;
  mitre?: string;
}

interface NavColumn {
  title: string;
  subtitle: string;
  badge: string;
  badgeClass: string;
  icon: React.ComponentType<{ className?: string }>;
  items: NavItem[];
}

export const TopNav: React.FC<TopNavProps> = ({
  activeTab,
  onSelectTab,
  onDownloadScript,
  onDownloadZip,
  onOpenPdfReport,
  activeUsersCount = 1,
  connectionStatus = 'connected',
  onOpenCollabModal,
  onRunInConsole,
  onOpenShortcutsModal,
}) => {
  const [isMegaMenuOpen, setIsMegaMenuOpen] = useState(false);
  const [isMoreMenuOpen, setIsMoreMenuOpen] = useState(false);
  const [searchFilter, setSearchFilter] = useState('');
  const megaMenuRef = useRef<HTMLDivElement>(null);
  const triggerButtonRef = useRef<HTMLButtonElement>(null);
  const moreMenuRef = useRef<HTMLDivElement>(null);
  const moreButtonRef = useRef<HTMLButtonElement>(null);

  // Close menus on Click Outside or Escape key
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent | TouchEvent) => {
      const target = event.target as Node;
      if (
        megaMenuRef.current &&
        !megaMenuRef.current.contains(target) &&
        triggerButtonRef.current &&
        !triggerButtonRef.current.contains(target)
      ) {
        setIsMegaMenuOpen(false);
      }
      if (
        moreMenuRef.current &&
        !moreMenuRef.current.contains(target) &&
        moreButtonRef.current &&
        !moreButtonRef.current.contains(target)
      ) {
        setIsMoreMenuOpen(false);
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsMegaMenuOpen(false);
        setIsMoreMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('touchstart', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('touchstart', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  // Two columns navigation structure for the Mega Menu
  const columns: NavColumn[] = [
    {
      title: 'SUPERVISION & PROCESSUS SYSTÈME',
      subtitle: "Télémétrie continue, analyse des tâches & flux d'événements",
      badge: 'SURVEILLANCE',
      badgeClass: 'text-cyan-400 bg-cyan-950/80 border-cyan-800/60',
      icon: Activity,
      items: [
        {
          id: 'overview',
          title: 'Vue Centrale',
          category: 'Télémétrie Globale',
          shortDesc: 'Tableau de bord de sécurité, indicateurs CPU/RAM, posture globale & alertes.',
          icon: Activity,
          tag: 'TEMPS RÉEL',
          tagClass: 'text-cyan-400 bg-cyan-950/70 border-cyan-800/50',
        },
        {
          id: 'edr-fleet',
          title: 'Flotte EDR & Agents',
          category: 'Supervision Multi-Postes',
          shortDesc: 'Gestion centralisée du parc de machines distantes, ingestion télémétrie & ordres EDR.',
          icon: Server,
          tag: 'SOC ENTERPRISE',
          tagClass: 'text-indigo-400 bg-indigo-950/70 border-indigo-800/50',
        },
        {
          id: 'task-manager',
          title: 'Gestionnaire des Tâches',
          category: 'Inspection Processus',
          shortDesc: 'Arborescence des PID, détection DLL masquées, threads injectés & conso RAM.',
          icon: Cpu,
          tag: 'MONITORING',
          tagClass: 'text-blue-400 bg-blue-950/70 border-blue-800/50',
        },
        {
          id: 'bits',
          title: 'BITS Task Manager',
          category: 'Persistance T1197',
          shortDesc: 'Audit & éradication des jobs BITS furtifs (svchost/netsvcs, C2 stage2 & exfil).',
          icon: Radio,
          tag: 'T1197 C2',
          tagClass: 'text-amber-400 bg-amber-950/70 border-amber-800/50',
        },
        {
          id: 'timeline',
          title: 'Chronologie Menaces',
          category: 'Corrélation MITRE',
          shortDesc: 'Journal temporel des alertes, cycle de détection, confinement et remédiation.',
          icon: Clock,
          tag: 'TIMELINE',
          tagClass: 'text-indigo-400 bg-indigo-950/70 border-indigo-800/50',
        },
        {
          id: 'heuristic',
          title: 'Moteur Heuristique',
          category: 'Entropie & API Hooks',
          shortDesc: "Scoring temps réel de l'entropie de Shannon et interception des crochets API suspects.",
          icon: Binary,
          tag: 'HEURISTIQUE',
          tagClass: 'text-amber-400 bg-amber-950/70 border-amber-800/50',
        },
        {
          id: 'console',
          title: 'Console Live',
          category: 'Shell Interactif',
          shortDesc: 'CLI cyberdéfense avec suggestions rapides, analyse de dumps & contre-mesures.',
          icon: Terminal,
          tag: 'INTERACTIF',
          tagClass: 'text-emerald-400 bg-emerald-950/70 border-emerald-800/50',
        },
      ],
    },
    {
      title: 'ÉRADICATION KERNEL & FORENSIQUE',
      subtitle: "Contre-mesures ring0, introspection mémoire & politiques d'isolement",
      badge: 'CONTRE-MESURES',
      badgeClass: 'text-rose-400 bg-rose-950/80 border-rose-800/60',
      icon: Zap,
      items: [
        {
          id: 'deep-excision',
          title: 'Éradication OS & Kernel',
          category: 'Ring0 & Fichiers Verrouillés',
          shortDesc: 'Déchargement de drivers rootkits, purge IFEO, TrustedInstaller & ADS cachés.',
          icon: Zap,
          tag: 'RING 0',
          tagClass: 'text-rose-400 bg-rose-950/70 border-rose-800/50',
        },
        {
          id: 'themes-hunter',
          title: 'Chasseur Thèmes (Rogue Explorer)',
          category: 'Cas Forensique Réel',
          shortDesc: 'Nettoyage des faux explorer.exe & icsys dans Resources\\Themes, bypass TrustedInstaller & Defender CFA.',
          icon: Flame,
          tag: 'CAS RÉEL',
          tagClass: 'text-rose-400 bg-rose-950/70 border-rose-800/50',
        },
        {
          id: 'deep-detection',
          title: 'Détection Profonde (Menus 10-14)',
          category: 'Menus 10 à 14',
          shortDesc: 'Usurpation de processus, processus cachés brute-force PID, quarantaine restaurable & règles ASR.',
          icon: ShieldAlert,
          tag: 'MENUS 10-14',
          tagClass: 'text-cyan-400 bg-cyan-950/70 border-cyan-800/50',
        },
        {
          id: 'sandbox-isolation',
          title: 'Isolateur & Bac à Sable (Sandbox Live)',
          category: 'Kill-Switch Réseau & Confinement',
          shortDesc: "Coupure d'urgence Wi-Fi/Ethernet (netsh/WMI), conservation 127.0.0.1 et bac à sable de processus.",
          icon: WifiOff,
          tag: 'KILL-SWITCH',
          tagClass: 'text-rose-400 bg-rose-950/70 border-rose-800/50',
        },
        {
          id: 'forensics',
          title: 'Forensique RAM',
          category: 'Mémoire Volatile',
          shortDesc: 'Détection Process Hollowing, modules non signés et analyse mémoire dynamique.',
          icon: Shield,
          tag: 'MÉMOIRE',
          tagClass: 'text-purple-400 bg-purple-950/70 border-purple-800/50',
        },
        {
          id: 'network',
          title: 'Scan Réseau (Sockets & C2)',
          category: 'Trafic Sortant & Sockets',
          shortDesc: "Audit des sockets actifs, détection des balises C2 persistantes, ports d'écoute & flux hostiles.",
          icon: Network,
          tag: 'SCAN RÉSEAU',
          tagClass: 'text-cyan-400 bg-cyan-950/70 border-cyan-800/50',
        },
        {
          id: 'wifi',
          title: 'Scan WiFi (BSSID)',
          category: 'Audit Réseaux Sans-Fil',
          shortDesc: "Scan des bornes 802.11 environnantes, détection Evil Twin, trames Deauth & points d'accès ouverts.",
          icon: Wifi,
          tag: 'SCAN WIFI',
          tagClass: 'text-indigo-400 bg-indigo-950/70 border-indigo-800/50',
        },
        {
          id: 'remediation',
          title: 'Restauration Post-Infection',
          category: 'Déblocage GPO & Fichier HOSTS',
          shortDesc: 'Déblocage Taskmgr, Regedit, CMD après attaque virale, assainissement du fichier HOSTS et flush DNS.',
          icon: Wrench,
          tag: 'RESTAURATION GPO',
          tagClass: 'text-amber-400 bg-amber-950/70 border-amber-800/50',
        },
        {
          id: 'hardening',
          title: 'Durcissement OS',
          category: 'GPO & Protection Hôte',
          shortDesc: 'Audit des exclusions Defender, verrouillage des ports & isolation du système.',
          icon: Lock,
          tag: 'HARDENING',
          tagClass: 'text-emerald-400 bg-emerald-950/70 border-emerald-800/50',
        },
        {
          id: 'script-hub',
          title: 'Script PowerShell (.ps1)',
          category: 'Automatisation & Scripts',
          shortDesc: "Script SpaceSecurity_ULTRA_v3_Kernel.ps1, lanceurs batch élévateurs & guides d'intervention.",
          icon: FileCode,
          tag: 'SCRIPT PS1',
          tagClass: 'text-amber-400 bg-amber-950/70 border-amber-800/50',
        },
        {
          id: 'ip-locator',
          title: 'Géolocalisation & Traçeur IP',
          category: 'Localisation Précise & C2',
          shortDesc: 'Localiser le pays, la ville, la zone, coordonnées GPS, FAI & C2 pour toute IP.',
          icon: Globe,
          tag: 'GÉO-TRACKER',
          tagClass: 'text-sky-400 bg-sky-950/70 border-sky-800/50',
        },
      ],
    },
  ];

  const allItems = columns.flatMap((col) => col.items);

  // Filter items based on search query
  const query = searchFilter.toLowerCase().trim();
  const filterItem = (item: NavItem) => {
    if (!query) return true;
    return (
      item.title.toLowerCase().includes(query) ||
      item.shortDesc.toLowerCase().includes(query) ||
      item.category.toLowerCase().includes(query) ||
      item.tag.toLowerCase().includes(query)
    );
  };

  const handleSelectTab = (tab: TabId) => {
    onSelectTab(tab);
    setIsMegaMenuOpen(false);
    setIsMoreMenuOpen(false);
    setSearchFilter('');
  };

  // Center Zone: 5 primary navigation tabs
  const centerTabs: Array<{
    id: TabId;
    title: string;
    icon: React.ComponentType<{ className?: string }>;
    accentColor: string;
  }> = [
    { id: 'overview', title: 'Vue Centrale', icon: Activity, accentColor: 'text-cyan-400' },
    { id: 'edr-fleet', title: 'Flotte EDR', icon: Server, accentColor: 'text-indigo-400' },
    { id: 'task-manager', title: 'Gestionnaire', icon: Cpu, accentColor: 'text-blue-400' },
    { id: 'console', title: 'Console', icon: Terminal, accentColor: 'text-emerald-400' },
    { id: 'ip-locator', title: 'Traceur IP', icon: Globe, accentColor: 'text-sky-400' },
  ];

  return (
    <header className="sticky top-0 z-50 w-full max-w-[100vw] h-16 max-h-16 bg-[#030712] border-b border-slate-800/90 shadow-md select-none overflow-x-hidden flex items-center">
      <div className="w-full max-w-7xl mx-auto h-full px-2 sm:px-4 lg:px-6 flex items-center justify-between gap-2 flex-nowrap overflow-x-hidden">
        
        {/* ========================================================================= */}
        {/* ZONE 1 (GAUCHE) : Logo + Badge KERNEL V3.0 + Statut PROTECTION ACTIVE     */}
        {/* ========================================================================= */}
        <div className="flex items-center gap-2 sm:gap-2.5 shrink-0 flex-nowrap">
          <div
            onClick={() => handleSelectTab('overview')}
            className="flex items-center gap-2 sm:gap-2.5 cursor-pointer text-slate-100 group select-none"
            title="Retour à la Vue Centrale"
          >
            <div className="w-9 h-9 rounded-lg bg-cyan-950/90 border border-cyan-800/90 flex items-center justify-center text-cyan-400 group-hover:border-cyan-400 group-hover:shadow-xs group-hover:shadow-cyan-500/30 transition-all shrink-0">
              <Shield className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="flex flex-col justify-center">
              <div className="flex items-center gap-1.5 leading-tight flex-nowrap">
                <span className="text-sm sm:text-base font-bold tracking-tight text-white font-['Plus_Jakarta_Sans'] whitespace-nowrap">
                  Space Security
                </span>
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-cyan-950/90 text-cyan-300 border border-cyan-800/80 whitespace-nowrap">
                  KERNEL V3.0
                </span>
              </div>
              <div className="flex items-center gap-1.5 text-[10px] text-slate-400 leading-tight mt-0.5 flex-nowrap">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse shrink-0"></span>
                <span className="font-mono text-emerald-400 font-semibold tracking-wide whitespace-nowrap">
                  PROTECTION ACTIVE
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* ZONE 2 (CENTRE) : 4 Onglets Max avec min-w-0 et overflow-x: auto caché   */}
        {/* Responsive : Sous 1100px, seules les icônes restent visibles              */}
        {/* ========================================================================= */}
        <nav
          aria-label="Navigation principale"
          className="flex items-center justify-center gap-1 sm:gap-1.5 min-w-0 flex-1 overflow-x-auto no-scrollbar [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden flex-nowrap"
        >
          {centerTabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;

            return (
              <button
                key={tab.id}
                onClick={() => handleSelectTab(tab.id)}
                title={tab.title}
                className={`h-9 px-2 sm:px-2.5 min-[1100px]:px-3.5 rounded-lg text-xs font-medium whitespace-nowrap flex items-center justify-center gap-1.5 transition-all border shrink-0 cursor-pointer ${
                  isActive
                    ? 'bg-cyan-950/80 text-cyan-300 border-cyan-600/80 shadow-xs shadow-cyan-950/50 font-semibold'
                    : 'bg-slate-900/60 hover:bg-slate-800 text-slate-300 hover:text-white border-transparent hover:border-slate-700/60'
                }`}
              >
                <Icon className={`w-4 h-4 shrink-0 ${tab.accentColor}`} />
                <span className="hidden min-[1100px]:inline whitespace-nowrap">
                  {tab.title}
                </span>
              </button>
            );
          })}
        </nav>

        {/* ========================================================================= */}
        {/* ZONE 3 (DROITE) : Synchro, Kill-Switch, Archive ZIP & Modules & Outils    */}
        {/* Sous 1400px : Icônes seules (texte avec "hidden xl:inline")              */}
        {/* ========================================================================= */}
        <div className="flex items-center gap-1.5 sm:gap-2 shrink-0 flex-nowrap">
          {/* Bouton Synchro */}
          <button
            onClick={onOpenCollabModal}
            title="Centre d'Opérations Multi-Opérateurs : Cliquez pour auditer la synchronisation"
            className={`h-9 px-2.5 sm:px-3 rounded-lg text-xs font-mono font-medium transition-all border flex items-center justify-center gap-1.5 shrink-0 whitespace-nowrap cursor-pointer shadow-xs ${
              connectionStatus === 'connected'
                ? 'bg-emerald-950/60 hover:bg-emerald-950/90 text-emerald-300 border-emerald-800/80 hover:border-emerald-600'
                : 'bg-amber-950/60 hover:bg-amber-950/90 text-amber-300 border-amber-800/80 hover:border-amber-600'
            }`}
          >
            <span className="relative flex h-2 w-2 shrink-0">
              {connectionStatus === 'connected' && (
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              )}
              <span
                className={`relative inline-flex rounded-full h-2 w-2 ${
                  connectionStatus === 'connected' ? 'bg-emerald-400' : 'bg-amber-400'
                }`}
              ></span>
            </span>
            <span className="font-semibold tracking-wide whitespace-nowrap hidden xl:inline">
              {connectionStatus === 'connected'
                ? activeUsersCount > 1
                  ? `${activeUsersCount} Analystes`
                  : 'Synchro Live'
                : 'Synchro En Cours'}
            </span>
            <Users className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
          </button>

          {/* Bouton Kill-Switch Réseau */}
          <button
            onClick={() => onSelectTab('sandbox-isolation')}
            title="Kill-Switch Réseau d'Urgence : Couper le trafic sortant/entrant tout en maintenant localhost"
            className="h-9 px-2.5 sm:px-3 rounded-lg text-xs font-mono font-bold transition-all border shadow-xs bg-rose-950/50 hover:bg-rose-900/70 text-rose-300 border-rose-800/80 hover:border-rose-500 flex items-center justify-center gap-1.5 shrink-0 whitespace-nowrap cursor-pointer"
          >
            <WifiOff className="w-3.5 h-3.5 text-rose-400 shrink-0" />
            <span className="hidden xl:inline whitespace-nowrap">Kill-Switch</span>
          </button>

          {/* Bouton Télécharger Archive ZIP (Direct sous xl / >= 1400px avec texte, icône sous 1400px) */}
          <button
            onClick={onDownloadZip}
            title="Télécharger l'Archive ZIP complète Space Security (scripts, modules, exécutables)"
            className="h-9 px-2.5 sm:px-3 rounded-lg text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 transition-all shadow-xs flex items-center justify-center gap-1.5 shrink-0 whitespace-nowrap cursor-pointer"
          >
            <Archive className="w-3.5 h-3.5 shrink-0" />
            <span className="hidden xl:inline whitespace-nowrap">Archive ZIP</span>
          </button>

          {/* Menu "..." Actions Rapides (Rapport PDF, Script PS1, Raccourcis) */}
          <div className="relative">
            <button
              ref={moreButtonRef}
              onClick={() => setIsMoreMenuOpen(!isMoreMenuOpen)}
              aria-expanded={isMoreMenuOpen}
              aria-haspopup="true"
              title="Actions rapides & Téléchargements"
              className={`h-9 w-8 sm:w-9 rounded-lg text-xs font-semibold transition-all border flex items-center justify-center shrink-0 cursor-pointer ${
                isMoreMenuOpen
                  ? 'bg-slate-800 text-cyan-300 border-cyan-500 shadow-xs'
                  : 'bg-slate-900/80 hover:bg-slate-800 text-slate-300 hover:text-white border-slate-700/80'
              }`}
            >
              <MoreHorizontal className="w-4 h-4 shrink-0" />
            </button>

            {/* Popup Menu "..." */}
            {isMoreMenuOpen && (
              <div
                ref={moreMenuRef}
                className="absolute right-0 top-full mt-1.5 w-56 bg-[#0c1222] border border-cyan-800/80 rounded-xl shadow-2xl shadow-black z-[100] py-2 animate-in fade-in zoom-in-95 duration-100"
              >
                <div className="px-3 py-1.5 border-b border-slate-800 text-[10px] font-mono uppercase tracking-wider text-slate-400 font-bold">
                  Outils & Téléchargements
                </div>
                <button
                  onClick={() => {
                    onDownloadZip();
                    setIsMoreMenuOpen(false);
                  }}
                  className="w-full text-left px-3 py-2 text-xs text-slate-200 hover:text-cyan-300 hover:bg-slate-800/80 flex items-center gap-2 cursor-pointer transition-colors"
                >
                  <Archive className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  <span>Télécharger Archive ZIP</span>
                </button>
                <button
                  onClick={() => {
                    onOpenPdfReport();
                    setIsMoreMenuOpen(false);
                  }}
                  className="w-full text-left px-3 py-2 text-xs text-slate-200 hover:text-rose-300 hover:bg-slate-800/80 flex items-center gap-2 cursor-pointer transition-colors"
                >
                  <FileText className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                  <span>Générer Rapport PDF</span>
                </button>
                <button
                  onClick={() => {
                    onDownloadScript();
                    setIsMoreMenuOpen(false);
                  }}
                  className="w-full text-left px-3 py-2 text-xs text-slate-200 hover:text-amber-300 hover:bg-slate-800/80 flex items-center gap-2 cursor-pointer transition-colors"
                >
                  <Download className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                  <span>Script PowerShell (.ps1)</span>
                </button>
                <div className="border-t border-slate-800 my-1"></div>
                <button
                  onClick={() => {
                    onOpenShortcutsModal?.();
                    setIsMoreMenuOpen(false);
                  }}
                  className="w-full text-left px-3 py-2 text-xs text-slate-300 hover:text-cyan-300 hover:bg-slate-800/80 flex items-center gap-2 cursor-pointer transition-colors"
                >
                  <Keyboard className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  <span>Raccourcis Clavier (?)</span>
                </button>
              </div>
            )}
          </div>

          {/* Bouton Menu Déroulant "Modules & Outils" */}
          <button
            ref={triggerButtonRef}
            onClick={() => setIsMegaMenuOpen(!isMegaMenuOpen)}
            aria-expanded={isMegaMenuOpen}
            aria-haspopup="true"
            title="Ouvrir le catalogue complet des 19 modules de cyberdéfense"
            className={`h-9 px-2.5 sm:px-3 rounded-lg text-xs font-semibold transition-all border flex items-center justify-center gap-1.5 shrink-0 whitespace-nowrap cursor-pointer ${
              isMegaMenuOpen
                ? 'bg-cyan-950 text-cyan-300 border-cyan-500 shadow-sm shadow-cyan-950/60'
                : 'bg-slate-900 hover:bg-slate-800 text-slate-100 border-slate-700/80 hover:border-cyan-600/70 shadow-xs'
            }`}
          >
            <LayoutGrid className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span className="whitespace-nowrap hidden sm:inline">Modules & Outils</span>
            <span className="px-1.5 py-0.2 font-mono text-[10px] rounded bg-slate-800 text-slate-300 border border-slate-700 shrink-0">
              {allItems.length}
            </span>
            <ChevronDown
              className={`w-3.5 h-3.5 text-slate-400 transition-transform duration-200 shrink-0 ${
                isMegaMenuOpen ? 'rotate-180 text-cyan-400' : ''
              }`}
            />
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* PANNEAU DÉROULANT COMPLET : FOND OPAQUE + BACKDROP BLUR + Z-INDEX FORT    */}
      {/* ========================================================================= */}
      {isMegaMenuOpen && (
        <>
          {/* Backdrop sombre opaque avec fort flou d'arrière-plan */}
          <div
            className="fixed inset-0 top-16 bg-black/85 backdrop-blur-md z-[80] transition-opacity"
            onClick={() => setIsMegaMenuOpen(false)}
            aria-hidden="true"
          />

          {/* Conteneur du menu déroulant 100% opaque pour éliminer toute transparence */}
          <div
            ref={megaMenuRef}
            role="dialog"
            aria-modal="true"
            aria-label="Centre de Contrôle & Navigation"
            className="fixed top-16 left-0 right-0 z-[90] bg-[#020617] border-b border-cyan-800/80 shadow-2xl shadow-black max-h-[calc(100vh-4rem)] max-h-[calc(100dvh-4rem)] overflow-y-auto overscroll-contain animate-in fade-in slide-in-from-top-2 duration-150"
            style={{
              WebkitOverflowScrolling: 'touch',
            }}
          >
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 pb-16">
              
              {/* Header du Menu Déroulant : Titre & Filtre de Recherche */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 mb-5 border-b border-slate-800">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 shrink-0">
                    <LayoutGrid className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white tracking-wide uppercase font-mono flex items-center gap-2">
                      Centre de Contrôle & Navigation Space Security
                      <span className="text-[10px] text-cyan-400 font-mono font-normal px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800">
                        Catalogue 19 Moteurs
                      </span>
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Sélectionnez un module spécialisé pour lancer l'analyse, l'éradication ou l'isolation mémoire.
                    </p>
                  </div>
                </div>

                {/* Barre de recherche de modules */}
                <div className="flex items-center gap-2 w-full sm:w-80">
                  <div className="relative w-full">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={searchFilter}
                      onChange={(e) => setSearchFilter(e.target.value)}
                      placeholder="Filtrer un module (ex: BITS, RAM, C2)..."
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-8 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono transition-colors"
                      autoFocus
                    />
                    {searchFilter && (
                      <button
                        onClick={() => setSearchFilter('')}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                        title="Effacer le filtre"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                  <button
                    onClick={() => setIsMegaMenuOpen(false)}
                    className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg border border-slate-800 transition-colors shrink-0"
                    title="Fermer le menu [Échap]"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Accès Rapide Scanners Réseau & Wi-Fi (BSSID) */}
              <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3.5 mb-6 bg-slate-900/90 border border-cyan-800/80 rounded-xl shadow-lg">
                <div className="flex items-center gap-3">
                  <span className="relative flex h-2.5 w-2.5 shrink-0">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-400"></span>
                  </span>
                  <div>
                    <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                      Scanners Réseau & Sans-Fil Haute Précision
                    </h4>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      Audit instantané des sockets, ports d'écoute, détection des balises C2 & analyse des bornes Wi-Fi BSSID environnantes.
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2.5 shrink-0 w-full sm:w-auto justify-end">
                  <button
                    onClick={() => {
                      handleSelectTab('network');
                      onRunInConsole?.('sockets');
                    }}
                    className="flex-1 sm:flex-none px-3.5 py-2 bg-cyan-950/90 hover:bg-cyan-900 text-cyan-200 hover:text-white border border-cyan-600 hover:border-cyan-400 rounded-lg font-bold text-xs transition-all flex items-center justify-center gap-2 shadow-xs cursor-pointer whitespace-nowrap"
                    title="Ouvrir le module Scan Réseau et auditer les sockets"
                  >
                    <Network className="w-4 h-4 text-cyan-400 shrink-0" />
                    <span>Scan Réseau</span>
                  </button>

                  <button
                    onClick={() => {
                      handleSelectTab('wifi');
                      onRunInConsole?.('netsh wlan show networks mode=bssid');
                    }}
                    className="flex-1 sm:flex-none px-3.5 py-2 bg-indigo-950/90 hover:bg-indigo-900 text-indigo-200 hover:text-white border border-indigo-600 hover:border-indigo-400 rounded-lg font-bold text-xs transition-all flex items-center justify-center gap-2 shadow-xs cursor-pointer whitespace-nowrap"
                    title="Ouvrir le module Scan WiFi (BSSID) et auditer les réseaux sans-fil"
                  >
                    <Wifi className="w-4 h-4 text-indigo-400 shrink-0" />
                    <span>Scan WiFi (BSSID)</span>
                  </button>
                </div>
              </div>

              {/* Grille 2 Colonnes Structurée */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 lg:gap-8">
                {columns.map((col) => {
                  const filteredItems = col.items.filter(filterItem);
                  const ColIcon = col.icon;

                  return (
                    <div
                      key={col.title}
                      className="flex flex-col space-y-3 bg-[#0c1222] p-4 rounded-xl border border-slate-800"
                    >
                      {/* En-tête de Colonne */}
                      <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                        <div className="flex items-center gap-2">
                          <ColIcon className="w-4 h-4 text-cyan-400" />
                          <h4 className="text-xs font-bold tracking-wider text-slate-200 font-mono">
                            {col.title}
                          </h4>
                        </div>
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${col.badgeClass}`}>
                          {col.badge}
                        </span>
                      </div>

                      <p className="text-[11px] text-slate-400 italic">
                        {col.subtitle}
                      </p>

                      {/* Éléments de la Colonne */}
                      <div className="space-y-2 pt-1">
                        {filteredItems.length === 0 ? (
                          <div className="py-6 text-center text-xs text-slate-500 font-mono">
                            Aucun module correspondant dans cette colonne
                          </div>
                        ) : (
                          filteredItems.map((item) => {
                            const ItemIcon = item.icon;
                            const isActive = activeTab === item.id;

                            return (
                              <button
                                key={item.id}
                                onClick={() => handleSelectTab(item.id)}
                                className={`w-full text-left p-3 rounded-lg border transition-all group flex items-start gap-3 relative cursor-pointer ${
                                  isActive
                                    ? 'bg-cyan-950/80 border-cyan-500 shadow-sm shadow-cyan-950/50'
                                    : 'bg-[#10172a] border-slate-800 hover:border-slate-600 hover:bg-[#162038]'
                                }`}
                              >
                                {/* Boîte d'icône */}
                                <div
                                  className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border transition-colors ${
                                    isActive
                                      ? 'bg-cyan-900 border-cyan-400 text-cyan-300'
                                      : 'bg-slate-900 border-slate-800 text-slate-400 group-hover:text-cyan-400 group-hover:border-cyan-700'
                                  }`}
                                >
                                  <ItemIcon className="w-4 h-4" />
                                </div>

                                {/* Titre, Badge & Description */}
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center justify-between gap-2 mb-1">
                                    <span
                                      className={`text-xs font-semibold tracking-tight transition-colors truncate ${
                                        isActive
                                          ? 'text-cyan-300 font-bold'
                                          : 'text-slate-200 group-hover:text-white'
                                      }`}
                                    >
                                      {item.title}
                                    </span>

                                    <div className="flex items-center gap-1.5 shrink-0">
                                      <span
                                        className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${item.tagClass}`}
                                      >
                                        {item.tag}
                                      </span>
                                      {item.id === 'script-hub' && (
                                        <span
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            onDownloadScript();
                                          }}
                                          title="Télécharger directement le script SpaceSecurity_ULTRA_v3_Kernel.ps1"
                                          className="text-[9px] font-mono font-bold text-amber-300 hover:text-white bg-amber-950 hover:bg-amber-900 border border-amber-700 px-1.5 py-0.5 rounded flex items-center gap-1 cursor-pointer transition-colors"
                                        >
                                          <Download className="w-2.5 h-2.5" />
                                          .ps1
                                        </span>
                                      )}
                                      {isActive && (
                                        <span className="text-[9px] font-mono font-bold text-cyan-400 bg-cyan-950 border border-cyan-700 px-1 py-0.5 rounded flex items-center gap-1">
                                          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                                          ACTIF
                                        </span>
                                      )}
                                    </div>
                                  </div>

                                  <p className="text-[11px] text-slate-400 group-hover:text-slate-300 line-clamp-2 leading-relaxed">
                                    {item.shortDesc}
                                  </p>
                                </div>

                                <ArrowRight
                                  className={`w-3.5 h-3.5 mt-1 transition-transform shrink-0 ${
                                    isActive
                                      ? 'text-cyan-400 translate-x-0.5'
                                      : 'text-slate-600 group-hover:text-slate-300 group-hover:translate-x-0.5'
                                  }`}
                                />
                              </button>
                            );
                          })
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Pied du Menu Déroulant : Raccourcis, Outils Clés & Exportations */}
              <div className="mt-6 pt-4 border-t border-slate-800 flex flex-col md:flex-row items-center justify-between gap-4 text-xs text-slate-400">
                <div className="flex items-center gap-2 font-mono text-[11px]">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span>Privilèges SeDebugPrivilege & SeTakeOwnership activés · Intégrité Kernel</span>
                </div>

                <div className="flex items-center flex-wrap gap-2.5">
                  {/* Raccourci Raccourcis Clavier */}
                  <button
                    onClick={() => {
                      onOpenShortcutsModal?.();
                      setIsMegaMenuOpen(false);
                    }}
                    className="h-8 px-2.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 hover:text-cyan-300 transition-colors text-xs font-mono flex items-center gap-1.5 cursor-pointer"
                  >
                    <Keyboard className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Raccourcis (?)</span>
                  </button>

                  {/* Kill-Switch Réseau Direct */}
                  <button
                    onClick={() => {
                      handleSelectTab('sandbox-isolation');
                    }}
                    className="h-8 px-2.5 rounded bg-rose-950/70 hover:bg-rose-900 border border-rose-800 text-rose-300 hover:text-white transition-colors text-xs font-mono font-semibold flex items-center gap-1.5 cursor-pointer"
                  >
                    <WifiOff className="w-3.5 h-3.5 text-rose-400" />
                    <span>Kill-Switch Réseau</span>
                  </button>

                  {/* Export PDF */}
                  <button
                    onClick={() => {
                      onOpenPdfReport();
                      setIsMegaMenuOpen(false);
                    }}
                    className="h-8 px-2.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 hover:text-white transition-colors text-xs font-mono flex items-center gap-1.5 cursor-pointer"
                  >
                    <FileText className="w-3.5 h-3.5 text-rose-400" />
                    <span>Rapport PDF</span>
                  </button>

                  {/* Téléchargement Archive ZIP */}
                  <button
                    onClick={() => {
                      onDownloadZip();
                      setIsMegaMenuOpen(false);
                    }}
                    className="h-8 px-2.5 rounded bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-semibold transition-colors text-xs flex items-center gap-1.5 cursor-pointer shadow-xs"
                  >
                    <Archive className="w-3.5 h-3.5" />
                    <span>Archive ZIP</span>
                  </button>

                  <button
                    onClick={() => setIsMegaMenuOpen(false)}
                    className="text-xs text-slate-400 hover:text-white transition-colors font-mono ml-1 cursor-pointer"
                  >
                    Fermer [Échap]
                  </button>
                </div>
              </div>

            </div>
          </div>
        </>
      )}
    </header>
  );
};
