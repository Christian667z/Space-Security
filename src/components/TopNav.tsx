import React, { useState, useRef, useEffect } from 'react';
import {
  Shield,
  Terminal,
  Download,
  Cpu,
  Activity,
  Network,
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
  AlertTriangle,
  ArrowRight,
  ExternalLink,
  FileText,
  Binary,
  Users,
  Globe,
  MapPin,
  Wifi,
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
}) => {
  const [isMegaMenuOpen, setIsMegaMenuOpen] = useState(false);
  const [searchFilter, setSearchFilter] = useState('');
  const [systemTime, setSystemTime] = useState('');
  const megaMenuRef = useRef<HTMLDivElement>(null);
  const triggerButtonRef = useRef<HTMLButtonElement>(null);

  // Live system clock
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setSystemTime(
        now.toLocaleTimeString('fr-FR', {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        })
      );
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Close Mega Menu on Click Outside or Escape key
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        megaMenuRef.current &&
        !megaMenuRef.current.contains(event.target as Node) &&
        triggerButtonRef.current &&
        !triggerButtonRef.current.contains(event.target as Node)
      ) {
        setIsMegaMenuOpen(false);
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsMegaMenuOpen(false);
      }
    };

    if (isMegaMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isMegaMenuOpen]);

  // Two columns navigation structure
  const columns: NavColumn[] = [
    {
      title: 'SUPERVISION & PROCESSUS SYSTÈME',
      subtitle: 'Télémétrie continue, analyse des tâches & flux d\'événements',
      badge: 'SURVEILLANCE',
      badgeClass: 'text-cyan-400 bg-cyan-950/60 border-cyan-800/40',
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
          title: 'Moteur Heuristique & Détection Live',
          category: 'Entropie, Registre & Signatures',
          shortDesc: 'Calcul d\'entropie de Shannon (ransomware/obfuscation), surveillance du Registre (Run/Winlogon) et inspecteur de signature Authenticode (faux explorer.exe).',
          icon: Binary,
          tag: 'ENTROPIE & SPOOFING',
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
      subtitle: 'Contre-mesures ring0, introspection mémoire & politiques d\'isolement',
      badge: 'CONTRE-MESURES',
      badgeClass: 'text-rose-400 bg-rose-950/60 border-rose-800/40',
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
          shortDesc: 'Audit des sockets actifs, détection des balises C2 persistantes, ports d\'écoute & flux hostiles.',
          icon: Network,
          tag: 'SCAN RÉSEAU',
          tagClass: 'text-cyan-400 bg-cyan-950/70 border-cyan-800/50',
        },
        {
          id: 'wifi',
          title: 'Scan WiFi (BSSID)',
          category: 'Audit Réseaux Sans-Fil',
          shortDesc: 'Scan des bornes 802.11 environnantes, détection Evil Twin, trames Deauth & points d\'accès ouverts.',
          icon: Wifi,
          tag: 'SCAN WIFI',
          tagClass: 'text-indigo-400 bg-indigo-950/70 border-indigo-800/50',
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
          shortDesc: 'Script SpaceSecurity_ULTRA_v3_Kernel.ps1, lanceurs batch élévateurs & guides d\'intervention.',
          icon: FileCode,
          tag: 'SCRIPT PS1',
          tagClass: 'text-amber-400 bg-amber-950/70 border-amber-800/50',
        },
        {
          id: 'ip-locator',
          title: 'Géolocalisation & Traçeur IP',
          category: 'Localisation Précise & C2',
          shortDesc: 'Localiser le pays, la ville, la rue, le bâtiment, coordonnées GPS, FAI & C2 pour toute IP.',
          icon: Globe,
          tag: 'GÉO-TRACKER',
          tagClass: 'text-sky-400 bg-sky-950/70 border-sky-800/50',
        },
      ],
    },
  ];

  // Helper to find title of active tab
  const allItems = columns.flatMap((col) => col.items);
  const currentActiveItem = allItems.find((item) => item.id === activeTab);

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
    setSearchFilter('');
  };

  return (
    <header className="relative border-b border-slate-800 bg-slate-950/90 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-4">
          
          {/* Zone 1: Brand Wordmark + Live Kernel Badge */}
          <div className="flex items-center gap-3 shrink-0">
            <div
              onClick={() => handleSelectTab('overview')}
              className="flex items-center gap-2.5 cursor-pointer text-slate-100 group select-none"
              title="Retour à la Vue Centrale"
            >
              <div className="w-9 h-9 rounded-lg bg-cyan-950/80 border border-cyan-800/80 flex items-center justify-center text-cyan-400 group-hover:border-cyan-400 group-hover:shadow-sm group-hover:shadow-cyan-500/20 transition-all">
                <Shield className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="flex flex-col">
                <div className="flex items-center gap-2">
                  <span className="text-base font-bold tracking-tight text-white font-['Plus_Jakarta_Sans']">
                    Space Security
                  </span>
                  <span className="text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 hidden sm:inline-block">
                    Kernel v3.0
                  </span>
                </div>
                <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
                  <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                  <span className="font-mono text-emerald-400 font-medium">PROTECTION ACTIVE</span>
                  <span className="text-slate-600 hidden md:inline">·</span>
                  <span className="text-slate-400 hidden md:inline truncate max-w-[130px]">
                    {currentActiveItem?.title || 'Vue Centrale'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Zone 2: Navigation Controls with Mega Menu Trigger & Direct Shortcuts */}
          <div className="flex items-center gap-2 lg:gap-3">
            {/* Direct Quick Link 1: Vue Centrale */}
            <button
              onClick={() => handleSelectTab('overview')}
              className={`hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'overview'
                  ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/60'
                  : 'text-slate-300 hover:text-white hover:bg-slate-900 border border-transparent'
              }`}
            >
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span>Vue Centrale</span>
            </button>

            {/* Direct Quick Link 2: Gestionnaire des Tâches */}
            <button
              onClick={() => handleSelectTab('task-manager')}
              className={`hidden lg:flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'task-manager'
                  ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/60'
                  : 'text-slate-300 hover:text-white hover:bg-slate-900 border border-transparent'
              }`}
            >
              <Cpu className="w-3.5 h-3.5 text-blue-400" />
              <span>Gestionnaire</span>
            </button>

            {/* Direct Quick Link 3: Console Live */}
            <button
              onClick={() => handleSelectTab('console')}
              className={`hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'console'
                  ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/60'
                  : 'text-slate-300 hover:text-white hover:bg-slate-900 border border-transparent'
              }`}
            >
              <Terminal className="w-3.5 h-3.5 text-emerald-400" />
              <span>Console</span>
            </button>

            {/* Direct Quick Link 4: Géolocalisation & Traçeur IP */}
            <button
              onClick={() => handleSelectTab('ip-locator')}
              className={`hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'ip-locator'
                  ? 'bg-sky-950/70 text-sky-300 border border-sky-600/70 shadow-sm shadow-sky-950/50'
                  : 'text-slate-300 hover:text-white hover:bg-slate-900 border border-transparent'
              }`}
            >
              <Globe className="w-3.5 h-3.5 text-sky-400" />
              <span>Traçeur IP</span>
            </button>

            {/* Direct Modules: Scan Réseau & Scan WiFi (BSSID) */}
            <div className="hidden xl:flex items-center gap-1.5 p-1 bg-slate-900/90 border border-cyan-800/60 rounded-xl shadow-md">
              <button
                onClick={() => {
                  handleSelectTab('network');
                  onRunInConsole?.('sockets');
                }}
                className={`px-2.5 py-1.5 rounded-lg font-bold text-xs transition-all flex items-center gap-1.5 shadow-sm active:scale-95 cursor-pointer ${
                  activeTab === 'network'
                    ? 'bg-gradient-to-r from-cyan-900 to-blue-900 text-white border border-cyan-400 shadow-cyan-950/50'
                    : 'bg-gradient-to-r from-cyan-950/80 to-blue-950/80 hover:from-cyan-900 hover:to-blue-900 text-cyan-200 hover:text-white border border-cyan-700/60'
                }`}
                title="Module Scan Réseau : Audit des sockets et ports ouverts"
              >
                <Network className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span>Scan Réseau</span>
              </button>

              <button
                onClick={() => {
                  handleSelectTab('wifi');
                  onRunInConsole?.('netsh wlan show networks mode=bssid');
                }}
                className={`px-2.5 py-1.5 rounded-lg font-bold text-xs transition-all flex items-center gap-1.5 shadow-sm active:scale-95 cursor-pointer ${
                  activeTab === 'wifi'
                    ? 'bg-gradient-to-r from-indigo-900 to-purple-900 text-white border border-indigo-400 shadow-indigo-950/50'
                    : 'bg-gradient-to-r from-indigo-950/80 to-purple-950/80 hover:from-indigo-900 hover:to-purple-900 text-indigo-200 hover:text-white border border-indigo-700/60'
                }`}
                title="Module Scan WiFi (BSSID) : Audit des bornes 802.11 et Evil Twin"
              >
                <Wifi className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                <span>Scan WiFi (BSSID)</span>
              </button>
            </div>

            {/* MEGA MENU TRIGGER BUTTON */}
            <div className="relative">
              <button
                ref={triggerButtonRef}
                onClick={() => setIsMegaMenuOpen(!isMegaMenuOpen)}
                aria-expanded={isMegaMenuOpen}
                aria-haspopup="true"
                className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all border ${
                  isMegaMenuOpen
                    ? 'bg-cyan-950 text-cyan-300 border-cyan-500 shadow-md shadow-cyan-950/50'
                    : 'bg-slate-900/90 hover:bg-slate-800/90 text-slate-100 border-slate-700/80 hover:border-cyan-600/70 shadow-sm'
                }`}
              >
                <LayoutGrid className="w-4 h-4 text-cyan-400 shrink-0" />
                <span className="tracking-wide">
                  Modules & Outils
                </span>
                <span className="hidden sm:inline-block px-1.5 py-0.2 font-mono text-[10px] rounded bg-slate-800 text-slate-300 border border-slate-700">
                  {allItems.length}
                </span>
                <ChevronDown
                  className={`w-3.5 h-3.5 text-slate-400 transition-transform duration-200 ${
                    isMegaMenuOpen ? 'rotate-180 text-cyan-400' : ''
                  }`}
                />
              </button>
            </div>
          </div>

          {/* Zone 3: Live System Clock & Primary Action Button */}
          <div className="flex items-center gap-3 shrink-0">
            {/* System Clock Pill */}
            {systemTime && (
              <div className="hidden 2xl:flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900/80 border border-slate-800 text-slate-300 text-xs font-mono">
                <Clock className="w-3 h-3 text-slate-400" />
                <span>{systemTime}</span>
              </div>
            )}

            {/* Real-Time Multi-User Collaboration & Synchronization Badge */}
            <button
              onClick={onOpenCollabModal}
              title="Centre d'Opérations Multi-Utilisateurs : Cliquez pour voir les analystes connectés et la synchronisation"
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono transition-all border shadow-sm ${
                connectionStatus === 'connected'
                  ? 'bg-emerald-950/40 hover:bg-emerald-950/80 text-emerald-300 border-emerald-800/80 hover:border-emerald-600'
                  : 'bg-amber-950/40 hover:bg-amber-950/70 text-amber-300 border-amber-800/80 hover:border-amber-600'
              }`}
            >
              <span className="relative flex h-2 w-2">
                {connectionStatus === 'connected' && (
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                )}
                <span
                  className={`relative inline-flex rounded-full h-2 w-2 ${
                    connectionStatus === 'connected' ? 'bg-emerald-400' : 'bg-amber-400'
                  }`}
                ></span>
              </span>
              <span className="font-semibold tracking-wide">
                {connectionStatus === 'connected'
                  ? activeUsersCount > 1
                    ? `${activeUsersCount} Analystes en Direct`
                    : 'Synchro Live Active'
                  : 'Synchro En Cours'}
              </span>
              <Users className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            </button>

            {/* Primary Action: Download ZIP */}
            <button
              onClick={onDownloadZip}
              className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-all shadow-sm shadow-cyan-500/20 active:translate-y-px"
            >
              <Archive className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Télécharger</span>
              <span>Archive ZIP</span>
            </button>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 2-COLUMN MEGA MENU DROPDOWN PANEL */}
      {/* ========================================================================= */}
      {isMegaMenuOpen && (
        <>
          {/* Backdrop overlay for focus and outside-click dismissal */}
          <div
            className="fixed inset-0 top-16 bg-slate-950/75 backdrop-blur-xs z-40 transition-opacity"
            onClick={() => setIsMegaMenuOpen(false)}
            aria-hidden="true"
          />

          {/* Scrollable mega menu container with overflow-y: auto */}
          <div
            ref={megaMenuRef}
            className="absolute top-full left-0 right-0 bg-slate-950/98 backdrop-blur-2xl border-b border-cyan-900/40 shadow-2xl shadow-black/90 z-50 animate-in fade-in slide-in-from-top-2 duration-150 max-h-[calc(100vh-4rem)] max-h-[calc(100dvh-4rem)] overflow-y-auto overscroll-contain"
            style={{
              WebkitOverflowScrolling: 'touch',
            }}
          >
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 pb-14">
            
            {/* Header of Mega Menu: Title & Quick Search Filter */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 mb-5 border-b border-slate-800/80">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800/70 flex items-center justify-center text-cyan-400">
                  <LayoutGrid className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white tracking-wide uppercase font-mono flex items-center gap-2">
                    Centre de Contrôle & Navigation Space Security
                    <span className="text-[10px] text-cyan-400 font-mono font-normal px-1.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-800/50">
                      2 Colonnes
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Sélectionnez un moteur pour lancer l'analyse, l'éradication ou l'isolation mémoire.
                  </p>
                </div>
              </div>

              {/* Search filter input */}
              <div className="flex items-center gap-2 w-full sm:w-80">
                <div className="relative w-full">
                  <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={searchFilter}
                    onChange={(e) => setSearchFilter(e.target.value)}
                    placeholder="Filtrer un module (ex: BITS, Rootkit, RAM)..."
                    className="w-full bg-slate-900/90 border border-slate-700/80 rounded-lg pl-9 pr-8 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono transition-colors"
                  />
                  {searchFilter && (
                    <button
                      onClick={() => setSearchFilter('')}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
                <button
                  onClick={() => setIsMegaMenuOpen(false)}
                  className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800/80 rounded-lg border border-slate-800 transition-colors shrink-0"
                  title="Fermer (Échap)"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Featured Scanner Quick Launch in Mega Menu */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3.5 mb-6 bg-gradient-to-r from-slate-900 via-cyan-950/40 to-indigo-950/40 border border-cyan-800/70 rounded-xl shadow-lg shadow-black/50">
              <div className="flex items-center gap-3">
                <span className="relative flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-400"></span>
                </span>
                <div>
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                    Scanners Réseau & Sans-Fil Haute Précision
                  </h4>
                  <p className="text-[11px] text-slate-400">
                    Détection instantanée des flux C2, sockets réseau & analyse des bornes Wi-Fi BSSID environnantes.
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2.5 shrink-0 w-full sm:w-auto justify-end">
                <button
                  onClick={() => {
                    handleSelectTab('network');
                    onRunInConsole?.('sockets');
                  }}
                  className="flex-1 sm:flex-none px-3.5 py-2 bg-gradient-to-r from-cyan-950/90 to-blue-950/90 hover:from-cyan-900 hover:to-blue-900 text-cyan-200 hover:text-white border border-cyan-600/70 hover:border-cyan-400 rounded-lg font-bold text-xs transition-all flex items-center justify-center gap-2 shadow-sm active:scale-95 cursor-pointer"
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
                  className="flex-1 sm:flex-none px-3.5 py-2 bg-gradient-to-r from-indigo-950/90 to-purple-950/90 hover:from-indigo-900 hover:to-purple-900 text-indigo-200 hover:text-white border border-indigo-600/70 hover:border-indigo-400 rounded-lg font-bold text-xs transition-all flex items-center justify-center gap-2 shadow-sm active:scale-95 cursor-pointer"
                  title="Ouvrir le module Scan WiFi (BSSID) et auditer les réseaux sans-fil"
                >
                  <Wifi className="w-4 h-4 text-indigo-400 shrink-0" />
                  <span>Scan WiFi (BSSID)</span>
                </button>
              </div>
            </div>

            {/* 2 COLUMNS GRID */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 lg:gap-8">
              {columns.map((col, colIndex) => {
                const filteredItems = col.items.filter(filterItem);
                const ColIcon = col.icon;

                return (
                  <div
                    key={col.title}
                    className="flex flex-col space-y-3 bg-slate-900/40 p-4 rounded-xl border border-slate-800/60"
                  >
                    {/* Column Header */}
                    <div className="flex items-center justify-between pb-2 border-b border-slate-800/60">
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

                    {/* Column Items */}
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
                              className={`w-full text-left p-3 rounded-lg border transition-all group flex items-start gap-3 relative ${
                                isActive
                                  ? 'bg-cyan-950/60 border-cyan-500/80 shadow-sm shadow-cyan-950/40'
                                  : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-600 hover:bg-slate-900/90'
                              }`}
                            >
                              {/* Module Icon Box */}
                              <div
                                className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border transition-colors ${
                                  isActive
                                    ? 'bg-cyan-900/80 border-cyan-400 text-cyan-300'
                                    : 'bg-slate-900 border-slate-800 text-slate-400 group-hover:text-cyan-400 group-hover:border-cyan-700/60'
                                }`}
                              >
                                <ItemIcon className="w-4 h-4" />
                              </div>

                              {/* Title, Badge & Description */}
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center justify-between gap-2 mb-1">
                                  <div className="flex items-center gap-2 truncate">
                                    <span
                                      className={`text-xs font-semibold tracking-tight transition-colors truncate ${
                                        isActive
                                          ? 'text-cyan-300 font-bold'
                                          : 'text-slate-200 group-hover:text-white'
                                      }`}
                                    >
                                      {item.title}
                                    </span>
                                  </div>

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
                                        className="text-[9px] font-mono font-bold text-amber-300 hover:text-white bg-amber-950/80 hover:bg-amber-900 border border-amber-700/70 px-1.5 py-0.5 rounded flex items-center gap-1 cursor-pointer transition-colors shadow-xs"
                                      >
                                        <Download className="w-2.5 h-2.5" />
                                        Télécharger .ps1
                                      </span>
                                    )}
                                    {isActive && (
                                      <span className="text-[9px] font-mono font-bold text-cyan-400 bg-cyan-950 border border-cyan-700/60 px-1 py-0.5 rounded flex items-center gap-1">
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

            {/* Mega Menu Footer: Status, Shortcuts & Export */}
            <div className="mt-5 pt-4 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
              <div className="flex items-center gap-2 font-mono text-[11px]">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Noyau NT sécurisé · Droits SeDebugPrivilege & SeTakeOwnership actifs</span>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={() => {
                    onOpenPdfReport();
                    setIsMegaMenuOpen(false);
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-rose-950/70 hover:bg-rose-900 border border-rose-800/80 text-rose-200 hover:text-white transition-colors text-xs font-mono font-medium shadow-sm"
                >
                  <FileText className="w-3 h-3 text-rose-400" />
                  <span>Rapport Forensique (PDF)</span>
                </button>

                <button
                  onClick={() => {
                    onDownloadScript();
                    setIsMegaMenuOpen(false);
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-slate-300 hover:text-white transition-colors text-xs font-mono"
                >
                  <Download className="w-3 h-3 text-cyan-400" />
                  <span>SpaceSecurity_ULTRA_v3_Kernel.ps1</span>
                </button>

                <button
                  onClick={() => setIsMegaMenuOpen(false)}
                  className="text-xs text-slate-500 hover:text-slate-300 transition-colors font-mono"
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
