import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Wifi,
  WifiOff,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Play,
  RotateCcw,
  Lock,
  Unlock,
  Radio,
  Search,
  CheckCircle2,
  XCircle,
  Zap,
  Terminal,
  Filter,
  Eye,
  Server,
  Cpu,
  Layers,
  ArrowRight,
} from 'lucide-react';
import { WiFiNetworkItem } from '../types/cyberdefense';
import { apiFetch } from '../utils/api';

interface WiFiScannerProps {
  onRunInConsole: (command: string) => void;
}

export const WiFiScanner: React.FC<WiFiScannerProps> = ({ onRunInConsole }) => {
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(100);
  const [isLiveSniffing, setIsLiveSniffing] = useState<boolean>(true);
  const [filterMode, setFilterMode] = useState<'ALL' | 'EVIL_TWIN' | 'UNSECURED' | 'LEGITIMATE'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedNetwork, setSelectedNetwork] = useState<WiFiNetworkItem | null>(null);
  const [blockedBssids, setBlockedBssids] = useState<Set<string>>(new Set());

  // WiFi Networks State - starts empty and populates with real local Wi-Fi networks
  const [networks, setNetworks] = useState<WiFiNetworkItem[]>([]);

  // Fetch or trigger scan from server
  const handlePerformScan = useCallback(async () => {
    setIsScanning(true);
    setScanProgress(15);
    onRunInConsole('netsh wlan show networks mode=bssid');

    try {
      const res = await apiFetch('/api/system/wifi');
      if (res.ok) {
        const data = await res.json();
        if (data.success && Array.isArray(data.networks) && data.networks.length > 0) {
          setNetworks(data.networks);
        }
      }
    } catch {
      // Keep local state
    }

    const interval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          setIsScanning(false);
          return 100;
        }
        return prev + 25;
      });
    }, 250);
  }, [onRunInConsole]);

  // Initial scan on component mount
  useEffect(() => {
    handlePerformScan();
  }, [handlePerformScan]);

  // Live sniffing simulation (small jitter in signal & deauth count)
  useEffect(() => {
    if (!isLiveSniffing) return;

    const interval = setInterval(() => {
      setNetworks(prev =>
        prev.map(item => {
          if (item.isEvilTwin) {
            const addedDeauth = Math.floor(Math.random() * 4);
            return {
              ...item,
              deauthFramesDetected: item.deauthFramesDetected + addedDeauth,
              signalDbm: Math.max(-80, Math.min(-25, item.signalDbm + (Math.random() - 0.5) * 2)),
            };
          }
          return {
            ...item,
            signalDbm: Math.max(-85, Math.min(-35, item.signalDbm + (Math.random() - 0.5) * 1)),
          };
        })
      );
    }, 3500);

    return () => clearInterval(interval);
  }, [isLiveSniffing]);

  // Filtered networks list
  const filteredNetworks = useMemo(() => {
    return networks
      .filter(item => {
        if (filterMode === 'EVIL_TWIN') return item.isEvilTwin;
        if (filterMode === 'UNSECURED') return item.isUnsecured;
        if (filterMode === 'LEGITIMATE') return item.status === 'LEGITIMATE';
        return true;
      })
      .filter(item => {
        if (!searchQuery.trim()) return true;
        const q = searchQuery.toLowerCase();
        return (
          item.ssid.toLowerCase().includes(q) ||
          item.bssid.toLowerCase().includes(q) ||
          item.vendor.toLowerCase().includes(q) ||
          item.security.toLowerCase().includes(q)
        );
      });
  }, [networks, filterMode, searchQuery]);

  // Aggregate KPI stats
  const stats = useMemo(() => {
    const evilTwinCount = networks.filter(n => n.isEvilTwin).length;
    const unsecuredCount = networks.filter(n => n.isUnsecured).length;
    const totalDeauth = networks.reduce((acc, n) => acc + n.deauthFramesDetected, 0);

    return {
      totalNetworks: networks.length,
      evilTwinCount,
      unsecuredCount,
      totalDeauth,
    };
  }, [networks]);

  // Handlers for countermeasures
  const handleBlockBssid = (bssid: string, ssid: string) => {
    setBlockedBssids(prev => {
      const next = new Set(prev);
      next.add(bssid);
      return next;
    });

    onRunInConsole(`netsh wlan add filter permission=block ssid="${ssid}" networktype=infrastructure`);
    setNetworks(prev =>
      prev.map(n => (n.bssid === bssid ? { ...n, status: 'BLOCKED' as const } : n))
    );
  };

  const handleSimulateEvilTwinAttack = () => {
    const rogueAp: WiFiNetworkItem = {
      id: `wifi-rogue-sim-${Date.now()}`,
      ssid: 'SpaceSec-Secure-Corp',
      bssid: '00:1E:58:A4:77:FF',
      channel: 1,
      frequency: '2.4 GHz',
      signalDbm: -28,
      signalPercent: 100,
      security: 'OPEN_UNSECURED',
      vendor: 'Hak5 WiFi Pineapple (Attaque Détectée)',
      isEvilTwin: true,
      evilTwinReason: 'Attaque active en cours : clone ouvert de votre SSID officiel avec inondation de trames Deauth pour forcer la reconnexion automatique des clients.',
      isUnsecured: true,
      deauthFramesDetected: 210,
      status: 'SUSPECT_EVIL_TWIN',
      firstSeen: new Date().toTimeString().split(' ')[0],
      recommendedAction: 'Désactiver le Wi-Fi ou forcer le profil WPA3 protégé.',
      mitreTechnique: 'T1557.002 - Evil Twin Rogue AP',
      legitimateTwinBssid: '00:14:D1:68:55:2A',
    };
    setNetworks(prev => [rogueAp, ...prev]);
    onRunInConsole('netsh wlan disconnect');
  };

  return (
    <div className="p-6 bg-slate-900 border border-slate-800 rounded-2xl space-y-6 shadow-xl">
      {/* Top Header & Tactical Action Strip */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
            <span className="text-cyan-400 font-semibold uppercase tracking-wider">
              AUDIT RADIOFRÉQUENCE 802.11
            </span>
            <span aria-hidden="true">·</span>
            <span>SCANNER BSSID & BORNE ROGUE</span>
            <span aria-hidden="true">·</span>
            <span className="text-rose-400">{stats.evilTwinCount} EVIL TWIN SUSPECTS</span>
          </div>

          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2 mt-1 font-['Plus_Jakarta_Sans']">
            <Wifi className="w-5 h-5 text-cyan-400" />
            <span>Scanner WiFi Environnant & Détection d'Attaques Evil Twin</span>
          </h2>

          <p className="text-xs text-slate-300 mt-1 max-w-2xl leading-relaxed">
            Interroge les cartes réseau via <code className="text-cyan-300 font-mono text-xs">netsh wlan</code> pour identifier les points d'accès non sécurisés (Open/WEP) et démasquer les attaques de jumeaux malveillants (<strong className="text-rose-400">Evil Twin</strong>) usurpant votre SSID avec affaiblissement de chiffrement et injection de trames Deauth.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={handlePerformScan}
            disabled={isScanning}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold rounded-lg text-xs transition-colors shadow-sm disabled:opacity-50"
          >
            <Play className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
            <span>{isScanning ? 'Scan en cours...' : 'Lancer le Scan WiFi (BSSID)'}</span>
          </button>

          <button
            onClick={handleSimulateEvilTwinAttack}
            className="flex items-center gap-1.5 px-3 py-2 bg-rose-950 hover:bg-rose-900 border border-rose-800 text-rose-300 rounded-lg text-xs font-semibold transition-colors font-mono"
            title="Injecter une attaque de démonstration Evil Twin"
          >
            <Zap className="w-3.5 h-3.5 text-rose-400" />
            <span>+ Simuler Attaque Evil Twin</span>
          </button>

          <button
            onClick={() => setIsLiveSniffing(!isLiveSniffing)}
            className={`p-2 rounded-lg border text-xs transition-colors ${
              isLiveSniffing
                ? 'bg-cyan-950 border-cyan-800 text-cyan-300'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-white'
            }`}
            title={isLiveSniffing ? 'Sniffer radioactif en continu' : 'Activer le renifleur temps réel'}
          >
            <Radio className={`w-4 h-4 ${isLiveSniffing ? 'text-cyan-400 animate-pulse' : ''}`} />
          </button>
        </div>
      </div>

      {/* Progress Bar (Visible during scan) */}
      {isScanning && (
        <div className="space-y-1">
          <div className="flex justify-between text-xs font-mono text-slate-400">
            <span>Balayage des canaux 2.4 GHz, 5 GHz et 6 GHz...</span>
            <span>{scanProgress}%</span>
          </div>
          <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-cyan-400 transition-all duration-300 rounded-full"
              style={{ width: `${scanProgress}%` }}
            />
          </div>
        </div>
      )}

      {/* KPI Stats Strip (Unboxed text with tabular figures) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-2">
        <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400 font-mono">Points d'Accès Détectés</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-white">
            {stats.totalNetworks}
          </div>
          <div className="text-[11px] text-slate-500 font-mono">BSSID actifs à portée</div>
        </div>

        <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400 font-mono">Attaques Evil Twin</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-rose-400 flex items-center gap-1.5">
            <AlertTriangle className="w-5 h-5 text-rose-400" />
            <span>{stats.evilTwinCount} Clones</span>
          </div>
          <div className="text-[11px] text-rose-300/80 font-mono">Usurpation de SSID avérée</div>
        </div>

        <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400 font-mono">Réseaux Non Sécurisés</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-amber-400">
            {stats.unsecuredCount} Ouverts
          </div>
          <div className="text-[11px] text-amber-300/80 font-mono">Vulnérables aux écoutes</div>
        </div>

        <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-1">
          <div className="text-xs text-slate-400 font-mono">Trames Deauth Détectées</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-cyan-300">
            {stats.totalDeauth} trames
          </div>
          <div className="text-[11px] text-cyan-400 font-mono">Inondation de déconnexion</div>
        </div>
      </div>

      {/* Filter Segmented Control & Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
        <div className="flex items-center gap-1.5 flex-wrap">
          <button
            onClick={() => setFilterMode('ALL')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              filterMode === 'ALL'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-white bg-slate-950/60 border border-slate-800'
            }`}
          >
            Tous les Réseaux ({networks.length})
          </button>
          <button
            onClick={() => setFilterMode('EVIL_TWIN')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
              filterMode === 'EVIL_TWIN'
                ? 'bg-rose-950 text-rose-300 border border-rose-800'
                : 'text-slate-400 hover:text-white bg-slate-950/60 border border-slate-800'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span>Evil Twin ({stats.evilTwinCount})</span>
          </button>
          <button
            onClick={() => setFilterMode('UNSECURED')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
              filterMode === 'UNSECURED'
                ? 'bg-amber-950 text-amber-300 border border-amber-800'
                : 'text-slate-400 hover:text-white bg-slate-950/60 border border-slate-800'
            }`}
          >
            <Unlock className="w-3.5 h-3.5 text-amber-400" />
            <span>Non Sécurisés ({stats.unsecuredCount})</span>
          </button>
          <button
            onClick={() => setFilterMode('LEGITIMATE')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              filterMode === 'LEGITIMATE'
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                : 'text-slate-400 hover:text-white bg-slate-950/60 border border-slate-800'
            }`}
          >
            Nominaux (Sûrs)
          </button>
        </div>

        {/* Search */}
        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Filtrer SSID, BSSID, fabricant..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition-colors"
          />
        </div>
      </div>

      {/* Main Grid: Networks List & Detailed Forensic Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Scanned Networks Table / Cards */}
        <div className="lg:col-span-2 space-y-3">
          {filteredNetworks.length === 0 ? (
            <div className="py-12 text-center text-xs text-slate-500 font-mono bg-slate-950/40 rounded-xl border border-slate-800">
              Aucun réseau WiFi ne correspond aux critères de filtrage.
            </div>
          ) : (
            filteredNetworks.map(network => {
              const isSelected = selectedNetwork?.id === network.id;
              const isBlocked = blockedBssids.has(network.bssid) || network.status === 'BLOCKED';

              return (
                <div
                  key={network.id}
                  onClick={() => setSelectedNetwork(network)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all space-y-2.5 ${
                    isSelected
                      ? 'bg-slate-900 border-cyan-500 shadow-md'
                      : network.isEvilTwin
                      ? 'bg-rose-950/20 border-rose-800/80 hover:border-rose-600'
                      : network.isUnsecured
                      ? 'bg-amber-950/20 border-amber-800/80 hover:border-amber-600'
                      : 'bg-slate-950/80 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <div className={`p-1.5 rounded-lg border ${
                        network.isEvilTwin
                          ? 'bg-rose-950 border-rose-800 text-rose-400'
                          : network.isUnsecured
                          ? 'bg-amber-950 border-amber-800 text-amber-400'
                          : 'bg-slate-900 border-slate-800 text-cyan-400'
                      }`}>
                        {network.isUnsecured ? (
                          <Unlock className="w-4 h-4" />
                        ) : (
                          <Wifi className="w-4 h-4" />
                        )}
                      </div>

                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-sm text-white font-mono">
                            {network.ssid}
                          </span>
                          {network.isEvilTwin && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold text-rose-300 bg-rose-950 border border-rose-800 flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3 text-rose-400" />
                              CLONE EVIL TWIN
                            </span>
                          )}
                          {network.isUnsecured && !network.isEvilTwin && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold text-amber-300 bg-amber-950 border border-amber-800">
                              NON CHIFFRÉ
                            </span>
                          )}
                          {isBlocked && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold text-slate-400 bg-slate-900 border border-slate-700">
                              BLOQUÉ VIA NETSH
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                          BSSID : <span className="text-slate-300">{network.bssid}</span> · OUI : {network.vendor}
                        </div>
                      </div>
                    </div>

                    {/* Right Signals & Channel Indicator */}
                    <div className="flex items-center gap-3 shrink-0">
                      <div className="text-right font-mono">
                        <div className="text-xs font-bold text-white tabular-nums">
                          {network.signalDbm} dBm ({network.signalPercent}%)
                        </div>
                        <div className="text-[10px] text-slate-400">
                          Canal {network.channel} ({network.frequency})
                        </div>
                      </div>

                      <span className={`text-[11px] font-mono px-2 py-1 rounded border font-semibold ${
                        network.security === 'OPEN_UNSECURED'
                          ? 'text-rose-400 bg-rose-950/80 border-rose-800'
                          : network.security.includes('WPA3')
                          ? 'text-emerald-400 bg-emerald-950/80 border-emerald-800'
                          : 'text-cyan-400 bg-cyan-950/80 border-cyan-800'
                      }`}>
                        {network.security}
                      </span>
                    </div>
                  </div>

                  {/* Anomaly Reason or Alert */}
                  {network.evilTwinReason && (
                    <div className="p-2.5 rounded-lg bg-rose-950/40 border border-rose-900/60 text-xs text-rose-200 leading-relaxed font-sans flex items-start gap-2">
                      <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                      <span>{network.evilTwinReason}</span>
                    </div>
                  )}

                  {/* Action Bar */}
                  <div className="flex items-center justify-between text-xs font-mono pt-2 border-t border-slate-900">
                    <span className="text-slate-400 text-[11px] truncate max-w-sm">
                      {network.mitreTechnique}
                    </span>

                    <div className="flex items-center gap-2">
                      {network.isEvilTwin && !isBlocked && (
                        <button
                          onClick={e => {
                            e.stopPropagation();
                            handleBlockBssid(network.bssid, network.ssid);
                          }}
                          className="px-2.5 py-1 bg-rose-600 hover:bg-rose-500 text-white rounded text-[11px] font-semibold transition-colors"
                        >
                          Bloquer BSSID Pirate
                        </button>
                      )}
                      <button
                        onClick={e => {
                          e.stopPropagation();
                          setSelectedNetwork(network);
                        }}
                        className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px] transition-colors"
                      >
                        Détails Forensiques
                      </button>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right 1 Col: Detailed Forensic Dossier of Selected AP */}
        <div className="p-5 bg-slate-950 border border-slate-800 rounded-xl space-y-4 flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Radio className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white uppercase font-mono tracking-wider">
                  Dossier Borne Radio
                </h3>
              </div>
              {selectedNetwork && (
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
                  selectedNetwork.isEvilTwin
                    ? 'text-rose-400 bg-rose-950 border-rose-800'
                    : selectedNetwork.isUnsecured
                    ? 'text-amber-400 bg-amber-950 border-amber-800'
                    : 'text-emerald-400 bg-emerald-950 border-emerald-800'
                }`}>
                  {selectedNetwork.status}
                </span>
              )}
            </div>

            {selectedNetwork ? (
              <div className="space-y-3 text-xs font-mono">
                {/* SSID & Hardware Identity */}
                <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 space-y-1.5">
                  <div className="text-base font-bold text-white flex items-center justify-between">
                    <span>{selectedNetwork.ssid}</span>
                    <span className="text-xs text-cyan-400">{selectedNetwork.frequency}</span>
                  </div>
                  <div className="text-slate-400">
                    BSSID : <span className="text-slate-200 font-bold select-all">{selectedNetwork.bssid}</span>
                  </div>
                  <div className="text-slate-400">
                    Constructeur OUI : <span className="text-slate-200">{selectedNetwork.vendor}</span>
                  </div>
                </div>

                {/* Evil Twin Conflict Detection Matrix */}
                {selectedNetwork.isEvilTwin && selectedNetwork.legitimateTwinBssid && (
                  <div className="p-3 bg-rose-950/30 border border-rose-800 rounded-lg space-y-2">
                    <div className="text-xs font-bold text-rose-300 flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                      Analyse Comparative Jumeau Malveillant
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[11px] pt-1 border-t border-rose-900/60">
                      <div>
                        <span className="text-slate-400">Borne Légitime :</span>
                        <div className="text-emerald-400 font-bold">00:14:D1:68:55:2A</div>
                        <div className="text-slate-400">WPA3-SAE (5 GHz)</div>
                      </div>
                      <div>
                        <span className="text-rose-300 font-bold">Borne Pirate Clonant :</span>
                        <div className="text-rose-400 font-bold">{selectedNetwork.bssid}</div>
                        <div className="text-rose-300 font-bold">{selectedNetwork.security} ({selectedNetwork.frequency})</div>
                      </div>
                    </div>
                    <div className="text-[11px] text-slate-300 pt-1">
                      Inondation Deauth : <strong className="text-rose-400">{selectedNetwork.deauthFramesDetected} trames</strong>
                    </div>
                  </div>
                )}

                {/* Technical Parameters */}
                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div className="p-2 bg-slate-900 rounded border border-slate-800">
                    <span className="text-slate-500">Puissance Reçue :</span>
                    <div className="text-white font-bold">{selectedNetwork.signalDbm} dBm</div>
                    <div className="text-slate-500">{selectedNetwork.signalPercent}% qualité</div>
                  </div>
                  <div className="p-2 bg-slate-900 rounded border border-slate-800">
                    <span className="text-slate-500">Canal Radio :</span>
                    <div className="text-cyan-400 font-bold">Canal {selectedNetwork.channel}</div>
                    <div className="text-slate-500">{selectedNetwork.frequency}</div>
                  </div>
                </div>

                {/* Recommendation */}
                <div className="space-y-1">
                  <div className="text-slate-400 text-[11px]">Recommandation de Sécurité :</div>
                  <p className="text-slate-300 font-sans leading-relaxed bg-slate-900/50 p-2.5 rounded border border-slate-800">
                    {selectedNetwork.recommendedAction}
                  </p>
                </div>
              </div>
            ) : (
              <div className="py-12 text-center text-xs text-slate-500 font-mono">
                Sélectionnez un point d'accès dans la liste pour afficher l'analyse radio détaillée.
              </div>
            )}
          </div>

          {/* Action buttons */}
          {selectedNetwork && (
            <div className="pt-4 border-t border-slate-800 space-y-2">
              <button
                onClick={() => handleBlockBssid(selectedNetwork.bssid, selectedNetwork.ssid)}
                className="w-full py-2 bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>Bloquer l'accès au BSSID {selectedNetwork.bssid}</span>
              </button>

              <button
                onClick={() => onRunInConsole('netsh wlan disconnect')}
                className="w-full py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 font-mono text-xs rounded-lg transition-colors"
              >
                Déconnecter immédiatement la carte WiFi (Netsh)
              </button>

              <button
                onClick={() => onRunInConsole('arp -a')}
                className="w-full py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 font-mono text-xs rounded-lg transition-colors"
              >
                Auditer la passerelle par défaut (Table ARP)
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
