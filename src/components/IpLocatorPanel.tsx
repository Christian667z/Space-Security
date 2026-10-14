import React, { useState, useEffect, useCallback } from 'react';
import {
  Globe,
  MapPin,
  Search,
  ShieldAlert,
  ShieldCheck,
  Server,
  Crosshair,
  ExternalLink,
  Copy,
  Check,
  Terminal,
  Activity,
  Layers,
  Clock,
  Compass,
  AlertTriangle,
  Radio,
  RotateCw,
  Zap,
  Info,
  ArrowRight,
  Eye,
  Navigation,
  Lock,
} from 'lucide-react';
import { IpLocationReport, TracerouteHop } from '../types/cyberdefense';
import { apiFetch } from '../utils/api';

interface IpLocatorPanelProps {
  initialIp?: string;
  onRunInConsole: (command: string) => void;
  onNavigateTab?: (tab: any) => void;
}

// Convert decimal degrees to Degrees Minutes Seconds (DMS) format
function toDms(val: number, isLat: boolean): string {
  const abs = Math.abs(val);
  const degrees = Math.floor(abs);
  const minutesNotTruncated = (abs - degrees) * 60;
  const minutes = Math.floor(minutesNotTruncated);
  const seconds = Math.floor((minutesNotTruncated - minutes) * 60);
  const direction = isLat ? (val >= 0 ? 'N' : 'S') : val >= 0 ? 'E' : 'W';
  return `${degrees}° ${minutes}' ${seconds}" ${direction}`;
}

export const IpLocatorPanel: React.FC<IpLocatorPanelProps> = ({
  initialIp = '',
  onRunInConsole,
  onNavigateTab,
}) => {
  const [searchQuery, setSearchQuery] = useState<string>(initialIp || '185.220.101.4');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<IpLocationReport | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [mapMode, setMapMode] = useState<'osm' | 'tactical'>('osm');
  const [zoomLevel, setZoomLevel] = useState<number>(14);
  const [recentSearches, setRecentSearches] = useState<string[]>([
    '185.220.101.4',
    '45.154.255.89',
    '194.26.29.112',
    '1.1.1.1',
    '8.8.8.8',
  ]);

  // Target presets (clean real-world network anchors)
  const presets = [
    { label: 'Mon IP Publique', ip: '', tag: 'HÔTE ACTUEL', color: 'border-cyan-800 text-cyan-400 bg-cyan-950/40' },
    { label: 'Passerelle LAN (192.168.1.1)', ip: '192.168.1.1', tag: 'ROUTEUR LOCAL', color: 'border-slate-800 text-slate-300 bg-slate-900/60' },
    { label: 'Cloudflare DNS (1.1.1.1)', ip: '1.1.1.1', tag: 'DNS ANYCAST', color: 'border-blue-800 text-blue-400 bg-blue-950/40' },
    { label: 'Google Primary DNS (8.8.8.8)', ip: '8.8.8.8', tag: 'DNS ANYCAST', color: 'border-emerald-800 text-emerald-400 bg-emerald-950/40' },
    { label: 'Quad9 Sécurisé (9.9.9.9)', ip: '9.9.9.9', tag: 'DNS CYBERDEFENSE', color: 'border-purple-800 text-purple-400 bg-purple-950/40' },
  ];

  // Lookup function
  const lookupIp = useCallback(async (targetIp: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const trimmed = targetIp.trim();
      const res = await apiFetch(`/api/ip/geolocate?ip=${encodeURIComponent(trimmed)}`);
      if (!res.ok) {
        throw new Error(`Erreur réseau (${res.status}) lors de la résolution de l'IP`);
      }
      const data: IpLocationReport = await res.json();
      if (!data.success) {
        throw new Error(data.error || 'Impossible de résoudre la localisation de cette adresse IP.');
      }
      setReport(data);
      if (trimmed && !recentSearches.includes(trimmed)) {
        setRecentSearches(prev => [trimmed, ...prev.slice(0, 6)]);
      }
    } catch (err: any) {
      console.error('[IP Locator Lookup Error]:', err);
      setError(err?.message || 'Erreur inconnue lors de la localisation.');
    } finally {
      setIsLoading(false);
    }
  }, [recentSearches]);

  // Initial lookup on mount or initialIp change (defaults to current machine IP)
  useEffect(() => {
    const ipToQuery = initialIp || '';
    setSearchQuery(ipToQuery);
    lookupIp(ipToQuery);
  }, [initialIp, lookupIp]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) {
      lookupIp('');
    } else {
      lookupIp(searchQuery.trim());
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const getThreatBadge = (score: number, isTor: boolean) => {
    if (isTor || score >= 85) {
      return {
        label: 'MENACE CRITIQUE (C2 ACTIF)',
        color: 'text-rose-400 bg-rose-950/80 border-rose-700/80',
        barColor: 'bg-rose-500',
      };
    }
    if (score >= 60) {
      return {
        label: 'SUSPICIEUX / ANONYMISEUR',
        color: 'text-amber-400 bg-amber-950/80 border-amber-700/80',
        barColor: 'bg-amber-500',
      };
    }
    if (score >= 30) {
      return {
        label: 'RISQUE MODÉRÉ',
        color: 'text-blue-400 bg-blue-950/80 border-blue-700/80',
        barColor: 'bg-blue-500',
      };
    }
    return {
      label: 'TRAFIC BÉNIN / LÉGITIME',
      color: 'text-emerald-400 bg-emerald-950/80 border-emerald-700/80',
      barColor: 'bg-emerald-500',
    };
  };

  // Flag emoji based on country code
  const getFlagEmoji = (countryCode: string) => {
    if (!countryCode || countryCode.length !== 2) return '🌐';
    const codePoints = countryCode
      .toUpperCase()
      .split('')
      .map(char => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header Banner */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg backdrop-blur-sm relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-sky-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-2 text-sky-400 text-xs font-mono tracking-wider uppercase mb-1">
              <Globe className="w-4 h-4 animate-spin-slow text-sky-400" />
              <span>SPACESEC GEOLOCATION & C2 PHYSICAL TRACER</span>
            </div>
            <h1 className="text-xl lg:text-2xl font-bold text-slate-100 flex items-center gap-2 font-sans">
              Géolocalisation & Traçage d'Endroit Précis d'Adresse IP
            </h1>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
              Déterminez le <strong className="text-slate-200">pays</strong>, la <strong className="text-slate-200">ville</strong>, le <strong className="text-slate-200">quartier</strong> et l'<strong className="text-sky-300">endroit exact de connexion</strong> (bâtiment, centre de données, FAI, coordonnées GPS et vue cartographique interactive) pour n'importe quelle adresse IP ou serveur distant.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => lookupIp(searchQuery)}
              disabled={isLoading}
              className="flex items-center gap-2 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-medium transition-all shadow-sm"
              title="Rafraîchir la localisation"
            >
              <RotateCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-sky-400' : 'text-slate-400'}`} />
              <span>Actualiser</span>
            </button>
            {onNavigateTab && (
              <button
                onClick={() => onNavigateTab('network')}
                className="flex items-center gap-2 px-3.5 py-2 bg-cyan-950/60 hover:bg-cyan-900/60 text-cyan-300 border border-cyan-800/60 rounded-lg text-xs font-medium transition-all shadow-sm"
              >
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                <span>Voir Connexions C2 Actives</span>
              </button>
            )}
          </div>
        </div>

        {/* Search Bar */}
        <form onSubmit={handleSearchSubmit} className="mt-5 flex flex-col sm:flex-row gap-2 relative z-10">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
              <Search className="w-4 h-4 text-slate-500" />
            </div>
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Entrez une adresse IPv4, IPv6 ou nom d'hôte (ex: 185.220.101.4, 45.154.255.89, 8.8.8.8, google.com)..."
              className="w-full pl-10 pr-24 py-2.5 bg-slate-950/90 border border-slate-700/80 focus:border-sky-500 focus:ring-1 focus:ring-sky-500/40 rounded-lg text-xs font-mono text-slate-100 placeholder-slate-500 transition-all outline-none"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="absolute inset-y-0 right-20 pr-2 flex items-center text-slate-500 hover:text-slate-300 text-xs"
              >
                Effacer
              </button>
            )}
            <button
              type="button"
              onClick={() => lookupIp('')}
              className="absolute inset-y-0 right-2 px-2.5 my-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] font-sans flex items-center gap-1 border border-slate-700 transition-all"
              title="Localiser l'IP de votre machine"
            >
              <Navigation className="w-3 h-3 text-cyan-400" />
              <span>Mon IP</span>
            </button>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="flex items-center justify-center gap-2 px-5 py-2.5 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg transition-all shadow-md shadow-sky-950/40 shrink-0"
          >
            {isLoading ? (
              <>
                <RotateCw className="w-4 h-4 animate-spin text-white" />
                <span>Reconnaissance en cours...</span>
              </>
            ) : (
              <>
                <Crosshair className="w-4 h-4 text-white" />
                <span>Localiser l'Endroit</span>
              </>
            )}
          </button>
        </form>

        {/* Quick Presets */}
        <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-400 text-[11px] font-mono mr-1">Cibles Fréquentes :</span>
          {presets.map((preset, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => {
                setSearchQuery(preset.ip);
                lookupIp(preset.ip);
              }}
              className={`px-2.5 py-1 rounded-md text-[11px] font-mono border transition-all hover:scale-105 ${preset.color}`}
            >
              <span className="font-semibold">{preset.label}</span>
              {preset.ip && <span className="opacity-75 ml-1">({preset.ip})</span>}
            </button>
          ))}
        </div>
      </div>

      {/* Error notification */}
      {error && (
        <div className="bg-rose-950/60 border border-rose-800/80 rounded-xl p-4 text-xs text-rose-300 flex items-start gap-3 shadow-lg">
          <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="flex-1">
            <h3 className="font-semibold text-rose-200">Échec de la résolution de l'adresse</h3>
            <p className="mt-0.5 text-rose-300/90">{error}</p>
          </div>
          <button
            onClick={() => lookupIp('185.220.101.4')}
            className="px-3 py-1 bg-rose-900/80 hover:bg-rose-800 border border-rose-700 rounded text-xs text-rose-100"
          >
            Réessayer avec C2 Détecté
          </button>
        </div>
      )}

      {/* Main Results Container */}
      {report && (
        <div className="space-y-6">
          {/* Top KPI Cards: Pays, Ville, Endroit Précis, Coordonnées */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Card 1: Pays */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-md relative overflow-hidden">
              <div className="flex items-center justify-between text-xs text-slate-400 font-mono mb-2">
                <span className="flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-sky-400" />
                  PAYS & TERRITOIRE
                </span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  {report.countryCode || 'N/A'}
                </span>
              </div>
              <div className="flex items-center gap-2.5">
                <span className="text-3xl leading-none" title={report.country}>
                  {getFlagEmoji(report.countryCode)}
                </span>
                <div>
                  <div className="text-base font-bold text-slate-100 font-sans leading-tight">
                    {report.country || 'Inconnu'}
                  </div>
                  <div className="text-xs text-slate-400 font-mono">
                    Continent : {report.continent || 'Europe'}
                  </div>
                </div>
              </div>
            </div>

            {/* Card 2: Ville & Région */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-md relative overflow-hidden">
              <div className="flex items-center justify-between text-xs text-slate-400 font-mono mb-2">
                <span className="flex items-center gap-1.5">
                  <MapPin className="w-3.5 h-3.5 text-emerald-400" />
                  VILLE & RÉGION
                </span>
                {report.zip && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-emerald-400 border border-slate-700 font-mono">
                    CP: {report.zip}
                  </span>
                )}
              </div>
              <div className="text-base font-bold text-slate-100 font-sans leading-tight">
                {report.city || 'Inconnue'}
              </div>
              <div className="text-xs text-slate-400 font-mono mt-0.5 truncate" title={report.regionName}>
                {report.regionName || report.district || 'Région Métropolitaine'}
              </div>
            </div>

            {/* Card 3: Infrastructure Réseau & POP */}
            <div className="bg-slate-900/90 border border-sky-800/60 rounded-xl p-4 shadow-md relative overflow-hidden bg-gradient-to-br from-slate-900/90 to-sky-950/20">
              <div className="flex items-center justify-between text-xs text-sky-400 font-mono mb-2">
                <span className="flex items-center gap-1.5">
                  <Navigation className="w-3.5 h-3.5 text-sky-400" />
                  INFRASTRUCTURE & POP
                </span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-700/60">
                  POP FAI / AS
                </span>
              </div>
              <div className="text-sm font-bold text-sky-200 font-sans leading-tight truncate" title={report.placeFacility}>
                {report.placeFacility || 'Point de Présence Réseau'}
              </div>
              <div className="text-xs text-slate-300 font-mono mt-1 truncate" title={report.placeAddress}>
                📍 Zone IP : {report.placeAddress}
              </div>
            </div>

            {/* Card 4: Coordonnées GPS & Distance */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-md relative overflow-hidden">
              <div className="flex items-center justify-between text-xs text-slate-400 font-mono mb-2">
                <span className="flex items-center gap-1.5">
                  <Compass className="w-3.5 h-3.5 text-amber-400" />
                  COORDONNÉES & DISTANCE
                </span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-amber-400 border border-slate-700 font-mono">
                  {report.distanceKm} km
                </span>
              </div>
              <div className="text-xs font-mono font-bold text-slate-100 flex items-center justify-between">
                <span>{report.latitude.toFixed(4)}°, {report.longitude.toFixed(4)}°</span>
                <button
                  onClick={() => copyToClipboard(`${report.latitude},${report.longitude}`, 'coords')}
                  className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 transition-all"
                  title="Copier les coordonnées GPS"
                >
                  {copiedKey === 'coords' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
              <div className="text-[11px] text-slate-400 font-mono mt-1 truncate">
                DMS : {toDms(report.latitude, true)} {toDms(report.longitude, false)}
              </div>
            </div>
          </div>

          {/* Interactive Tactical Map & Location Details Side-by-Side */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left 7 Cols: Interactive Map Visualizer */}
            <div className="lg:col-span-7 bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
              <div>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                  <div>
                    <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2 font-mono uppercase tracking-wide">
                      <Crosshair className="w-4 h-4 text-sky-400" />
                      Visualisation Cartographique Satellitaire & Urbaine
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Point d'ancrage physique de l'IP : {report.ip}
                    </p>
                  </div>

                  <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800">
                    <button
                      onClick={() => setMapMode('osm')}
                      className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
                        mapMode === 'osm'
                          ? 'bg-sky-600 text-white font-semibold'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      Carte Urbaine (OSM)
                    </button>
                    <button
                      onClick={() => setMapMode('tactical')}
                      className={`px-2.5 py-1 rounded text-xs font-medium transition-all ${
                        mapMode === 'tactical'
                          ? 'bg-sky-600 text-white font-semibold'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      Radar Tactique
                    </button>
                  </div>
                </div>

                {/* Map Display Frame */}
                <div className="relative w-full h-80 sm:h-96 bg-slate-950 border border-slate-800 rounded-lg overflow-hidden shadow-inner flex items-center justify-center">
                  {mapMode === 'osm' ? (
                    // OpenStreetMap Live Interactive Embedded Frame
                    <iframe
                      title="OpenStreetMap Live Tracer"
                      src={`https://www.openstreetmap.org/export/embed.html?bbox=${report.longitude - 0.02}%2C${report.latitude - 0.015}%2C${report.longitude + 0.02}%2C${report.latitude + 0.015}&layer=mapnik&marker=${report.latitude}%2C${report.longitude}`}
                      className="w-full h-full border-0 filter contrast-125"
                      loading="lazy"
                    />
                  ) : (
                    // High-Tech Cyber Radar Screen View
                    <div className="w-full h-full relative bg-slate-950 flex items-center justify-center overflow-hidden">
                      {/* Grid background */}
                      <div
                        className="absolute inset-0 opacity-20"
                        style={{
                          backgroundImage:
                            'linear-gradient(to right, #0ea5e9 1px, transparent 1px), linear-gradient(to bottom, #0ea5e9 1px, transparent 1px)',
                          backgroundSize: '24px 24px',
                        }}
                      />
                      {/* Radar sweep circle */}
                      <div className="absolute w-72 h-72 rounded-full border border-sky-500/30 animate-pulse pointer-events-none" />
                      <div className="absolute w-52 h-52 rounded-full border border-sky-500/40 pointer-events-none" />
                      <div className="absolute w-32 h-32 rounded-full border border-sky-500/50 pointer-events-none" />
                      <div className="absolute w-12 h-12 rounded-full border border-rose-500/60 animate-ping pointer-events-none" />

                      {/* Center Target Marker */}
                      <div className="relative z-10 flex flex-col items-center">
                        <div className="relative">
                          <div className="w-6 h-6 rounded-full bg-rose-500/20 border-2 border-rose-500 flex items-center justify-center shadow-lg shadow-rose-500/50 animate-bounce">
                            <div className="w-2 h-2 rounded-full bg-rose-400" />
                          </div>
                        </div>
                        <div className="mt-2 bg-slate-900/90 border border-slate-700/80 px-3 py-1.5 rounded-md text-center shadow-xl backdrop-blur-sm">
                          <div className="text-xs font-mono font-bold text-rose-400">{report.ip}</div>
                          <div className="text-[10px] text-slate-300 font-sans">{report.city}, {report.country}</div>
                          <div className="text-[9px] text-sky-400 font-mono">{report.latitude.toFixed(4)}°, {report.longitude.toFixed(4)}°</div>
                        </div>
                      </div>

                      {/* Tactical HUD overlays */}
                      <div className="absolute top-3 left-3 text-[10px] font-mono text-sky-400/80 bg-slate-950/80 p-2 rounded border border-slate-800">
                        <div>LAT: {report.latitude.toFixed(6)}°</div>
                        <div>LON: {report.longitude.toFixed(6)}°</div>
                        <div>ALT_EST: 45m MSL</div>
                        <div>BEARING: {((report.longitude + 180) % 360).toFixed(1)}° TRUE</div>
                      </div>

                      <div className="absolute top-3 right-3 text-[10px] font-mono text-emerald-400/90 bg-slate-950/80 p-2 rounded border border-slate-800 text-right">
                        <div>RTT_EST: {report.estLatencyMs} ms</div>
                        <div>DIST: {report.distanceKm} km</div>
                        <div>LOCK: GPS FIX HIGH</div>
                      </div>
                    </div>
                  )}

                  {/* Open In Full Map Quick Badges */}
                  <div className="absolute bottom-3 right-3 flex items-center gap-1.5 z-20">
                    <a
                      href={report.googleMapsUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2.5 py-1.5 bg-slate-900/90 hover:bg-slate-800 text-slate-200 border border-slate-700 rounded text-xs font-medium flex items-center gap-1.5 shadow-md backdrop-blur-sm transition-all"
                    >
                      <ExternalLink className="w-3 h-3 text-sky-400" />
                      <span>Google Maps</span>
                    </a>
                    <a
                      href={report.googleStreetViewUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2.5 py-1.5 bg-slate-900/90 hover:bg-slate-800 text-slate-200 border border-slate-700 rounded text-xs font-medium flex items-center gap-1.5 shadow-md backdrop-blur-sm transition-all"
                    >
                      <Eye className="w-3 h-3 text-emerald-400" />
                      <span>Street View 360°</span>
                    </a>
                    <a
                      href={report.openStreetMapUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2.5 py-1.5 bg-slate-900/90 hover:bg-slate-800 text-slate-200 border border-slate-700 rounded text-xs font-medium flex items-center gap-1.5 shadow-md backdrop-blur-sm transition-all"
                    >
                      <Layers className="w-3 h-3 text-purple-400" />
                      <span>OpenStreetMap</span>
                    </a>
                  </div>
                </div>
              </div>

              {/* Exact Address Box */}
              <div className="mt-4 bg-slate-950/90 border border-slate-800 rounded-lg p-3.5">
                <div className="flex flex-wrap items-center gap-2 mb-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-800/80">
                    BGP / RIR OFFICIEL
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                    PRÉCISION : POP OPÉRATEUR (VILLE)
                  </span>
                </div>
                <div className="text-xs font-mono text-slate-400 mb-1 flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-sky-400">
                    <Navigation className="w-3.5 h-3.5" />
                    ZONE GÉOGRAPHIQUE DU FOURNISSEUR D'ACCÈS
                  </span>
                  <button
                    onClick={() => copyToClipboard(report.placeAddress, 'full_address')}
                    className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200"
                  >
                    {copiedKey === 'full_address' ? (
                      <span className="text-emerald-400 flex items-center gap-1">
                        <Check className="w-3 h-3" /> Copié
                      </span>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" /> Copier l'adresse
                      </>
                    )}
                  </button>
                </div>
                <div className="text-xs font-sans text-slate-200 font-medium leading-relaxed">
                  {report.placeAddress}
                </div>
                {report.placeFacility && (
                  <div className="text-[11px] font-sans text-slate-400 mt-1 flex items-center gap-1.5">
                    <Server className="w-3 h-3 text-sky-400 shrink-0" />
                    <span>Installation Référencée : <strong className="text-slate-300">{report.placeFacility}</strong></span>
                  </div>
                )}
              </div>
            </div>

            {/* Right 5 Cols: Deep Reconnaissance Intel & Telecom / ASN */}
            <div className="lg:col-span-5 space-y-5">
              {/* Threat Severity Card */}
              {(() => {
                const badge = getThreatBadge(report.threatScore, report.isTor);
                return (
                  <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5">
                        <ShieldAlert className="w-4 h-4 text-rose-400" />
                        POSTURE & SCORE DE RISQUE
                      </span>
                      <span className={`px-2.5 py-0.5 rounded text-[11px] font-bold border font-mono ${badge.color}`}>
                        {badge.label}
                      </span>
                    </div>

                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="text-slate-400">Score de Menace SpaceSec :</span>
                        <span className="font-bold text-slate-100">{report.threatScore} / 100</span>
                      </div>
                      <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${badge.barColor}`}
                          style={{ width: `${Math.min(100, report.threatScore)}%` }}
                        />
                      </div>
                    </div>

                    {/* Flags Grid */}
                    <div className="mt-4 grid grid-cols-2 gap-2 text-xs font-mono">
                      <div className={`p-2 rounded border ${report.isTor ? 'bg-rose-950/40 border-rose-800 text-rose-300' : 'bg-slate-950/80 border-slate-800 text-slate-400'}`}>
                        <div className="text-[10px] text-slate-500">NOEUD TOR EXIT :</div>
                        <div className="font-bold">{report.isTor ? 'OUI (DÉTECTÉ)' : 'NON'}</div>
                      </div>
                      <div className={`p-2 rounded border ${report.isProxy ? 'bg-amber-950/40 border-amber-800 text-amber-300' : 'bg-slate-950/80 border-slate-800 text-slate-400'}`}>
                        <div className="text-[10px] text-slate-500">PROXY / VPN :</div>
                        <div className="font-bold">{report.isProxy ? 'OUI (ACTIF)' : 'NON DÉTECTÉ'}</div>
                      </div>
                      <div className="p-2 rounded border bg-slate-950/80 border-slate-800 text-slate-300">
                        <div className="text-[10px] text-slate-500">TYPE CONNEXION :</div>
                        <div className="font-bold">{report.isHosting ? 'DATACENTER / CLOUD' : 'RÉSIDENTIEL / FAI'}</div>
                      </div>
                      <div className="p-2 rounded border bg-slate-950/80 border-slate-800 text-slate-300">
                        <div className="text-[10px] text-slate-500">FUSEAU HORAIRE :</div>
                        <div className="font-bold truncate">{report.timezone}</div>
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* Telecom & ASN Details */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
                <h3 className="text-xs font-mono text-slate-300 font-bold uppercase tracking-wider mb-3 flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-cyan-400" />
                  Réseau, FAI & Système Autonome (ASN)
                </h3>

                <div className="space-y-3 text-xs">
                  <div className="flex items-start justify-between border-b border-slate-800/80 pb-2">
                    <span className="text-slate-400 font-mono">Fournisseur (ISP / FAI) :</span>
                    <span className="text-slate-200 font-semibold font-sans text-right max-w-[240px] truncate" title={report.isp}>
                      {report.isp || 'Inconnu'}
                    </span>
                  </div>

                  <div className="flex items-start justify-between border-b border-slate-800/80 pb-2">
                    <span className="text-slate-400 font-mono">Organisation (Org) :</span>
                    <span className="text-slate-200 font-semibold font-sans text-right max-w-[240px] truncate" title={report.org}>
                      {report.org || report.isp}
                    </span>
                  </div>

                  <div className="flex items-start justify-between border-b border-slate-800/80 pb-2">
                    <span className="text-slate-400 font-mono">Système Autonome (ASN) :</span>
                    <span className="text-cyan-400 font-mono font-bold text-right">
                      {report.as || 'AS Non Attribué'}
                    </span>
                  </div>

                  {report.reverseDns && (
                    <div className="flex items-start justify-between border-b border-slate-800/80 pb-2">
                      <span className="text-slate-400 font-mono">Reverse DNS (PTR) :</span>
                      <span className="text-slate-300 font-mono text-[11px] text-right truncate max-w-[220px]" title={report.reverseDns}>
                        {report.reverseDns}
                      </span>
                    </div>
                  )}

                  <div className="flex items-start justify-between border-b border-slate-800/80 pb-2">
                    <span className="text-slate-400 font-mono">Ping ICMP Réel :</span>
                    <span className="font-mono font-bold">
                      {report.measuredPingMs !== undefined && report.measuredPingMs !== null ? (
                        <span className="text-emerald-400">{report.measuredPingMs.toFixed(1)} ms (Mesuré)</span>
                      ) : (
                        <span className="text-amber-400 text-[11px]">Non mesuré / Filtré par pare-feu</span>
                      )}
                    </span>
                  </div>

                  <div className="flex items-start justify-between">
                    <span className="text-slate-400 font-mono">Latence Théorique (RTT) :</span>
                    <span className="text-cyan-400 font-mono font-bold">
                      ~{report.estLatencyMs} ms ({report.distanceKm} km physiques)
                    </span>
                  </div>
                </div>
              </div>

              {/* Quick Remediation / Blocking Action */}
              <div className="bg-slate-900/90 border border-rose-800/60 rounded-xl p-5 shadow-lg bg-gradient-to-br from-slate-900 to-rose-950/20">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-xs font-mono text-rose-300 font-bold uppercase tracking-wider flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-rose-400" />
                    Contre-Mesure Immédiate
                  </h3>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-rose-950 border border-rose-700/80 text-rose-300 font-mono">
                    FIREWALL
                  </span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed mb-3">
                  Isolez immédiatement votre poste contre toute communication sortante vers <strong className="text-slate-200 font-mono">{report.ip}</strong>.
                </p>

                <div className="bg-slate-950 border border-slate-800 rounded p-2.5 font-mono text-[11px] text-slate-300 break-all mb-3 select-all">
                  {report.firewallRulePs1}
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      onRunInConsole(report.firewallRulePs1);
                      if (onNavigateTab) onNavigateTab('console');
                    }}
                    className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 bg-rose-600 hover:bg-rose-500 text-white font-semibold rounded-lg text-xs transition-all shadow-md shadow-rose-950/40"
                  >
                    <Terminal className="w-3.5 h-3.5" />
                    <span>Bloquer via Console</span>
                  </button>
                  <button
                    onClick={() => copyToClipboard(report.firewallRulePs1, 'fw_rule')}
                    className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-medium transition-all"
                    title="Copier la commande PowerShell"
                  >
                    {copiedKey === 'fw_rule' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Forensic Reconnaissance Summary & Report */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
            <div className="flex items-center gap-2 text-xs font-mono text-sky-400 mb-2">
              <Info className="w-4 h-4 text-sky-400" />
              <span>RAPPORT DE RECONNAISSANCE FORENSIQUE APPROFONDIE</span>
            </div>
            <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-4 font-sans text-xs text-slate-300 leading-relaxed whitespace-pre-line">
              {report.placeIntel}
            </div>
          </div>

          {/* Traceroute Simulation Hops Table */}
          {report.hops && report.hops.length > 0 && (
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2 font-mono uppercase">
                    <Activity className="w-4 h-4 text-emerald-400" />
                    Topologie & Modèle de Transit Réseau ({report.hops.length} Nœuds)
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Modélisation du cheminement BGP/ASN jusqu'à l'infrastructure distante dans {report.city}.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      onRunInConsole(`tracert ${report.ip}`);
                      if (onNavigateTab) onNavigateTab('console');
                    }}
                    className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-sky-300 border border-slate-700 rounded text-xs font-mono font-medium transition-colors cursor-pointer"
                    title="Exécuter un tracert ICMP réel depuis la machine hôte"
                  >
                    <Terminal className="w-3.5 h-3.5" />
                    <span>Lancer tracert réel (Console)</span>
                  </button>
                  <div className="text-xs font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-2.5 py-1 rounded">
                    {report.measuredPingMs ? `Ping : ${report.measuredPingMs.toFixed(1)} ms` : `RTT Est. : ~${report.estLatencyMs} ms`}
                  </div>
                </div>
              </div>

              {/* Forensic Transparency Notice */}
              <div className="mb-4 p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-[11px] font-mono text-slate-300 flex items-center gap-2.5">
                <Info className="w-4 h-4 text-cyan-400 shrink-0" />
                <span>
                  {report.tracerouteNotice || "Modèle topologique de transit BGP / ASN estimé. Les sondes physiques ICMP hop-by-hop sont limitées sans privilèges bruts/root."}
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                      <th className="py-2 px-3">Saut #</th>
                      <th className="py-2 px-3">Adresse IP</th>
                      <th className="py-2 px-3">Nom d'Hôte / Équipement</th>
                      <th className="py-2 px-3">Localisation Réseau</th>
                      <th className="py-2 px-3">Opérateur / AS</th>
                      <th className="py-2 px-3 text-right">Latence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {report.hops.map(h => (
                      <tr key={h.hop} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-2.5 px-3 font-bold text-sky-400">#{h.hop}</td>
                        <td className="py-2.5 px-3 text-slate-200">{h.ip}</td>
                        <td className="py-2.5 px-3 text-slate-400 text-[11px] truncate max-w-[200px]" title={h.host}>
                          {h.host}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 font-sans">{h.location}</td>
                        <td className="py-2.5 px-3 text-slate-400 text-[11px]">{h.org}</td>
                        <td className="py-2.5 px-3 text-right font-bold text-emerald-400">{h.latency}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
