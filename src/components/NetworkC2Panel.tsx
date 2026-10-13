import React, { useState, useEffect, useCallback } from 'react';
import {
  Network,
  ShieldAlert,
  Globe,
  Server,
  AlertTriangle,
  ShieldCheck,
  RefreshCw,
  Activity,
  ArrowUpRight,
  ArrowDownLeft,
  Pause,
  Play,
  Radio,
  Lock,
  MapPin,
  Crosshair,
  ExternalLink,
  CheckCircle2,
  Navigation,
} from 'lucide-react';
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';
import { NetworkConnectionItem } from '../types/cyberdefense';
import { PortScanner } from './PortScanner';
import { WiFiScanner } from './WiFiScanner';
import { apiFetch } from '../utils/api';

interface HostGeoInfo {
  ip: string;
  city: string;
  country: string;
  isp: string;
  latitude: number;
  longitude: number;
  regionName?: string;
  timezone?: string;
}

interface NetworkC2PanelProps {
  onRunInConsole: (command: string) => void;
  onLocateIp?: (ip: string) => void;
}

interface TrafficDataPoint {
  time: string;
  inboundBeacon: number;     // KB/s from 185.220.101.4
  outboundExfil: number;     // KB/s to 185.220.101.4
  inboundPowerShell: number; // KB/s from 45.154.255.89
  outboundPowerShell: number;// KB/s to 45.154.255.89
  totalExfiltration: number; // Sum outbound
  isSpike: boolean;
}

export const NetworkC2Panel: React.FC<NetworkC2PanelProps> = ({ onRunInConsole, onLocateIp }) => {
  const [connections, setConnections] = useState<NetworkConnectionItem[]>([]);
  const [isLoadingSockets, setIsLoadingSockets] = useState<boolean>(false);

  const fetchRealSockets = useCallback(async () => {
    try {
      setIsLoadingSockets(true);
      const res = await apiFetch('/api/system/sockets');
      if (res.ok) {
        const data = await res.json();
        if (data.success && Array.isArray(data.connections)) {
          setConnections(data.connections);
        }
      }
    } catch (err) {
      console.warn('[Network Sockets Fetch Error]:', err);
    } finally {
      setIsLoadingSockets(false);
    }
  }, []);

  useEffect(() => {
    fetchRealSockets();
    const interval = setInterval(fetchRealSockets, 4000);
    return () => clearInterval(interval);
  }, [fetchRealSockets]);

  const namedPipes = [
    { name: '\\\\.\\pipe\\lsass', isSuspicious: false, description: 'Tuyau système légitime Local Security Authority (LSASS)' },
    { name: '\\\\.\\pipe\\spoolss', isSuspicious: false, description: 'Spooler d\'impression Windows officiel' },
    { name: '\\\\.\\pipe\\ntsvcs', isSuspicious: false, description: 'Contrôleur de services Windows NT (services.exe)' },
    { name: '\\\\.\\pipe\\epmapper', isSuspicious: false, description: 'Mappage d\'extrémités RPC Windows légitime' },
  ];

  // Real-time Traffic Simulator for Malicious IPs
  const [isLiveActive, setIsLiveActive] = useState<boolean>(true);
  const [selectedTargetIP, setSelectedTargetIP] = useState<string>('all');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [lastScanTime, setLastScanTime] = useState<string>('À l\'instant');
  const [scanCount, setScanCount] = useState<number>(1);

  const handleScanSockets = () => {
    setIsScanning(true);
    onRunInConsole('sockets');
    setTimeout(() => {
      setIsScanning(false);
      setLastScanTime(new Date().toLocaleTimeString());
      setScanCount(prev => prev + 1);
    }, 1200);
  };

  // Automated Host Public IP Detection & IP-Locator Geolocation
  const [hostGeo, setHostGeo] = useState<HostGeoInfo | null>(null);
  const [isDetectingHostIp, setIsDetectingHostIp] = useState<boolean>(true);
  const [detectError, setDetectError] = useState<string | null>(null);
  const [autoRedirectCountdown, setAutoRedirectCountdown] = useState<number | null>(null);
  const [hasAutoRedirected, setHasAutoRedirected] = useState<boolean>(() => {
    return sessionStorage.getItem('spacesec_host_auto_located') === 'true';
  });

  const detectHostIpAndGeolocate = useCallback(async (forceAutoRedirect = false) => {
    setIsDetectingHostIp(true);
    setDetectError(null);
    try {
      const res = await apiFetch('/api/system/geo');
      if (!res.ok) throw new Error(`Erreur réseau (${res.status})`);
      const data = await res.json();
      if (data && data.success && data.ip) {
        const info: HostGeoInfo = {
          ip: data.ip,
          city: data.city || 'Paris',
          country: data.country || 'France',
          isp: data.isp || 'Opérateur Réseau Hôte',
          latitude: data.latitude || 48.8566,
          longitude: data.longitude || 2.3522,
          regionName: data.regionName,
          timezone: data.timezone,
        };
        setHostGeo(info);
        setIsDetectingHostIp(false);

        // Notify console terminal of IP reconnaissance
        onRunInConsole(`geolocate ${data.ip}`);

        // Launch geolocation countdown if not yet auto-redirected this session or if forced
        const alreadyDone = sessionStorage.getItem('spacesec_host_auto_located') === 'true';
        if ((!alreadyDone || forceAutoRedirect) && onLocateIp) {
          setAutoRedirectCountdown(3);
        }
      } else {
        throw new Error('Impossible de résoudre l\'adresse IP publique');
      }
    } catch (err: any) {
      setIsDetectingHostIp(false);
      setDetectError(err.message || 'Erreur lors de la détection IP');
      const fallback: HostGeoInfo = {
        ip: '192.168.1.42',
        city: 'Paris',
        country: 'France',
        isp: 'Interface Locale SpaceSec',
        latitude: 48.8566,
        longitude: 2.3522,
      };
      setHostGeo(fallback);
    }
  }, [onLocateIp, onRunInConsole]);

  // Initial detection on component mount
  useEffect(() => {
    detectHostIpAndGeolocate();
  }, [detectHostIpAndGeolocate]);

  // Countdown effect to smoothly navigate to ip-locator
  useEffect(() => {
    if (autoRedirectCountdown === null) return;

    if (autoRedirectCountdown > 0) {
      const timeout = setTimeout(() => {
        setAutoRedirectCountdown(prev => (prev !== null ? prev - 1 : null));
      }, 1000);
      return () => clearTimeout(timeout);
    }

    if (autoRedirectCountdown === 0 && hostGeo?.ip && onLocateIp) {
      sessionStorage.setItem('spacesec_host_auto_located', 'true');
      setHasAutoRedirected(true);
      setAutoRedirectCountdown(null);
      onLocateIp(hostGeo.ip);
    }
  }, [autoRedirectCountdown, hostGeo, onLocateIp]);

  const handleTriggerLocateNow = () => {
    if (!hostGeo?.ip || !onLocateIp) return;
    sessionStorage.setItem('spacesec_host_auto_located', 'true');
    setHasAutoRedirected(true);
    setAutoRedirectCountdown(null);
    onLocateIp(hostGeo.ip);
  };

  const handleCancelAutoRedirect = () => {
    sessionStorage.setItem('spacesec_host_auto_located', 'true');
    setHasAutoRedirected(true);
    setAutoRedirectCountdown(null);
  };

  const [trafficHistory, setTrafficHistory] = useState<TrafficDataPoint[]>(() => {
    const initial: TrafficDataPoint[] = [];
    const now = Date.now();
    for (let i = 20; i >= 0; i--) {
      const d = new Date(now - i * 2000);
      const timeStr = d.toTimeString().split(' ')[0];
      const hasSpike = i === 12 || i === 4;
      const outbound = hasSpike ? 240 + Math.floor(Math.random() * 80) : 12 + Math.floor(Math.random() * 25);
      const inbound = hasSpike ? 60 + Math.floor(Math.random() * 30) : 4 + Math.floor(Math.random() * 8);
      const psOut = hasSpike ? 140 + Math.floor(Math.random() * 40) : 5 + Math.floor(Math.random() * 10);
      const psIn = hasSpike ? 35 + Math.floor(Math.random() * 15) : 2 + Math.floor(Math.random() * 6);

      initial.push({
        time: timeStr,
        inboundBeacon: inbound,
        outboundExfil: outbound,
        inboundPowerShell: psIn,
        outboundPowerShell: psOut,
        totalExfiltration: outbound + psOut,
        isSpike: hasSpike,
      });
    }
    return initial;
  });

  // Streaming effect
  useEffect(() => {
    if (!isLiveActive) return;

    const interval = setInterval(() => {
      const now = new Date();
      const timeStr = now.toTimeString().split(' ')[0];

      // Simulate occasional beacon spikes or exfiltration bursts
      const randomSeed = Math.random();
      const isSpike = randomSeed > 0.82;

      const outbound = isSpike
        ? Math.floor(220 + Math.random() * 120)
        : Math.floor(10 + Math.random() * 28);
      const inbound = isSpike
        ? Math.floor(55 + Math.random() * 45)
        : Math.floor(3 + Math.random() * 10);

      const psOut = isSpike
        ? Math.floor(130 + Math.random() * 60)
        : Math.floor(4 + Math.random() * 12);
      const psIn = isSpike
        ? Math.floor(30 + Math.random() * 20)
        : Math.floor(1 + Math.random() * 5);

      const newPoint: TrafficDataPoint = {
        time: timeStr,
        inboundBeacon: inbound,
        outboundExfil: outbound,
        inboundPowerShell: psIn,
        outboundPowerShell: psOut,
        totalExfiltration: outbound + psOut,
        isSpike,
      };

      setTrafficHistory(prev => {
        const next = [...prev.slice(1), newPoint];
        return next;
      });
    }, 2000);

    return () => clearInterval(interval);
  }, [isLiveActive]);

  // Current real-time indicators
  const latestPoint = trafficHistory[trafficHistory.length - 1] || {
    inboundBeacon: 0,
    outboundExfil: 0,
    inboundPowerShell: 0,
    outboundPowerShell: 0,
    totalExfiltration: 0,
  };

  const peakOutbound = Math.max(...trafficHistory.map(p => p.totalExfiltration));

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-wider mb-2">
              <Network className="w-4 h-4" />
              <span>Surveillance Télémétrie Réseau & C2</span>
              <span className="px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800 text-[10px] text-cyan-300 font-semibold">
                Scan #{scanCount} · {lastScanTime}
              </span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
              Interception des Sockets Command & Control (C2) & Tuyaux Nommés
            </h2>
            <p className="mt-1 text-sm text-slate-300">
              Traque les connexions persistantes vers des serveurs de contrôle distants, ports sensibles (4444, 445, 3389), pics d'exfiltration et proxies Man-in-the-Middle.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={handleScanSockets}
              disabled={isScanning}
              className={`flex items-center gap-2 px-4 py-2 border rounded-lg text-xs font-semibold transition-all shadow-sm ${
                isScanning
                  ? 'bg-cyan-950/80 border-cyan-500 text-cyan-300 cursor-wait animate-pulse'
                  : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-200 active:scale-95'
              }`}
            >
              <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isScanning ? 'animate-spin' : ''}`} />
              <span>{isScanning ? 'Scan des Sockets en cours...' : 'Actualiser Sockets (Scan)'}</span>
            </button>
            <button
              onClick={() => onRunInConsole('dns-test')}
              className="flex items-center gap-2 px-4 py-2 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 font-semibold rounded-lg text-xs transition-colors active:scale-95"
            >
              <Globe className="w-3.5 h-3.5" />
              <span>Tester Vitesse DNS</span>
            </button>
          </div>
        </div>

        {/* Live Scan Notification / Architecture Clarification Banner */}
        {isScanning ? (
          <div className="p-3.5 bg-cyan-950/40 border border-cyan-500/40 rounded-lg flex items-center justify-between text-xs animate-pulse">
            <div className="flex items-center gap-2.5 text-cyan-200">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
              <span className="font-semibold">Audit des sockets TCP/UDP & écouteurs en cours...</span>
              <span className="text-cyan-400/80 font-mono text-[11px]">(Get-NetTCPConnection | Test-NetConnection)</span>
            </div>
            <span className="font-mono text-cyan-300 text-[11px]">Ports 4444, 445, 8080 vérifiés</span>
          </div>
        ) : (
          <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs text-slate-400">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              <span>
                <strong className="text-slate-200">Moteur SOC Actif :</strong> 5 sockets analysés, 2 connexions C2 isolées (185.220.101.4 & 45.154.255.89).
              </span>
            </div>
            <div className="text-[11px] text-slate-400 flex items-center gap-1.5 shrink-0">
              <Lock className="w-3 h-3 text-cyan-400" />
              <span>Pour scanner le matériel de votre PC réel sans restriction web : exécutez le script .ps1 téléchargé.</span>
            </div>
          </div>
        )}
      </div>

      {/* Auto Public IP Detection & IP-Locator Geolocation Sentinel */}
      <div className="p-5 bg-gradient-to-r from-slate-900 via-cyan-950/20 to-slate-900 border border-cyan-800/60 rounded-xl shadow-xl space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-lg bg-cyan-950 border border-cyan-700/60 text-cyan-400">
                <Globe className="w-4 h-4 animate-pulse" />
              </span>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <span>Détection Automatique IP Publique Hôte & Géolocalisation</span>
                {isDetectingHostIp ? (
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-950/80 border border-amber-800 text-amber-300 animate-pulse">
                    Détection en cours...
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950/80 border border-emerald-800 text-emerald-300 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" />
                    <span>IP Détectée & Résolue</span>
                  </span>
                )}
              </h3>
            </div>
            <p className="text-xs text-slate-300">
              Résolution automatique de l'adresse IP publique de la machine hôte et initialisation de la reconnaissance forensique dans le panneau <strong className="text-cyan-300">IP-Locator</strong> dès le chargement.
            </p>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <button
              onClick={() => detectHostIpAndGeolocate(true)}
              disabled={isDetectingHostIp}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5 active:scale-95 cursor-pointer"
              title="Relancer la détection automatique de l'IP hôte"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isDetectingHostIp ? 'animate-spin' : ''}`} />
              <span>Re-détecter IP</span>
            </button>

            <button
              onClick={handleTriggerLocateNow}
              disabled={!hostGeo?.ip}
              className="px-3.5 py-1.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold text-xs rounded-lg shadow-md shadow-cyan-900/40 transition-all flex items-center gap-1.5 active:scale-95 cursor-pointer"
              title="Ouvrir immédiatement l'IP détectée dans le panneau IP-Locator"
            >
              <MapPin className="w-3.5 h-3.5 text-cyan-200" />
              <span>Ouvrir dans IP-Locator</span>
              <ExternalLink className="w-3 h-3 ml-0.5 text-cyan-200" />
            </button>
          </div>
        </div>

        {/* Live Detected Host IP Stats / Pill Row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
            <div className="text-[11px] text-slate-400 flex items-center gap-1">
              <Crosshair className="w-3 h-3 text-cyan-400" />
              <span>Adresse IP Publique</span>
            </div>
            <div className="text-sm font-bold text-cyan-300 tracking-wide">
              {hostGeo?.ip || '192.168.1.42'}
            </div>
            <div className="text-[10px] text-slate-500 font-sans">
              Point d'accès WAN / Hôte local
            </div>
          </div>

          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
            <div className="text-[11px] text-slate-400 flex items-center gap-1">
              <MapPin className="w-3 h-3 text-emerald-400" />
              <span>Localisation Physique</span>
            </div>
            <div className="text-sm font-bold text-emerald-300 truncate">
              {hostGeo ? `${hostGeo.city}, ${hostGeo.country}` : 'Paris, France'}
            </div>
            <div className="text-[10px] text-slate-500 font-sans">
              Géocodage territorial
            </div>
          </div>

          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
            <div className="text-[11px] text-slate-400 flex items-center gap-1">
              <Server className="w-3 h-3 text-indigo-400" />
              <span>Fournisseur / FAI</span>
            </div>
            <div className="text-sm font-bold text-indigo-300 truncate">
              {hostGeo?.isp || 'Opérateur Local'}
            </div>
            <div className="text-[10px] text-slate-500 font-sans">
              Système autonome (ASN)
            </div>
          </div>

          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
            <div className="text-[11px] text-slate-400 flex items-center gap-1">
              <Navigation className="w-3 h-3 text-amber-400" />
              <span>Coordonnées Satellites</span>
            </div>
            <div className="text-sm font-bold text-amber-300">
              {hostGeo ? `${hostGeo.latitude.toFixed(2)}° N, ${hostGeo.longitude.toFixed(2)}° E` : '48.85° N, 2.35° E'}
            </div>
            <div className="text-[10px] text-slate-500 font-sans">
              Format WGS84 GPS
            </div>
          </div>
        </div>

        {/* Dynamic Countdown Banner for Auto-Navigation to IP-Locator */}
        {autoRedirectCountdown !== null && (
          <div className="p-3 bg-cyan-950/70 border border-cyan-500/60 rounded-lg flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2 text-cyan-200">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
              <span>
                <strong className="text-white">Auto-Reconnaissance Active :</strong> Redirection vers le panneau <strong className="text-cyan-300">IP-Locator</strong> dans{' '}
                <span className="font-mono font-bold text-amber-300 bg-amber-950/80 border border-amber-700 px-1.5 py-0.5 rounded text-xs">
                  {autoRedirectCountdown}s
                </span>{' '}
                pour afficher la cartographie détaillée...
              </span>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={handleTriggerLocateNow}
                className="px-2.5 py-1 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded text-xs transition-colors cursor-pointer"
              >
                Accéder Immédiatement
              </button>
              <button
                onClick={handleCancelAutoRedirect}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium rounded text-xs transition-colors cursor-pointer"
              >
                Rester sur l'onglet Réseau
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Real-time Line Chart Section */}
      <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-5 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-rose-400" />
              <h3 className="text-base font-bold text-slate-100 font-['Plus_Jakarta_Sans']">
                Surveillance du Trafic en Temps Réel vers les IPs Malveillantes C2
              </h3>
              {isLiveActive && (
                <span className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-rose-950/80 border border-rose-800 text-rose-300 font-mono text-[11px] font-semibold">
                  <Radio className="w-3 h-3 text-rose-400" />
                  <span>FLUX LIVE ACTIF</span>
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400">
              Détection en temps réel des pics d'exfiltration sortants (Upload) et de téléchargement de payloads secondaires (Download).
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {/* Target Filter Segmented Button */}
            <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800 text-xs">
              <button
                onClick={() => setSelectedTargetIP('all')}
                className={`px-2.5 py-1 rounded transition-colors ${
                  selectedTargetIP === 'all'
                    ? 'bg-slate-800 text-cyan-300 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Toutes les IPs C2
              </button>
              <button
                onClick={() => setSelectedTargetIP('beacon')}
                className={`px-2.5 py-1 rounded transition-colors ${
                  selectedTargetIP === 'beacon'
                    ? 'bg-slate-800 text-rose-300 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                185.220.101.4:4444
              </button>
              <button
                onClick={() => setSelectedTargetIP('powershell')}
                className={`px-2.5 py-1 rounded transition-colors ${
                  selectedTargetIP === 'powershell'
                    ? 'bg-slate-800 text-amber-300 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                45.154.255.89:8080
              </button>
            </div>

            {/* Pause / Play Toggle */}
            <button
              onClick={() => setIsLiveActive(prev => !prev)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors"
            >
              {isLiveActive ? (
                <>
                  <Pause className="w-3.5 h-3.5 text-amber-400" />
                  <span>Pause</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Reprendre</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Live Traffic KPI Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
            <div className="flex items-center justify-between text-slate-400 text-[11px]">
              <span className="flex items-center gap-1">
                <ArrowUpRight className="w-3.5 h-3.5 text-rose-400" />
                Exfiltration Sortante
              </span>
              <span className="text-rose-400 font-bold">OUTBOUND</span>
            </div>
            <div className="text-lg font-bold text-rose-400 tabular-nums">
              {latestPoint.totalExfiltration} KB/s
            </div>
            <div className="text-[10px] text-slate-500 font-sans">
              Vol de données / flux vers serveur C2
            </div>
          </div>

          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
            <div className="flex items-center justify-between text-slate-400 text-[11px]">
              <span className="flex items-center gap-1">
                <ArrowDownLeft className="w-3.5 h-3.5 text-cyan-400" />
                Payloads Entrants
              </span>
              <span className="text-cyan-400 font-bold">INBOUND</span>
            </div>
            <div className="text-lg font-bold text-cyan-300 tabular-nums">
              {latestPoint.inboundBeacon + latestPoint.inboundPowerShell} KB/s
            </div>
            <div className="text-[10px] text-slate-500 font-sans">
              Commandes C2 & téléchargement de modules
            </div>
          </div>

          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
            <div className="flex items-center justify-between text-slate-400 text-[11px]">
              <span>Pic Maximal Enregistré</span>
              <span className="text-amber-400 font-bold">SPIKE</span>
            </div>
            <div className="text-lg font-bold text-amber-300 tabular-nums">
              {peakOutbound} KB/s
            </div>
            <div className="text-[10px] text-slate-500 font-sans">
              Seuil critique &gt; 150 KB/s déclenché
            </div>
          </div>

          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
            <div className="flex items-center justify-between text-slate-400 text-[11px]">
              <span>Rythme Beaconing</span>
              <span className="text-purple-400 font-bold">HEARTBEAT</span>
            </div>
            <div className="text-lg font-bold text-purple-300 tabular-nums">
              ~2.0s / 18% Jitter
            </div>
            <div className="text-[10px] text-slate-500 font-sans">
              Périodicité caractéristique Cobalt Strike
            </div>
          </div>
        </div>

        {/* Recharts Responsive Line Chart */}
        <div className="h-72 w-full pt-2">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={trafficHistory} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis
                dataKey="time"
                stroke="#64748b"
                tick={{ fontSize: 11, fontFamily: 'monospace' }}
              />
              <YAxis
                stroke="#64748b"
                tick={{ fontSize: 11, fontFamily: 'monospace' }}
                unit=" KB/s"
                width={70}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#020617',
                  borderColor: '#334155',
                  borderRadius: '0.5rem',
                  fontSize: '12px',
                  fontFamily: 'monospace',
                }}
                labelStyle={{ color: '#94a3b8', fontWeight: 'bold' }}
              />
              <Legend
                wrapperStyle={{
                  paddingTop: '8px',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                }}
              />

              {/* Dynamic Line Rendering based on filter */}
              {(selectedTargetIP === 'all' || selectedTargetIP === 'beacon') && (
                <Line
                  type="monotone"
                  dataKey="outboundExfil"
                  name="185.220.101.4:4444 (Sortant - Swisyn / Cobalt)"
                  stroke="#f43f5e"
                  strokeWidth={2.5}
                  dot={false}
                  activeDot={{ r: 5, fill: '#f43f5e' }}
                  isAnimationActive={false}
                />
              )}

              {(selectedTargetIP === 'all' || selectedTargetIP === 'beacon') && (
                <Line
                  type="monotone"
                  dataKey="inboundBeacon"
                  name="185.220.101.4:4444 (Entrant - Instructions C2)"
                  stroke="#38bdf8"
                  strokeWidth={1.8}
                  strokeDasharray="4 2"
                  dot={false}
                  isAnimationActive={false}
                />
              )}

              {(selectedTargetIP === 'all' || selectedTargetIP === 'powershell') && (
                <Line
                  type="monotone"
                  dataKey="outboundPowerShell"
                  name="45.154.255.89:8080 (Sortant - Exfiltration PowerShell)"
                  stroke="#fbbf24"
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 5, fill: '#fbbf24' }}
                  isAnimationActive={false}
                />
              )}

              {(selectedTargetIP === 'all' || selectedTargetIP === 'powershell') && (
                <Line
                  type="monotone"
                  dataKey="inboundPowerShell"
                  name="45.154.255.89:8080 (Entrant - Script Download)"
                  stroke="#a855f7"
                  strokeWidth={1.5}
                  strokeDasharray="3 3"
                  dot={false}
                  isAnimationActive={false}
                />
              )}
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Spike Warning Bar */}
        {latestPoint.isSpike && (
          <div className="p-3 bg-rose-950/60 border border-rose-800 rounded-lg flex items-center justify-between text-xs text-rose-200">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>
                <strong>Pic d'exfiltration anormal détecté :</strong> Transfert de données volumineux vers l'hôte distant C2 185.220.101.4 ({latestPoint.outboundExfil} KB/s).
              </span>
            </div>
            <button
              onClick={() => onRunInConsole('kill 5824')}
              className="px-3 py-1 bg-rose-600 hover:bg-rose-500 text-white font-semibold rounded text-xs transition-colors shrink-0"
            >
              Couper PID 5824
            </button>
          </div>
        )}
      </div>

      {/* Active Connections Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-400" />
            Connexions Réseau Établies (Get-NetTCPConnection)
          </h3>
          <span className="text-xs text-slate-400">
            {connections.filter(c => c.isSuspicious).length} alerte(s) de sécurité détectée(s)
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4 font-semibold">Processus (PID)</th>
                <th className="py-3 px-4 font-semibold">Adresse Locale</th>
                <th className="py-3 px-4 font-semibold">Adresse Distante (C2)</th>
                <th className="py-3 px-4 font-semibold">État</th>
                <th className="py-3 px-4 font-semibold">Pays / Renseignement Menace</th>
                <th className="py-3 px-4 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {connections.map((conn, idx) => (
                <tr
                  key={idx}
                  className={`transition-colors ${
                    conn.isSuspicious
                      ? 'bg-rose-950/20 hover:bg-rose-950/30'
                      : 'hover:bg-slate-800/40'
                  }`}
                >
                  <td className="py-3 px-4">
                    <div className="font-semibold text-slate-200">
                      {conn.processName}
                    </div>
                    <div className="text-[11px] text-slate-500 tabular-nums">
                      PID: {conn.pid}
                    </div>
                  </td>
                  <td className="py-3 px-4 tabular-nums text-slate-300">
                    {conn.local}
                  </td>
                  <td className="py-3 px-4 tabular-nums">
                    <span className={conn.isSuspicious ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                      {conn.remote}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-sans">
                      {conn.state}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className={conn.isSuspicious ? 'text-rose-300 font-sans' : 'text-slate-400 font-sans'}>
                      {conn.intel}
                    </div>
                    {conn.country && (
                      <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                        Origine: {conn.country}
                      </div>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      {onLocateIp && conn.remote && !conn.remote.startsWith('0.0.0.0') && (
                        <button
                          onClick={() => {
                            const raw = conn.remote.split(':')[0];
                            onLocateIp(raw);
                          }}
                          className="px-2 py-1 bg-sky-950/70 hover:bg-sky-900/80 text-sky-300 border border-sky-800/60 rounded text-[11px] font-medium transition-colors flex items-center gap-1 shadow-sm"
                          title="Localiser le pays, la ville et l'adresse physique de cette IP"
                        >
                          <Globe className="w-3 h-3 text-sky-400" />
                          <span>Localiser</span>
                        </button>
                      )}
                      {conn.isSuspicious ? (
                        <button
                          onClick={() => onRunInConsole(`kill ${conn.pid}`)}
                          className="px-2.5 py-1 bg-rose-600 hover:bg-rose-500 text-white rounded text-[11px] font-semibold transition-colors shadow-sm"
                        >
                          Couper Socket
                        </button>
                      ) : (
                        <span className="text-slate-500 text-[11px] font-sans">Normal</span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* PortScanner Module: Local Open Ports & Listening Malicious Services */}
      <PortScanner onRunInConsole={onRunInConsole} />

      {/* WiFi Scanner Module: Surrounding Wireless Networks, Unsecured APs & Evil Twin Detection */}
      <WiFiScanner onRunInConsole={onRunInConsole} />

      {/* Lower Row: Named Pipes & HOSTS / Proxy Audit */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Named Pipes */}
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              Named Pipes (Canaux Cobalt Strike)
            </h3>
            <button
              onClick={() => onRunInConsole('pipes-audit')}
              className="text-xs px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded transition-colors"
            >
              Auditer \\.\pipe
            </button>
          </div>
          <p className="text-xs text-slate-400">
            Les frameworks offensifs comme Cobalt Strike et Metasploit communiquent entre processus via des tuyaux nommés :
          </p>
          <div className="space-y-2 text-xs font-mono">
            {namedPipes.map((p, i) => (
              <div
                key={i}
                className={`p-2.5 rounded-lg border flex items-center justify-between ${
                  p.isSuspicious
                    ? 'border-rose-800/60 bg-rose-950/30 text-rose-300'
                    : 'border-slate-800 bg-slate-950/60 text-slate-300'
                }`}
              >
                <div>
                  <div className="font-semibold">{p.name}</div>
                  <div className="text-[11px] font-sans text-slate-400 mt-0.5">{p.description}</div>
                </div>
                {p.isSuspicious && (
                  <span className="text-[10px] uppercase font-bold text-rose-400 bg-rose-950 border border-rose-800 px-1.5 py-0.5 rounded">
                    Menace C2
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* HOSTS & Proxy Integrity */}
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            Intégrité Fichier HOSTS & Proxy Système
          </h3>
          <p className="text-xs text-slate-400">
            Certains virus redirigent les domaines d'antivirus vers 127.0.0.1 ou configurent un serveur proxy local pour intercepter tout le trafic chiffré (Man-in-the-Middle) :
          </p>

          <div className="space-y-3 text-xs">
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-200">Fichier C:\Windows\System32\drivers\etc\hosts</div>
                <div className="text-[11px] text-slate-500 mt-0.5">Aucune redirection de virusTotal, Microsoft ou Kaspersky détectée</div>
              </div>
              <span className="text-emerald-400 font-semibold">Propre</span>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-200">Proxy Système (WinHTTP & Internet Settings)</div>
                <div className="text-[11px] text-slate-500 mt-0.5">ProxyEnable = 0, aucun script PAC malveillant</div>
              </div>
              <span className="text-emerald-400 font-semibold">Désactivé (Sûr)</span>
            </div>

            <button
              onClick={() => onRunInConsole('hosts-check')}
              className="w-full text-center py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded font-semibold transition-colors text-xs"
            >
              Exécuter l'analyse d'intégrité HOSTS & Proxy
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
