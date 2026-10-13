import React, { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import * as d3 from 'd3';
import * as topojson from 'topojson-client';
import worldAtlasData from 'world-atlas/countries-110m.json';
import {
  Globe,
  Map as MapIcon,
  ShieldAlert,
  Radio,
  Zap,
  Activity,
  Maximize2,
  Minimize2,
  RotateCw,
  Terminal,
  Crosshair,
  Lock,
  Layers,
  Flame,
  AlertTriangle,
  Info,
  Server,
  ArrowUpRight,
  TrendingUp,
  Filter,
  Play,
  Pause,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  CheckCircle2,
  Skull,
  Shield,
  Eye,
  Navigation,
  RefreshCw,
  MapPin,
} from 'lucide-react';
import {
  ThreatGeoLocation,
  DETECTED_MALICIOUS_ORIGINS,
  PROTECTED_SYSTEM_LOCATION,
  TargetHostLocation,
} from '../data/threatGeoData';
import { apiFetch } from '../utils/api';

interface ThreatIntensityMapProps {
  onRunInConsole: (command: string) => void;
  onNavigateTab?: (tab: any) => void;
}

export const ThreatIntensityMap: React.FC<ThreatIntensityMapProps> = ({
  onRunInConsole,
  onNavigateTab,
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Real Target Host Geolocation State (Loaded dynamically on startup)
  const [targetHost, setTargetHost] = useState<TargetHostLocation>(PROTECTED_SYSTEM_LOCATION);
  const [isGeoLoading, setIsGeoLoading] = useState<boolean>(true);
  const [geoError, setGeoError] = useState<string | null>(null);

  // UI & View States
  const [selectedThreat, setSelectedThreat] = useState<ThreatGeoLocation | null>(
    DETECTED_MALICIOUS_ORIGINS[0] || null
  );
  const [projectionMode, setProjectionMode] = useState<'2D_MAPBOX' | '3D_GLOBE'>('2D_MAPBOX');
  const [filterType, setFilterType] = useState<string>('ALL');
  const [showHeatmap, setShowHeatmap] = useState<boolean>(true);
  const [showArcs, setShowArcs] = useState<boolean>(true);
  const [showLabels, setShowLabels] = useState<boolean>(true);
  const [isLiveTelemetry, setIsLiveTelemetry] = useState<boolean>(true);
  const [isAutoRotating, setIsAutoRotating] = useState<boolean>(false); // Crisp tactical default
  
  // Globe rotation angles [lambda (yaw), phi (pitch), gamma (roll)]
  const [globeRotation, setGlobeRotation] = useState<[number, number, number]>([-10, -35, 0]);
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [blockedIps, setBlockedIps] = useState<Set<string>>(new Set());

  // Dynamic Geolocation Resolution on Mount
  const resolveHostGeolocation = useCallback(async () => {
    setIsGeoLoading(true);
    setGeoError(null);

    let resolved = false;

    // Strategy 1: Check internal proxy endpoint /api/system/geo
    try {
      const res = await apiFetch('/api/system/geo');
      if (res.ok) {
        const data = await res.json();
        if (data && data.success && data.latitude && data.longitude) {
          // If server resolved a non-fallback public IP or valid city
          if (data.city && data.country && data.ip !== '127.0.0.1') {
            setTargetHost({
              name: `Station Hôte (${data.city}, ${data.country})`,
              ip: data.ip,
              city: data.city,
              country: data.country,
              countryCode: data.countryCode || 'FR',
              latitude: Number(data.latitude),
              longitude: Number(data.longitude),
              isp: data.isp || 'Opérateur Local',
              regionName: data.regionName,
              isRealDetected: true,
            });
            resolved = true;
          }
        }
      }
    } catch {
      // Continue to client direct fetch
    }

    // Strategy 2: Client-side direct query to IP geolocation API (resolves user's real browser IP)
    if (!resolved) {
      try {
        const clientRes = await fetch('https://ipapi.co/json/');
        if (clientRes.ok) {
          const cData = await clientRes.json();
          if (cData && cData.city && cData.latitude && cData.longitude) {
            setTargetHost({
              name: `Station Hôte (${cData.city}, ${cData.country_name || cData.country})`,
              ip: cData.ip,
              city: cData.city,
              country: cData.country_name || cData.country,
              countryCode: cData.country_code || 'FR',
              latitude: Number(cData.latitude),
              longitude: Number(cData.longitude),
              isp: cData.org || cData.asn || 'Connexion Locale',
              regionName: cData.region,
              isRealDetected: true,
            });
            resolved = true;
          }
        }
      } catch {
        // Fallback strategy 3
      }
    }

    // Strategy 3: Alternative IP-API endpoint
    if (!resolved) {
      try {
        const altRes = await fetch('http://ip-api.com/json/');
        if (altRes.ok) {
          const aData = await altRes.json();
          if (aData && aData.status === 'success' && aData.lat && aData.lon) {
            setTargetHost({
              name: `Station Hôte (${aData.city}, ${aData.country})`,
              ip: aData.query,
              city: aData.city,
              country: aData.country,
              countryCode: aData.countryCode || 'FR',
              latitude: Number(aData.lat),
              longitude: Number(aData.lon),
              isp: aData.isp || 'Fournisseur d\'Accès',
              regionName: aData.regionName,
              isRealDetected: true,
            });
            resolved = true;
          }
        }
      } catch {
        // Keep fallback
      }
    }

    setIsGeoLoading(false);
  }, []);

  useEffect(() => {
    resolveHostGeolocation();
  }, [resolveHostGeolocation]);

  // Adjust initial globe rotation towards target host when detected
  useEffect(() => {
    if (targetHost.latitude && targetHost.longitude) {
      setGlobeRotation([-targetHost.longitude, -targetHost.latitude, 0]);
    }
  }, [targetHost.latitude, targetHost.longitude]);

  // Filtered threats
  const currentThreats = useMemo(() => {
    return DETECTED_MALICIOUS_ORIGINS.map(t => ({
      ...t,
      status: blockedIps.has(t.ip) ? ('BLOCKED' as const) : t.status,
    })).filter(t => {
      if (filterType === 'ALL') return true;
      if (filterType === 'ACTIVE') return t.status === 'ACTIVE';
      if (filterType === 'BLOCKED') return t.status === 'BLOCKED';
      if (filterType === 'C2') return t.threatType === 'C2_BEACON';
      if (filterType === 'EXFIL') return t.threatType === 'DATA_EXFIL';
      return true;
    });
  }, [blockedIps, filterType]);

  // Dynamic statistics
  const activeCount = currentThreats.filter(t => t.status === 'ACTIVE').length;
  const criticalCount = currentThreats.filter(t => t.threatIntensity >= 85 && t.status === 'ACTIVE').length;
  const totalBandwidth = currentThreats
    .filter(t => t.status === 'ACTIVE')
    .reduce((sum, t) => sum + t.bandwidthKbps, 0);

  // Auto-rotation timer for 3D Globe
  useEffect(() => {
    if (projectionMode !== '3D_GLOBE' || !isAutoRotating) return;

    const interval = setInterval(() => {
      setGlobeRotation(([lambda, phi, gamma]) => [(lambda + 0.4) % 360, phi, gamma]);
    }, 50);

    return () => clearInterval(interval);
  }, [projectionMode, isAutoRotating]);

  // Main D3 Tactical Map Rendering (STRICTLY NO NEONS / NO BLURS)
  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const width = containerRef.current.clientWidth || 920;
    const height = Math.min(540, Math.max(400, width * 0.50));

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();
    svg.attr('viewBox', `0 0 ${width} ${height}`);

    // Color Scales for Tactical Markers (Crisp High-Contrast Hues, No Glows)
    const tacticalColorScale = (intensity: number) => {
      if (intensity >= 85) return '#ef4444'; // Crisp red (critical)
      if (intensity >= 70) return '#f97316'; // Crisp orange (high)
      return '#eab308'; // Crisp yellow (moderate)
    };

    // 1. Projections: 2D Tactical Mapbox Natural Earth vs 3D Orthographic Globe
    let projection: d3.GeoProjection;
    if (projectionMode === '3D_GLOBE') {
      const radius = Math.min(width, height) * 0.43 * zoomLevel;
      projection = d3.geoOrthographic()
        .scale(radius)
        .translate([width / 2, height / 2])
        .rotate(globeRotation)
        .clipAngle(90);
    } else {
      projection = d3.geoNaturalEarth1()
        .scale((width / 5.5) * zoomLevel)
        .translate([width / 2, height / 2 + 10]);
    }

    const pathGenerator = d3.geoPath().projection(projection);

    // Extract real countries and borders from TopoJSON
    const countriesGeo: any = topojson.feature(
      worldAtlasData as any,
      (worldAtlasData as any).objects.countries
    );
    const countryBorders: any = topojson.mesh(
      worldAtlasData as any,
      (worldAtlasData as any).objects.countries,
      (a: any, b: any) => a !== b
    );

    // Main Canvas Group
    const g = svg.append('g').attr('class', 'tactical-map-root');

    // ==========================================
    // 3D GLOBE SPHERE BACKGROUND (Crisp Vector Edges)
    // ==========================================
    if (projectionMode === '3D_GLOBE') {
      const radius = Math.min(width, height) * 0.43 * zoomLevel;

      // Deep Ocean Sphere (Sharp 1px border, NO blur filter)
      g.append('circle')
        .attr('cx', width / 2)
        .attr('cy', height / 2)
        .attr('r', radius)
        .attr('fill', '#070b14')
        .attr('stroke', '#1e293b')
        .attr('stroke-width', 1.2);
    }

    // ==========================================
    // TACTICAL GRATICULE GRID (Clean Hairline Coordinates)
    // ==========================================
    const graticule = d3.geoGraticule().step([20, 20]);
    g.append('path')
      .datum(graticule)
      .attr('class', 'graticule')
      .attr('d', pathGenerator)
      .attr('fill', 'none')
      .attr('stroke', '#1e293b')
      .attr('stroke-width', 0.5)
      .attr('stroke-dasharray', '1 4')
      .attr('opacity', 0.6);

    // ==========================================
    // MAPBOX DARK COUNTRIES & CONTINENTS (Net & Professionnel)
    // ==========================================
    const countriesGroup = g.append('g').attr('class', 'countries-layer');

    // Individual Country Polygons
    countriesGroup.selectAll('path.country')
      .data(countriesGeo.features)
      .enter()
      .append('path')
      .attr('class', 'country')
      .attr('d', pathGenerator as any)
      .attr('fill', '#0f172a') // Crisp dark matte landmass
      .attr('stroke', '#1e293b')
      .attr('stroke-width', 0.5)
      .attr('cursor', 'pointer')
      .on('mouseenter', function () {
        d3.select(this)
          .attr('fill', '#1e293b')
          .attr('stroke', '#475569')
          .attr('stroke-width', 0.75);
      })
      .on('mouseleave', function () {
        d3.select(this)
          .attr('fill', '#0f172a')
          .attr('stroke', '#1e293b')
          .attr('stroke-width', 0.5);
      });

    // Realistic Crisp Country Borders (TopoJSON Mesh - hairline stroke, no blur)
    g.append('path')
      .datum(countryBorders)
      .attr('class', 'country-borders')
      .attr('d', pathGenerator)
      .attr('fill', 'none')
      .attr('stroke', '#334155') // Crisp tactical border lines
      .attr('stroke-width', 0.75)
      .attr('opacity', 0.9);

    // Target Host Projected Coordinates (Dynamic from targetHost state)
    const targetCoords: [number, number] = [
      targetHost.longitude,
      targetHost.latitude,
    ];
    const targetProjected = projection(targetCoords);

    // Check if point is on visible hemisphere in 3D
    const isPointVisibleIn3D = (lon: number, lat: number) => {
      if (projectionMode !== '3D_GLOBE') return true;
      const center = projection.rotate();
      const distance = d3.geoDistance([lon, lat], [-center[0], -center[1]]);
      return distance < Math.PI / 2;
    };

    // ==========================================
    // LAYER 1: TACTICAL HEATMAP ZONES (CRISP CONCENTRIC RINGS - NO NEON GLOW)
    // ==========================================
    if (showHeatmap) {
      const heatGroup = g.append('g').attr('class', 'tactical-heat-layer');

      currentThreats.forEach((threat) => {
        if (!isPointVisibleIn3D(threat.longitude, threat.latitude)) return;

        const coords = projection([threat.longitude, threat.latitude]);
        if (!coords) return;

        const isBlocked = threat.status === 'BLOCKED';
        const intensity = threat.threatIntensity;
        const color = isBlocked ? '#64748b' : tacticalColorScale(intensity);

        // Scaled tactical perimeter radius (clean pixels)
        const radius = Math.max(18, (intensity / 100) * 44);

        // Crisp Semi-Transparent Tactical Fill (No blur, no radial gradient fade)
        heatGroup.append('circle')
          .attr('cx', coords[0])
          .attr('cy', coords[1])
          .attr('r', radius)
          .attr('fill', color)
          .attr('fill-opacity', isBlocked ? 0.05 : 0.12)
          .attr('stroke', color)
          .attr('stroke-width', 1)
          .attr('stroke-dasharray', '3 3')
          .attr('stroke-opacity', isBlocked ? 0.3 : 0.65)
          .attr('pointer-events', 'none');

        // Inner Tactical Precision Ring
        heatGroup.append('circle')
          .attr('cx', coords[0])
          .attr('cy', coords[1])
          .attr('r', radius * 0.45)
          .attr('fill', color)
          .attr('fill-opacity', isBlocked ? 0.08 : 0.18)
          .attr('stroke', color)
          .attr('stroke-width', 0.75)
          .attr('pointer-events', 'none');
      });
    }

    // ==========================================
    // LAYER 2: CRISP CONNECTION LINES (Arcs & Traces - NO GLOW FILTERS)
    // ==========================================
    if (showArcs && targetProjected && isPointVisibleIn3D(targetCoords[0], targetCoords[1])) {
      const arcGroup = g.append('g').attr('class', 'arcs-layer');

      currentThreats.forEach(threat => {
        const isThreatVisible = isPointVisibleIn3D(threat.longitude, threat.latitude);
        if (!isThreatVisible) return;

        const sourceCoords = projection([threat.longitude, threat.latitude]);
        if (!sourceCoords) return;

        const isBlocked = threat.status === 'BLOCKED';
        const color = isBlocked
          ? '#475569'
          : tacticalColorScale(threat.threatIntensity);

        let arcPath: string;

        if (projectionMode === '3D_GLOBE') {
          // Great Circle Interpolation GeoJSON LineString
          const geoInterpolator = d3.geoInterpolate(
            [threat.longitude, threat.latitude],
            targetCoords
          );
          const steps = 30;
          const arcPoints: [number, number][] = [];
          for (let s = 0; s <= steps; s++) {
            const p = geoInterpolator(s / steps);
            arcPoints.push(p);
          }
          const geoLineString: any = {
            type: 'Feature',
            geometry: {
              type: 'LineString',
              coordinates: arcPoints,
            },
          };
          arcPath = pathGenerator(geoLineString) || '';
        } else {
          // Clean curved quadratic Bézier arc towards real host position
          const dx = targetProjected[0] - sourceCoords[0];
          const dy = targetProjected[1] - sourceCoords[1];
          const dr = Math.sqrt(dx * dx + dy * dy);

          const midX = (sourceCoords[0] + targetProjected[0]) / 2;
          const midY = (sourceCoords[1] + targetProjected[1]) / 2 - Math.min(70, dr * 0.28);

          arcPath = `M ${sourceCoords[0]} ${sourceCoords[1]} Q ${midX} ${midY} ${targetProjected[0]} ${targetProjected[1]}`;
        }

        if (!arcPath) return;

        // Base Crisp Vector Arc Line (No blur filter)
        arcGroup.append('path')
          .attr('d', arcPath)
          .attr('fill', 'none')
          .attr('stroke', color)
          .attr('stroke-width', isBlocked ? 1 : 1.4)
          .attr('stroke-dasharray', isBlocked ? '2 3' : '4 4')
          .attr('stroke-opacity', isBlocked ? 0.35 : 0.7);

        // Clean Solid Photon Particle (Sharp, no glow)
        if (!isBlocked && isLiveTelemetry) {
          const particle = arcGroup.append('circle')
            .attr('r', 2.5)
            .attr('fill', '#ffffff')
            .attr('stroke', color)
            .attr('stroke-width', 1.2);

          const pathEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
          pathEl.setAttribute('d', arcPath);
          const pathLength = pathEl.getTotalLength();

          if (pathLength > 0) {
            const animatePhoton = () => {
              particle
                .transition()
                .duration(1800 + Math.random() * 600)
                .ease(d3.easeLinear)
                .attrTween('transform', () => {
                  return (t: number) => {
                    const point = pathEl.getPointAtLength((1 - t) * pathLength);
                    return `translate(${point.x}, ${point.y})`;
                  };
                })
                .on('end', () => {
                  if (isLiveTelemetry) animatePhoton();
                });
            };

            animatePhoton();
          }
        }
      });
    }

    // ==========================================
    // LAYER 3: C2 SERVERS WITH TACTICAL SKULL ICONS (CRISP VECTOR EMBLEMS)
    // ==========================================
    const c2Group = g.append('g').attr('class', 'c2-nodes-layer');

    currentThreats.forEach(threat => {
      if (!isPointVisibleIn3D(threat.longitude, threat.latitude)) return;

      const coords = projection([threat.longitude, threat.latitude]);
      if (!coords) return;

      const isSelected = selectedThreat?.id === threat.id;
      const isBlocked = threat.status === 'BLOCKED';
      const color = isBlocked ? '#64748b' : tacticalColorScale(threat.threatIntensity);

      const nodeG = c2Group.append('g')
        .attr('transform', `translate(${coords[0]}, ${coords[1]})`)
        .attr('cursor', 'pointer')
        .on('click', () => {
          setSelectedThreat(threat);
        });

      // Sharp Tactical Selection Reticle (Hairline brackets, NO blur)
      if (isSelected) {
        nodeG.append('circle')
          .attr('r', 15)
          .attr('fill', 'none')
          .attr('stroke', '#38bdf8')
          .attr('stroke-width', 1.5)
          .attr('stroke-dasharray', '2 2');
      }

      // Tactical Badge Container (Solid dark background with sharp border)
      const badgeRadius = isSelected ? 11 : 9.5;
      nodeG.append('circle')
        .attr('r', badgeRadius)
        .attr('fill', isBlocked ? '#1e293b' : '#300808')
        .attr('stroke', color)
        .attr('stroke-width', 1.5);

      // CRISP VECTOR SKULL ICON PATH (Centré, net et précis)
      const skullG = nodeG.append('g')
        .attr('transform', `translate(-${badgeRadius * 0.65}, -${badgeRadius * 0.65}) scale(${badgeRadius * 0.055})`);

      skullG.append('path')
        .attr('d', 'M12 2C7.58 2 4 5.58 4 10c0 2.65 1.28 4.99 3.25 6.45V19c0 .55.45 1 1 1h1.5v2h4.5v-2H16c.55 0 1-.45 1-1v-2.55C18.72 14.99 20 12.65 20 10c0-4.42-3.58-8-8-8zm-3 9c-.83 0-1.5-.67-1.5-1.5S8.17 8 9 8s1.5.67 1.5 1.5S9.83 11 9 11zm6 0c-.83 0-1.5-.67-1.5-1.5S14.17 8 15 8s1.5.67 1.5 1.5S15.83 11 15 11z')
        .attr('fill', isBlocked ? '#94a3b8' : '#ffffff');

      // Crisp Tactical Text Label
      if (showLabels) {
        const textLabel = `${threat.city} (${threat.ip})`;
        
        // Micro background pill for maximum legibility over landmasses
        nodeG.append('rect')
          .attr('x', 12)
          .attr('y', -7)
          .attr('width', textLabel.length * 6.2 + 8)
          .attr('height', 14)
          .attr('rx', 3)
          .attr('fill', '#090d16')
          .attr('stroke', '#1e293b')
          .attr('stroke-width', 0.75);

        nodeG.append('text')
          .attr('x', 16)
          .attr('y', 4)
          .attr('font-size', '9.5px')
          .attr('font-family', 'JetBrains Mono, monospace')
          .attr('font-weight', isSelected ? 'bold' : 'normal')
          .attr('fill', isSelected ? '#38bdf8' : '#f8fafc')
          .text(textLabel);
      }
    });

    // ==========================================
    // LAYER 4: TARGET HOST (REAL DYNAMIC GEOLOCATION - CRISP BLUE CIRCLE)
    // ==========================================
    if (targetProjected && isPointVisibleIn3D(targetCoords[0], targetCoords[1])) {
      const targetG = g.append('g')
        .attr('transform', `translate(${targetProjected[0]}, ${targetProjected[1]})`)
        .attr('class', 'target-endpoint-node');

      // Outer Tactical Radar Ring (Sharp hairline, NO blur)
      targetG.append('circle')
        .attr('r', 16)
        .attr('fill', 'none')
        .attr('stroke', '#0284c7')
        .attr('stroke-width', 1)
        .attr('stroke-dasharray', '2 2')
        .attr('opacity', 0.8);

      // Distinct Solid Blue Circle (Le cercle bleu net)
      targetG.append('circle')
        .attr('r', 10)
        .attr('fill', '#0284c7')
        .attr('stroke', '#38bdf8')
        .attr('stroke-width', 1.8);

      // Sharp White Center Dot
      targetG.append('circle')
        .attr('r', 3.5)
        .attr('fill', '#ffffff');

      // Tactical Host Label (Real City, Country, Real IP)
      if (showLabels) {
        const hostLabel = `HÔTE : ${targetHost.city}, ${targetHost.countryCode} (${targetHost.ip})`;
        const labelWidth = hostLabel.length * 6.5 + 12;

        targetG.append('rect')
          .attr('x', -labelWidth / 2)
          .attr('y', -24)
          .attr('width', labelWidth)
          .attr('height', 15)
          .attr('rx', 3)
          .attr('fill', '#090d16')
          .attr('stroke', '#0284c7')
          .attr('stroke-width', 1);

        targetG.append('text')
          .attr('x', 0)
          .attr('y', -13)
          .attr('text-anchor', 'middle')
          .attr('font-size', '9.5px')
          .attr('font-family', 'JetBrains Mono, monospace')
          .attr('font-weight', 'bold')
          .attr('fill', '#38bdf8')
          .text(hostLabel);
      }
    }

    // ==========================================
    // INTERACTIVE DRAG TO ROTATE GLOBE (3D MODE)
    // ==========================================
    if (projectionMode === '3D_GLOBE') {
      const dragBehavior = d3.drag()
        .on('start', () => {
          setIsAutoRotating(false);
        })
        .on('drag', (event: any) => {
          const sensitivity = 0.4;
          setGlobeRotation(([lambda, phi, gamma]) => [
            lambda + event.dx * sensitivity,
            Math.max(-80, Math.min(80, phi - event.dy * sensitivity)),
            gamma,
          ]);
        });

      svg.call(dragBehavior as any);
    }

  }, [
    currentThreats,
    selectedThreat,
    targetHost,
    projectionMode,
    globeRotation,
    zoomLevel,
    showHeatmap,
    showArcs,
    showLabels,
    isLiveTelemetry,
  ]);

  // Handler: Block IP via Windows Firewall
  const handleBlockIp = (ip: string, pid?: number) => {
    setBlockedIps(prev => {
      const next = new Set(prev);
      next.add(ip);
      return next;
    });

    onRunInConsole(`netsh advfirewall firewall add rule name="Block SpaceSec C2 ${ip}" dir=out action=block remoteip=${ip}`);
    if (pid) {
      setTimeout(() => {
        onRunInConsole(`kill ${pid}`);
      }, 500);
    }
  };

  // Handler: Unblock IP
  const handleUnblockIp = (ip: string) => {
    setBlockedIps(prev => {
      const next = new Set(prev);
      next.delete(ip);
      return next;
    });
    onRunInConsole(`netsh advfirewall firewall delete rule name="Block SpaceSec C2 ${ip}"`);
  };

  return (
    <div className="p-6 bg-slate-900 border border-slate-800 rounded-2xl space-y-6 relative overflow-hidden">
      {/* Top Header & Cyber World Map Control Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
            <span className="text-cyan-400 font-semibold uppercase tracking-wider">
              GÉOLOCALISATION FORENSIQUE DE L'HÔTE
            </span>
            <span aria-hidden="true">·</span>
            <span>CARTE TACTIQUE MINIMALISTE</span>
            <span aria-hidden="true">·</span>
            <span className="text-rose-400">{activeCount} SERVEURS C2 IDENTIFIÉS</span>
          </div>

          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2.5 mt-1 font-['Plus_Jakarta_Sans']">
            <span>Cartographie Tactique des Menaces & Hôte Local</span>
          </h2>
          <p className="text-xs text-slate-300 mt-1 max-w-2xl leading-relaxed">
            Surveillance en temps réel des vecteurs C2 convergeant vers votre machine locale (
            <strong className="text-cyan-300">
              {targetHost.city}, {targetHost.country} · {targetHost.ip}
            </strong>
            ) avec détection d'origine par géolocalisation IP et affichage sans fard ni néons.
          </p>
        </div>

        {/* Projection Mode (2D Mapbox vs 3D Globe) & View Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Geolocation Refresh Button */}
          <button
            onClick={resolveHostGeolocation}
            disabled={isGeoLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium bg-slate-950 border border-slate-800 hover:border-cyan-800 text-slate-300 hover:text-white transition-colors"
            title="Réinterroger l'API de géolocalisation IP de votre machine"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isGeoLoading ? 'animate-spin' : ''}`} />
            <span>{isGeoLoading ? 'Détection IP...' : 'Actualiser Hôte'}</span>
          </button>

          {/* 2D / 3D Projection Toggle */}
          <div className="flex items-center p-1 bg-slate-950 rounded-lg border border-slate-800">
            <button
              onClick={() => setProjectionMode('2D_MAPBOX')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                projectionMode === '2D_MAPBOX'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <MapIcon className="w-3.5 h-3.5" />
              <span>Carte 2D Tactique</span>
            </button>
            <button
              onClick={() => setProjectionMode('3D_GLOBE')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                projectionMode === '3D_GLOBE'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>Globe 3D</span>
            </button>
          </div>

          {/* Zoom In/Out Controls */}
          <div className="flex items-center p-0.5 bg-slate-950 rounded-lg border border-slate-800">
            <button
              onClick={() => setZoomLevel(prev => Math.min(2.5, prev + 0.2))}
              className="p-1.5 text-slate-400 hover:text-white transition-colors"
              title="Zoom +"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoomLevel(prev => Math.max(0.7, prev - 0.2))}
              className="p-1.5 text-slate-400 hover:text-white transition-colors"
              title="Zoom -"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => {
                setZoomLevel(1);
                setGlobeRotation([-targetHost.longitude, -targetHost.latitude, 0]);
              }}
              className="p-1.5 text-slate-400 hover:text-white transition-colors"
              title="Centrer sur l'Hôte Local"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Layer Toggles & Real Geolocation Status Strip */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        {/* Layer Checkboxes */}
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 cursor-pointer text-slate-300 hover:text-white select-none">
            <input
              type="checkbox"
              checked={showHeatmap}
              onChange={e => setShowHeatmap(e.target.checked)}
              className="rounded bg-slate-950 border-slate-700 text-rose-500 focus:ring-0"
            />
            <span className="flex items-center gap-1 font-mono text-xs">
              <Flame className="w-3.5 h-3.5 text-rose-400" /> Périmètres d'Intensité
            </span>
          </label>

          <label className="flex items-center gap-1.5 cursor-pointer text-slate-300 hover:text-white select-none">
            <input
              type="checkbox"
              checked={showArcs}
              onChange={e => setShowArcs(e.target.checked)}
              className="rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-0"
            />
            <span className="flex items-center gap-1 font-mono text-xs">
              <Zap className="w-3.5 h-3.5 text-cyan-400" /> Arcs Réseau C2
            </span>
          </label>

          <label className="flex items-center gap-1.5 cursor-pointer text-slate-300 hover:text-white select-none">
            <input
              type="checkbox"
              checked={showLabels}
              onChange={e => setShowLabels(e.target.checked)}
              className="rounded bg-slate-950 border-slate-700 text-indigo-500 focus:ring-0"
            />
            <span className="flex items-center gap-1 font-mono text-xs">
              <Eye className="w-3.5 h-3.5 text-indigo-400" /> Étiquettes Nœuds
            </span>
          </label>
        </div>

        {/* Tactical Legend (Clean shapes, no glows) */}
        <div className="flex items-center gap-4 text-xs font-mono text-slate-400">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-600 border border-cyan-400 inline-block"></span>
            <span className="text-cyan-300">
              Hôte Local ({targetHost.city})
            </span>
          </span>
          <span className="flex items-center gap-1.5">
            <Skull className="w-3.5 h-3.5 text-rose-400" />
            <span className="text-rose-400">Nœuds C2</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-slate-500 inline-block"></span>
            <span>Filtré Pare-Feu</span>
          </span>
        </div>
      </div>

      {/* Main Layout: Tactical Map Canvas + Tactical Inspector Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: D3 Map Canvas (Clean slate, crisp vector graphics) */}
        <div
          ref={containerRef}
          className="lg:col-span-2 bg-[#090d16] border border-slate-800 rounded-xl overflow-hidden relative min-h-[420px] flex items-center justify-center"
        >
          <svg ref={svgRef} className="w-full h-full select-none" />

          {/* Real Local Host Floating Geolocation Pill */}
          <div className="absolute top-3 left-3 flex items-center gap-2">
            <div className="px-2.5 py-1.5 rounded-lg bg-slate-950/95 border border-slate-800 text-xs font-mono flex items-center gap-2">
              <span className="inline-block w-2 h-2 rounded-full bg-cyan-400"></span>
              <span className="text-white font-bold">
                {targetHost.city}, {targetHost.country}
              </span>
              <span className="text-slate-600">·</span>
              <span className="text-cyan-300">{targetHost.ip}</span>
              {targetHost.isRealDetected && (
                <span className="text-[10px] text-emerald-400 font-semibold px-1 py-0.2 bg-emerald-950/80 rounded border border-emerald-800/60">
                  GÉOLOCALISÉ EN DIRECT
                </span>
              )}
            </div>
          </div>

          {/* 3D Drag Help */}
          {projectionMode === '3D_GLOBE' && (
            <div className="absolute bottom-3 left-3 px-2.5 py-1 rounded bg-slate-950/90 border border-slate-800 text-[10px] text-slate-400 font-mono pointer-events-none">
              Glissez la souris pour faire pivoter le globe 3D
            </div>
          )}
        </div>

        {/* Right 1 Col: Selected Threat Detail / Local Host Dossier */}
        <div className="p-5 bg-slate-950 border border-slate-800 rounded-xl space-y-4 flex flex-col justify-between">
          <div className="space-y-4">
            {/* Host Geolocation Summary Card */}
            <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 space-y-1.5">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <MapPin className="w-3.5 h-3.5 text-cyan-400" />
                  Machine Locale Détectée
                </span>
                <span className="text-[10px] text-cyan-300 font-bold">
                  {targetHost.latitude.toFixed(2)}°N, {targetHost.longitude.toFixed(2)}°E
                </span>
              </div>
              <div className="text-sm font-bold text-white font-mono">
                {targetHost.city}, {targetHost.country}
              </div>
              <div className="text-xs text-slate-400 font-mono">
                IP Publique : <strong className="text-cyan-300">{targetHost.ip}</strong> · FAI : {targetHost.isp}
              </div>
            </div>

            {/* Selected Threat Inspector */}
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Skull className="w-4 h-4 text-rose-400" />
                <h3 className="text-xs font-bold text-white uppercase font-mono tracking-wider">
                  Nœud C2 Sélectionné
                </h3>
              </div>
              {selectedThreat && (
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
                  selectedThreat.status === 'BLOCKED'
                    ? 'text-slate-400 bg-slate-900 border-slate-700'
                    : selectedThreat.threatIntensity >= 85
                    ? 'text-rose-400 bg-rose-950 border-rose-800'
                    : 'text-amber-400 bg-amber-950 border-amber-800'
                }`}>
                  {selectedThreat.status === 'BLOCKED' ? 'BLOQUÉ' : `INTENSITÉ ${selectedThreat.threatIntensity}%`}
                </span>
              )}
            </div>

            {selectedThreat ? (
              <div className="space-y-3 text-xs font-mono">
                {/* IP & City Card */}
                <div className="p-3 bg-slate-900/90 rounded-lg border border-slate-800 space-y-1">
                  <div className="text-base font-bold text-white flex items-center justify-between">
                    <span>{selectedThreat.ip}:{selectedThreat.port}</span>
                    <span className="text-xs text-rose-400 font-semibold">{selectedThreat.threatType}</span>
                  </div>
                  <div className="text-slate-400">
                    {selectedThreat.city}, {selectedThreat.country}
                  </div>
                  <div className="text-[11px] text-slate-500 pt-1 border-t border-slate-800">
                    {selectedThreat.asOrganization}
                  </div>
                </div>

                {/* Threat Intel Dossier */}
                <div className="space-y-1.5">
                  <div className="text-slate-400 text-[11px]">Renseignement Threat Intel :</div>
                  <p className="text-slate-300 font-sans text-xs leading-relaxed bg-slate-900/50 p-2.5 rounded border border-slate-800/80">
                    {selectedThreat.intel}
                  </p>
                </div>

                {/* Technical Process Metrics */}
                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div className="p-2 bg-slate-900/70 rounded border border-slate-800/60">
                    <span className="text-slate-500">Processus Local :</span>
                    <div className="text-slate-200 font-bold truncate">{selectedThreat.processName}</div>
                    <div className="text-slate-500">PID {selectedThreat.pid}</div>
                  </div>
                  <div className="p-2 bg-slate-900/70 rounded border border-slate-800/60">
                    <span className="text-slate-500">Flux Vers Hôte :</span>
                    <div className="text-cyan-400 font-bold">{selectedThreat.bandwidthKbps} Ko/s</div>
                    <div className="text-slate-500">{selectedThreat.protocol} Socket</div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-8 text-center text-xs text-slate-500 font-mono">
                Sélectionnez un serveur C2 sur la carte pour afficher le dossier technique.
              </div>
            )}
          </div>

          {/* Action Buttons for Selected Node */}
          {selectedThreat && (
            <div className="pt-4 border-t border-slate-800 space-y-2">
              {selectedThreat.status === 'BLOCKED' ? (
                <button
                  onClick={() => handleUnblockIp(selectedThreat.ip)}
                  className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs rounded-lg transition-colors font-mono"
                >
                  Débloquer l'adresse IP
                </button>
              ) : (
                <button
                  onClick={() => handleBlockIp(selectedThreat.ip, selectedThreat.pid)}
                  className="w-full py-2 bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs rounded-lg transition-colors flex items-center justify-center gap-2"
                >
                  <Lock className="w-3.5 h-3.5" />
                  <span>Bloquer IP via Pare-Feu & Tuer PID {selectedThreat.pid}</span>
                </button>
              )}

              {onNavigateTab && (
                <button
                  onClick={() => {
                    onRunInConsole(`geolocate ${selectedThreat.ip}`);
                    onNavigateTab('ip-locator');
                  }}
                  className="w-full py-2 bg-sky-950/80 hover:bg-sky-900/80 border border-sky-700/60 text-sky-200 font-semibold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 font-mono shadow-sm"
                >
                  <Globe className="w-3.5 h-3.5 text-sky-400" />
                  <span>Localiser l'Endroit Précis ({selectedThreat.city})</span>
                </button>
              )}

              <button
                onClick={() => onRunInConsole(`sockets`)}
                className="w-full py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 font-mono text-xs rounded-lg transition-colors"
              >
                Inspecter tous les sockets ouverts (Netstat)
              </button>
            </div>
          ) : (
            <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 text-center space-y-2">
              <div className="w-8 h-8 rounded-full bg-emerald-950/80 border border-emerald-800 text-emerald-400 flex items-center justify-center mx-auto">
                <CheckCircle2 className="w-4 h-4" />
              </div>
              <div className="text-xs font-bold text-slate-200">
                0 Balise C2 Malveillante Détectée
              </div>
              <p className="text-[11px] text-slate-400">
                Tous les flux réseau sortants vers des infrastructures distantes sont sains.
              </p>
              <button
                onClick={() => onRunInConsole(`sockets`)}
                className="w-full mt-2 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 font-mono text-xs rounded-lg transition-colors"
              >
                Inspecter tous les sockets ouverts (Netstat)
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
