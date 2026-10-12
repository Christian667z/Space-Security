import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as d3 from 'd3';
import {
  Globe,
  ShieldAlert,
  Radio,
  Zap,
  Activity,
  Maximize2,
  Minimize2,
  RefreshCw,
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
  Filter
} from 'lucide-react';
import {
  ThreatGeoLocation,
  DETECTED_MALICIOUS_ORIGINS,
  PROTECTED_SYSTEM_LOCATION
} from '../data/threatGeoData';

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

  // States
  const [selectedThreat, setSelectedThreat] = useState<ThreatGeoLocation | null>(
    DETECTED_MALICIOUS_ORIGINS[0]
  );
  const [filterType, setFilterType] = useState<string>('ALL');
  const [viewMode, setViewMode] = useState<'HEATMAP' | 'ARCS' | 'HYBRID'>('HYBRID');
  const [isLiveTelemetry, setIsLiveTelemetry] = useState<boolean>(true);
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [pulseCount, setPulseCount] = useState<number>(0);
  const [blockedIps, setBlockedIps] = useState<Set<string>>(new Set());

  // Dynamic threat nodes with stateful blocked status
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

  // Aggregate stats
  const activeCount = currentThreats.filter(t => t.status === 'ACTIVE').length;
  const maxIntensity = Math.max(...currentThreats.map(t => t.threatIntensity), 0);
  const totalBandwidth = currentThreats
    .filter(t => t.status === 'ACTIVE')
    .reduce((sum, t) => sum + t.bandwidthKbps, 0);

  // Telemetry pulse simulation
  useEffect(() => {
    if (!isLiveTelemetry) return;
    const interval = setInterval(() => {
      setPulseCount(prev => prev + 1);
    }, 2500);
    return () => clearInterval(interval);
  }, [isLiveTelemetry]);

  // D3 Rendering
  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const width = containerRef.current.clientWidth || 900;
    const height = Math.min(520, Math.max(380, width * 0.48));

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    svg.attr('viewBox', `0 0 ${width} ${height}`);

    // D3 Projection: Natural Earth or Equirectangular
    const projection = d3
      .geoNaturalEarth1()
      .scale(width / 5.8 * zoomLevel)
      .translate([width / 2, height / 2]);

    const pathGenerator = d3.geoPath().projection(projection);

    // Defs: Gradients, Filters & Heatmap radial gradients
    const defs = svg.append('defs');

    // Glow filter
    const filter = defs.append('filter')
      .attr('id', 'map-glow')
      .attr('x', '-50%')
      .attr('y', '-50%')
      .attr('width', '200%')
      .attr('height', '200%');
    filter.append('feGaussianBlur')
      .attr('stdDeviation', '4')
      .attr('result', 'coloredBlur');
    const feMerge = filter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Heatmap color scale: Low (cyan/amber) to High/Critical (rose/crimson/neon red)
    const heatColorScale = d3.scaleSequential()
      .domain([30, 100])
      .interpolator(d3.interpolateRgbBasis([
        '#06b6d4', // cyan-500
        '#eab308', // amber-500
        '#f97316', // orange-500
        '#ef4444', // red-500
        '#ff0055'  // intense neon crimson
      ]));

    // Background Map Ocean Grid
    const g = svg.append('g').attr('class', 'map-container');

    // Graticule (lat/long grid lines)
    const graticule = d3.geoGraticule().step([20, 20]);
    g.append('path')
      .datum(graticule)
      .attr('class', 'graticule')
      .attr('d', pathGenerator)
      .attr('fill', 'none')
      .attr('stroke', '#1e293b')
      .attr('stroke-width', 0.5)
      .attr('stroke-dasharray', '2 4')
      .attr('opacity', 0.6);

    // Simplified high-aesthetic world map landmass shapes (GeoJSON coordinates)
    // Detailed continents polygons for dark cyber theme
    const worldGeoData: any = {
      type: 'FeatureCollection',
      features: [
        // North America
        {
          type: 'Feature',
          properties: { name: 'North America' },
          geometry: {
            type: 'Polygon',
            coordinates: [[
              [-168, 65], [-140, 70], [-105, 75], [-75, 72], [-55, 60],
              [-60, 45], [-75, 35], [-80, 25], [-90, 20], [-100, 20],
              [-110, 23], [-118, 32], [-124, 40], [-125, 49], [-140, 58],
              [-165, 60], [-168, 65]
            ]]
          }
        },
        // Greenland
        {
          type: 'Feature',
          properties: { name: 'Greenland' },
          geometry: {
            type: 'Polygon',
            coordinates: [[
              [-45, 60], [-20, 70], [-25, 82], [-55, 82], [-55, 70], [-45, 60]
            ]]
          }
        },
        // South America
        {
          type: 'Feature',
          properties: { name: 'South America' },
          geometry: {
            type: 'Polygon',
            coordinates: [[
              [-80, 10], [-60, 12], [-50, 0], [-35, -5], [-35, -12],
              [-40, -22], [-52, -33], [-65, -55], [-75, -50], [-72, -40],
              [-70, -25], [-78, -5], [-80, 10]
            ]]
          }
        },
        // Europe
        {
          type: 'Feature',
          properties: { name: 'Europe' },
          geometry: {
            type: 'Polygon',
            coordinates: [[
              [-10, 36], [0, 43], [-5, 48], [2, 51], [8, 55], [10, 60],
              [25, 71], [40, 68], [45, 55], [35, 45], [28, 41], [15, 38],
              [0, 36], [-10, 36]
            ]]
          }
        },
        // UK & Scandinavia
        {
          type: 'Feature',
          properties: { name: 'Scandinavia' },
          geometry: {
            type: 'Polygon',
            coordinates: [[
              [5, 58], [15, 56], [28, 60], [28, 70], [18, 68], [5, 62], [5, 58]
            ]]
          }
        },
        // Africa
        {
          type: 'Feature',
          properties: { name: 'Africa' },
          geometry: {
            type: 'Polygon',
            coordinates: [[
              [-17, 30], [10, 37], [25, 32], [35, 30], [43, 12], [51, 10],
              [40, -5], [35, -25], [20, -35], [15, -30], [12, -5], [0, 5],
              [-15, 10], [-17, 30]
            ]]
          }
        },
        // Eurasia / Russia / Northern Asia
        {
          type: 'Feature',
          properties: { name: 'Russia & North Asia' },
          geometry: {
            type: 'Polygon',
            coordinates: [[
              [35, 45], [45, 55], [40, 68], [60, 72], [100, 76], [140, 74],
              [170, 66], [175, 60], [150, 50], [130, 45], [115, 40],
              [90, 48], [60, 45], [45, 40], [35, 45]
            ]]
          }
        },
        // Central & East Asia (China, India, Japan)
        {
          type: 'Feature',
          properties: { name: 'Central & East Asia' },
          geometry: {
            type: 'Polygon',
            coordinates: [[
              [60, 25], [72, 35], [90, 48], [115, 40], [122, 32], [120, 22],
              [108, 18], [100, 8], [80, 8], [70, 20], [60, 25]
            ]]
          }
        },
        // Japan
        {
          type: 'Feature',
          properties: { name: 'Japan' },
          geometry: {
            type: 'Polygon',
            coordinates: [[
              [130, 32], [140, 36], [145, 44], [140, 44], [132, 34], [130, 32]
            ]]
          }
        },
        // South East Asia & Indonesia
        {
          type: 'Feature',
          properties: { name: 'SE Asia' },
          geometry: {
            type: 'Polygon',
            coordinates: [[
              [95, 20], [110, 22], [110, 10], [100, 2], [95, 10], [95, 20]
            ]]
          }
        },
        // Australia
        {
          type: 'Feature',
          properties: { name: 'Australia' },
          geometry: {
            type: 'Polygon',
            coordinates: [[
              [115, -22], [125, -15], [138, -12], [148, -20], [152, -32],
              [142, -38], [128, -35], [115, -34], [115, -22]
            ]]
          }
        }
      ]
    };

    // Render world landmass polygons
    g.selectAll('path.country')
      .data(worldGeoData.features)
      .enter()
      .append('path')
      .attr('class', 'country')
      .attr('d', pathGenerator as any)
      .attr('fill', '#0f172a')
      .attr('stroke', '#334155')
      .attr('stroke-width', 0.8)
      .attr('opacity', 0.95);

    // Target endpoint position (Paris)
    const targetCoords: [number, number] = [
      PROTECTED_SYSTEM_LOCATION.longitude,
      PROTECTED_SYSTEM_LOCATION.latitude,
    ];
    const targetProjected = projection(targetCoords) || [width / 2, height / 2];

    // ==========================================
    // LAYER 1: D3 HEATMAP INTENSITY DENSITY CONTOURS
    // ==========================================
    if (viewMode === 'HEATMAP' || viewMode === 'HYBRID') {
      const heatGroup = g.append('g').attr('class', 'heat-layer');

      // Create radial blurred heat gradients for each malicious hotspot
      currentThreats.forEach((threat, i) => {
        const coords = projection([threat.longitude, threat.latitude]);
        if (!coords) return;

        const isThreatBlocked = threat.status === 'BLOCKED';
        const intensity = threat.threatIntensity;
        const radius = Math.max(16, (intensity / 100) * 48);

        // Unique radial gradient ID
        const gradId = `heat-grad-${threat.id}`;
        const radGrad = defs.append('radialGradient')
          .attr('id', gradId)
          .attr('cx', '50%')
          .attr('cy', '50%')
          .attr('r', '50%');

        const baseColor = isThreatBlocked ? '#38bdf8' : heatColorScale(intensity);

        radGrad.append('stop')
          .attr('offset', '0%')
          .attr('stop-color', baseColor)
          .attr('stop-opacity', isThreatBlocked ? 0.4 : 0.8);

        radGrad.append('stop')
          .attr('offset', '50%')
          .attr('stop-color', baseColor)
          .attr('stop-opacity', isThreatBlocked ? 0.15 : 0.4);

        radGrad.append('stop')
          .attr('offset', '100%')
          .attr('stop-color', baseColor)
          .attr('stop-opacity', 0);

        // Append heat halo circle
        heatGroup.append('circle')
          .attr('cx', coords[0])
          .attr('cy', coords[1])
          .attr('r', radius)
          .attr('fill', `url(#${gradId})`)
          .attr('pointer-events', 'none')
          .attr('class', 'threat-heat-halo');

        // Concentric intensity ring
        heatGroup.append('circle')
          .attr('cx', coords[0])
          .attr('cy', coords[1])
          .attr('r', radius * 0.55)
          .attr('fill', 'none')
          .attr('stroke', baseColor)
          .attr('stroke-width', 0.8)
          .attr('stroke-dasharray', '3 3')
          .attr('opacity', isThreatBlocked ? 0.3 : 0.7);
      });
    }

    // ==========================================
    // LAYER 2: ATTACK ARCS & C2 TRAFFIC VECTORS
    // ==========================================
    if (viewMode === 'ARCS' || viewMode === 'HYBRID') {
      const arcGroup = g.append('g').attr('class', 'arcs-layer');

      currentThreats.forEach(threat => {
        const sourceCoords = projection([threat.longitude, threat.latitude]);
        if (!sourceCoords) return;

        const isBlocked = threat.status === 'BLOCKED';
        const color = isBlocked
          ? '#64748b'
          : threat.threatType === 'C2_BEACON'
          ? '#f43f5e'
          : threat.threatType === 'DATA_EXFIL'
          ? '#f59e0b'
          : '#a855f7';

        // Curved quadratic Bézier arc towards protected station
        const dx = targetProjected[0] - sourceCoords[0];
        const dy = targetProjected[1] - sourceCoords[1];
        const dr = Math.sqrt(dx * dx + dy * dy);

        // Midpoint offset for cyber arch curve
        const midX = (sourceCoords[0] + targetProjected[0]) / 2;
        const midY = (sourceCoords[1] + targetProjected[1]) / 2 - Math.min(60, dr * 0.28);

        const arcPath = `M ${sourceCoords[0]} ${sourceCoords[1]} Q ${midX} ${midY} ${targetProjected[0]} ${targetProjected[1]}`;

        // Base faint line
        arcGroup.append('path')
          .attr('d', arcPath)
          .attr('fill', 'none')
          .attr('stroke', color)
          .attr('stroke-width', isBlocked ? 1 : Math.max(1.2, (threat.threatIntensity / 100) * 2.4))
          .attr('stroke-dasharray', isBlocked ? '3 3' : '4 4')
          .attr('opacity', isBlocked ? 0.35 : 0.65);

        // Animated packet particle traveling along arc if active
        if (!isBlocked && isLiveTelemetry) {
          const packetId = `packet-${threat.id}`;
          const particle = arcGroup.append('circle')
            .attr('id', packetId)
            .attr('r', 3)
            .attr('fill', color)
            .attr('filter', 'url(#map-glow)');

          // Native D3 transition along the arc path
          const pathEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
          pathEl.setAttribute('d', arcPath);
          const pathLength = pathEl.getTotalLength();

          const animatePacket = () => {
            particle
              .transition()
              .duration(1800 + Math.random() * 800)
              .ease(d3.easeLinear)
              .attrTween('transform', () => {
                return (t: number) => {
                  const p = pathEl.getPointAtLength((1 - t) * pathLength); // Malicious origin -> Target
                  return `translate(${p.x}, ${p.y})`;
                };
              })
              .on('end', () => {
                if (isLiveTelemetry) animatePacket();
              });
          };

          animatePacket();
        }
      });
    }

    // ==========================================
    // LAYER 3: THREAT ORIGIN NODES & INTERACTION
    // ==========================================
    const nodesGroup = g.append('g').attr('class', 'nodes-layer');

    currentThreats.forEach(threat => {
      const coords = projection([threat.longitude, threat.latitude]);
      if (!coords) return;

      const isSelected = selectedThreat?.id === threat.id;
      const isBlocked = threat.status === 'BLOCKED';
      const nodeColor = isBlocked ? '#64748b' : heatColorScale(threat.threatIntensity);

      const nodeG = nodesGroup.append('g')
        .attr('transform', `translate(${coords[0]}, ${coords[1]})`)
        .attr('cursor', 'pointer')
        .on('click', () => {
          setSelectedThreat(threat);
        });

      // Animated pulsating wave for critical active threats
      if (!isBlocked && threat.threatIntensity >= 70) {
        nodeG.append('circle')
          .attr('r', 8)
          .attr('fill', 'none')
          .attr('stroke', nodeColor)
          .attr('stroke-width', 1.5)
          .attr('opacity', 0.8)
          .transition()
          .duration(1600)
          .ease(d3.easeCubicOut)
          .attr('r', 22)
          .attr('opacity', 0)
          .on('end', function repeat() {
            d3.select(this)
              .attr('r', 8)
              .attr('opacity', 0.8)
              .transition()
              .duration(1600)
              .ease(d3.easeCubicOut)
              .attr('r', 22)
              .attr('opacity', 0)
              .on('end', repeat);
          });
      }

      // Outer Selection Target Reticle
      if (isSelected) {
        nodeG.append('circle')
          .attr('r', 14)
          .attr('fill', 'none')
          .attr('stroke', '#38bdf8')
          .attr('stroke-width', 1.5)
          .attr('stroke-dasharray', '2 2')
          .attr('filter', 'url(#map-glow)');
      }

      // Core Node Pin
      nodeG.append('circle')
        .attr('r', isSelected ? 6.5 : 5)
        .attr('fill', isBlocked ? '#475569' : nodeColor)
        .attr('stroke', '#020617')
        .attr('stroke-width', 1.5);

      // Micro Label
      nodeG.append('text')
        .attr('x', 9)
        .attr('y', 4)
        .attr('font-size', '10px')
        .attr('font-family', 'monospace')
        .attr('font-weight', isSelected ? 'bold' : 'normal')
        .attr('fill', isSelected ? '#38bdf8' : '#94a3b8')
        .text(`${threat.ip}:${threat.port}`);
    });

    // ==========================================
    // LAYER 4: TARGET SYSTEM (PARIS SOC ENDPOINT)
    // ==========================================
    const targetG = g.append('g')
      .attr('transform', `translate(${targetProjected[0]}, ${targetProjected[1]})`)
      .attr('class', 'target-endpoint');

    // Radar pulse ring
    targetG.append('circle')
      .attr('r', 16)
      .attr('fill', 'none')
      .attr('stroke', '#06b6d4')
      .attr('stroke-width', 1)
      .attr('stroke-dasharray', '3 3')
      .attr('opacity', 0.6);

    // Central cyan badge
    targetG.append('circle')
      .attr('r', 6)
      .attr('fill', '#06b6d4')
      .attr('stroke', '#ffffff')
      .attr('stroke-width', 1.5)
      .attr('filter', 'url(#map-glow)');

    targetG.append('text')
      .attr('x', -10)
      .attr('y', -12)
      .attr('text-anchor', 'middle')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace')
      .attr('font-weight', 'bold')
      .attr('fill', '#22d3ee')
      .text('ENDPOINT (HÔTE)');

  }, [currentThreats, selectedThreat, viewMode, zoomLevel, isLiveTelemetry, pulseCount]);

  // Handler: Block IP
  const handleBlockIp = (ip: string, pid?: number) => {
    setBlockedIps(prev => {
      const next = new Set(prev);
      next.add(ip);
      return next;
    });
    onRunInConsole(`netsh advfirewall firewall add rule name="Block_C2_${ip}" dir=out action=block remoteip=${ip}`);
    if (pid) {
      setTimeout(() => {
        onRunInConsole(`kill ${pid}`);
      }, 600);
    }
  };

  // Handler: Unblock IP
  const handleUnblockIp = (ip: string) => {
    setBlockedIps(prev => {
      const next = new Set(prev);
      next.delete(ip);
      return next;
    });
    onRunInConsole(`netsh advfirewall firewall delete rule name="Block_C2_${ip}"`);
  };

  return (
    <div className="p-5 md:p-6 bg-slate-900 border border-slate-800 rounded-2xl space-y-5 shadow-2xl relative overflow-hidden">
      {/* Top Header Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="p-1.5 rounded-lg bg-rose-950/80 border border-rose-800/80 text-rose-400">
              <Flame className="w-4 h-4 animate-pulse" />
            </div>
            <div className="flex items-center gap-2">
              <h3 className="text-base md:text-lg font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
                Carte Thermique d'Intensité des Menaces & Origines Géographiques C2
              </h3>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-rose-950 text-rose-300 border border-rose-800">
                D3 Heatmap · ISO 27001
              </span>
            </div>
          </div>
          <p className="text-xs text-slate-400">
            Visualisation géospatiale D3.js en temps réel des sockets Command & Control (C2), exfiltrations massives et balises APT identifiées dans le module Réseau.
          </p>
        </div>

        {/* Live Controls & Mode Selector */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {/* Mode Switcher */}
          <div className="flex items-center p-1 bg-slate-950 rounded-lg border border-slate-800 text-xs">
            <button
              onClick={() => setViewMode('HYBRID')}
              className={`px-2.5 py-1 rounded transition-colors ${
                viewMode === 'HYBRID'
                  ? 'bg-cyan-950 border border-cyan-800 text-cyan-300 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Hybride
            </button>
            <button
              onClick={() => setViewMode('HEATMAP')}
              className={`px-2.5 py-1 rounded transition-colors ${
                viewMode === 'HEATMAP'
                  ? 'bg-rose-950 border border-rose-800 text-rose-300 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Heatmap
            </button>
            <button
              onClick={() => setViewMode('ARCS')}
              className={`px-2.5 py-1 rounded transition-colors ${
                viewMode === 'ARCS'
                  ? 'bg-indigo-950 border border-indigo-800 text-indigo-300 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Vecteurs
            </button>
          </div>

          {/* Live Telemetry Toggle */}
          <button
            onClick={() => setIsLiveTelemetry(!isLiveTelemetry)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono font-semibold transition-colors ${
              isLiveTelemetry
                ? 'bg-rose-950/70 border-rose-800 text-rose-300'
                : 'bg-slate-950 border-slate-800 text-slate-400'
            }`}
          >
            <Radio className={`w-3.5 h-3.5 ${isLiveTelemetry ? 'text-rose-400 animate-spin' : 'text-slate-500'}`} />
            <span>{isLiveTelemetry ? 'FLUX TEMPS RÉEL' : 'PAUSE TÉLÉMÉTRIE'}</span>
          </button>

          {/* Quick Deep Network Tab Link */}
          {onNavigateTab && (
            <button
              onClick={() => onNavigateTab('network')}
              className="flex items-center gap-1 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg font-medium transition-colors border border-slate-700"
            >
              <Server className="w-3.5 h-3.5 text-cyan-400" />
              <span>Détails Sockets C2</span>
            </button>
          )}
        </div>
      </div>

      {/* KPI Micro Ribbons */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800/80 flex items-center justify-between">
          <div>
            <div className="text-[11px] text-slate-400 font-medium">Origines C2 Actives</div>
            <div className="text-lg font-bold text-rose-400 font-mono">{activeCount} Hôtes</div>
          </div>
          <div className="p-2 rounded-lg bg-rose-950/50 border border-rose-900/60 text-rose-400">
            <ShieldAlert className="w-4 h-4" />
          </div>
        </div>

        <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800/80 flex items-center justify-between">
          <div>
            <div className="text-[11px] text-slate-400 font-medium">Intensité Maximale</div>
            <div className="text-lg font-bold text-amber-400 font-mono">{maxIntensity} / 100</div>
          </div>
          <div className="p-2 rounded-lg bg-amber-950/50 border border-amber-900/60 text-amber-400">
            <TrendingUp className="w-4 h-4" />
          </div>
        </div>

        <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800/80 flex items-center justify-between">
          <div>
            <div className="text-[11px] text-slate-400 font-medium">Bande Passante C2 Sortante</div>
            <div className="text-lg font-bold text-cyan-300 font-mono">{totalBandwidth} KB/s</div>
          </div>
          <div className="p-2 rounded-lg bg-cyan-950/50 border border-cyan-900/60 text-cyan-400">
            <Activity className="w-4 h-4" />
          </div>
        </div>

        <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800/80 flex items-center justify-between">
          <div>
            <div className="text-[11px] text-slate-400 font-medium">Pare-feu Sortant</div>
            <div className="text-lg font-bold text-emerald-400 font-mono">
              {blockedIps.size > 0 ? `${blockedIps.size} Bloquée(s)` : 'Surveillance'}
            </div>
          </div>
          <div className="p-2 rounded-lg bg-emerald-950/50 border border-emerald-900/60 text-emerald-400">
            <Lock className="w-4 h-4" />
          </div>
        </div>
      </div>

      {/* Main Map Canvas & Interactive Inspector Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column: Interactive D3 Geo SVG Canvas */}
        <div className="lg:col-span-8 flex flex-col space-y-2">
          {/* Controls Bar */}
          <div className="flex items-center justify-between px-2 text-xs text-slate-400">
            <div className="flex items-center gap-2">
              <span className="text-[11px] uppercase font-mono tracking-wider text-slate-500">Filtrer menaces :</span>
              <div className="flex items-center gap-1">
                {(['ALL', 'ACTIVE', 'C2', 'EXFIL', 'BLOCKED'] as const).map(f => (
                  <button
                    key={f}
                    onClick={() => setFilterType(f)}
                    className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors ${
                      filterType === f
                        ? 'bg-slate-800 text-cyan-300 font-semibold'
                        : 'text-slate-500 hover:text-slate-300'
                    }`}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setZoomLevel(prev => Math.min(2.0, prev + 0.2))}
                className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs"
                title="Zoomer sur la carte"
              >
                +
              </button>
              <button
                onClick={() => setZoomLevel(prev => Math.max(0.8, prev - 0.2))}
                className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs"
                title="Dézoomer"
              >
                -
              </button>
              <button
                onClick={() => setZoomLevel(1)}
                className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px]"
              >
                Reset
              </button>
            </div>
          </div>

          {/* SVG Map Container */}
          <div
            ref={containerRef}
            className="w-full bg-slate-950 rounded-xl border border-slate-800/90 overflow-hidden relative shadow-inner flex items-center justify-center min-h-[360px]"
          >
            <svg
              ref={svgRef}
              className="w-full h-auto block select-none"
              style={{ maxHeight: '480px' }}
            />

            {/* In-Map Heat Legend Overlay */}
            <div className="absolute bottom-3 left-3 bg-slate-900/90 backdrop-blur-md border border-slate-800 p-2.5 rounded-lg text-[10px] space-y-1.5 shadow-lg">
              <div className="text-slate-300 font-mono font-bold flex items-center gap-1.5">
                <Flame className="w-3 h-3 text-rose-400" />
                <span>Densité d'Intensité (D3 Gradient)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-slate-400 font-mono">Modérée</span>
                <div className="w-24 h-2 rounded bg-gradient-to-r from-cyan-400 via-amber-400 to-rose-500" />
                <span className="text-rose-400 font-mono font-bold">Critique</span>
              </div>
              <div className="flex items-center gap-3 text-slate-400 font-mono pt-0.5">
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 inline-block" />
                  <span>Station Hôte</span>
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-rose-500 inline-block" />
                  <span>IP Malveillante</span>
                </span>
              </div>
            </div>

            {/* Corner Quick Status Tag */}
            <div className="absolute top-3 right-3 flex items-center gap-2 bg-slate-900/80 backdrop-blur border border-slate-800 px-2.5 py-1 rounded-md text-[11px] font-mono text-slate-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>Cible : {PROTECTED_SYSTEM_LOCATION.city} ({PROTECTED_SYSTEM_LOCATION.ip})</span>
            </div>
          </div>
        </div>

        {/* Right Column: Detailed Forensic Inspector of Selected Malicious IP */}
        <div className="lg:col-span-4 flex flex-col space-y-4">
          {selectedThreat ? (
            <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-4 flex-1 flex flex-col justify-between shadow-lg">
              <div className="space-y-3">
                {/* Header IP & Threat Classification */}
                <div className="flex items-start justify-between gap-2 border-b border-slate-800/80 pb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-base font-extrabold text-white font-mono">
                        {selectedThreat.ip}:{selectedThreat.port}
                      </span>
                      {selectedThreat.status === 'BLOCKED' ? (
                        <span className="px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-300 font-mono text-[10px] font-bold">
                          BLOQUÉE
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-rose-950 border border-rose-800 text-rose-300 font-mono text-[10px] font-bold animate-pulse">
                          ACTIVE C2
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-slate-400 mt-0.5 flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5 text-cyan-400" />
                      <span>{selectedThreat.city}, {selectedThreat.country}</span>
                    </div>
                  </div>

                  <div className="text-right">
                    <div className="text-xs text-slate-400 font-mono">Score Menace</div>
                    <div className="text-lg font-black text-rose-400 font-mono">
                      {selectedThreat.threatIntensity}%
                    </div>
                  </div>
                </div>

                {/* Threat Intel Details Card */}
                <div className="p-3 bg-slate-900/90 rounded-lg border border-slate-800 space-y-2 text-xs">
                  <div className="text-slate-300 font-medium leading-snug">
                    {selectedThreat.intel}
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-slate-400 pt-1 border-t border-slate-800/60">
                    <div>
                      <span className="text-slate-500">Processus Local:</span>
                      <div className="text-slate-200 font-semibold truncate">{selectedThreat.processName}</div>
                    </div>
                    <div>
                      <span className="text-slate-500">PID Système:</span>
                      <div className="text-cyan-300 font-semibold">{selectedThreat.pid}</div>
                    </div>
                    <div>
                      <span className="text-slate-500">Débit Détecté:</span>
                      <div className="text-amber-400 font-semibold">{selectedThreat.bandwidthKbps} KB/s</div>
                    </div>
                    <div>
                      <span className="text-slate-500">Protocole:</span>
                      <div className="text-slate-300 font-semibold">{selectedThreat.protocol} / Sockets</div>
                    </div>
                  </div>

                  <div className="text-[10px] text-slate-500 font-mono truncate">
                    Fournisseur AS : {selectedThreat.asOrganization}
                  </div>
                </div>

                {/* Threat Intensity Meter Bar */}
                <div className="space-y-1">
                  <div className="flex items-center justify-between text-[11px] font-mono">
                    <span className="text-slate-400">Intensité Heatmap Calculée :</span>
                    <span className="text-rose-400 font-bold">{selectedThreat.threatIntensity} / 100</span>
                  </div>
                  <div className="w-full h-2 rounded bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full transition-all duration-500 ${
                        selectedThreat.status === 'BLOCKED'
                          ? 'bg-slate-600'
                          : selectedThreat.threatIntensity > 80
                          ? 'bg-gradient-to-r from-orange-500 to-rose-600'
                          : 'bg-gradient-to-r from-cyan-400 to-amber-500'
                      }`}
                      style={{ width: `${selectedThreat.threatIntensity}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* Action Buttons for Incident Response */}
              <div className="space-y-2 pt-2 border-t border-slate-800/80">
                {selectedThreat.status !== 'BLOCKED' ? (
                  <button
                    onClick={() => handleBlockIp(selectedThreat.ip, selectedThreat.pid)}
                    className="w-full flex items-center justify-center gap-2 py-2 px-3 bg-rose-600 hover:bg-rose-500 text-white font-bold rounded-lg text-xs transition-colors shadow-md group"
                  >
                    <Lock className="w-3.5 h-3.5" />
                    <span>Bloquer IP Pare-feu & Tuer PID {selectedThreat.pid}</span>
                  </button>
                ) : (
                  <button
                    onClick={() => handleUnblockIp(selectedThreat.ip)}
                    className="w-full flex items-center justify-center gap-2 py-2 px-3 bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold rounded-lg text-xs transition-colors"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Débloquer l'adresse IP</span>
                  </button>
                )}

                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => onRunInConsole(`whois ${selectedThreat.ip}`)}
                    className="flex items-center justify-center gap-1.5 py-1.5 px-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold rounded text-[11px] transition-colors"
                  >
                    <Terminal className="w-3 h-3 text-cyan-400" />
                    <span>Whois AS Intel</span>
                  </button>

                  <button
                    onClick={() => onRunInConsole(`isolate-host --isolate-ip ${selectedThreat.ip}`)}
                    className="flex items-center justify-center gap-1.5 py-1.5 px-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold rounded text-[11px] transition-colors"
                  >
                    <Crosshair className="w-3 h-3 text-rose-400" />
                    <span>Isoler Hôte</span>
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-6 bg-slate-950 rounded-xl border border-slate-800 text-center space-y-2 flex-1 flex flex-col items-center justify-center">
              <Globe className="w-8 h-8 text-slate-600" />
              <div className="text-xs text-slate-400">
                Sélectionnez un point d'origine malveillant sur la carte D3 pour inspecter ses caractéristiques de menace et déployer une contre-mesure.
              </div>
            </div>
          )}

          {/* Quick List of Active C2 Origins */}
          <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
            <div className="text-xs font-bold text-slate-300 flex items-center justify-between">
              <span>Hôtes C2 Actifs ({currentThreats.length})</span>
              <span className="text-[10px] font-mono text-cyan-400">Cliquez pour cibler</span>
            </div>
            <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
              {currentThreats.map(t => {
                const isSelected = selectedThreat?.id === t.id;
                const isBlocked = t.status === 'BLOCKED';
                return (
                  <div
                    key={t.id}
                    onClick={() => setSelectedThreat(t)}
                    className={`p-2 rounded-lg border text-xs font-mono cursor-pointer transition-colors flex items-center justify-between ${
                      isSelected
                        ? 'bg-cyan-950/70 border-cyan-700 text-cyan-200'
                        : isBlocked
                        ? 'bg-slate-900/40 border-slate-800/80 text-slate-500'
                        : 'bg-slate-900 border-slate-800/80 hover:border-slate-700 text-slate-300'
                    }`}
                  >
                    <div className="flex items-center gap-2 truncate">
                      <span
                        className={`w-2 h-2 rounded-full shrink-0 ${
                          isBlocked ? 'bg-slate-500' : t.threatIntensity > 80 ? 'bg-rose-500' : 'bg-amber-400'
                        }`}
                      />
                      <span className="font-semibold truncate">{t.ip}</span>
                      <span className="text-[10px] text-slate-500">{t.countryCode}</span>
                    </div>
                    <span className="text-[10px] text-slate-400 shrink-0 font-bold">
                      {isBlocked ? 'BLOQUÉ' : `${t.threatIntensity}%`}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
