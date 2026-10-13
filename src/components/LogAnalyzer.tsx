import React, { useState, useEffect, useCallback } from 'react';
import { ShieldAlert, AlertTriangle, FileText, Filter, Terminal, Search, Upload, Download, Copy, Check, Info, Shield, Radio, RefreshCw } from 'lucide-react';
import { WindowsEventLogEntry } from '../types/cyberdefense';
import { apiFetch } from '../utils/api';

interface LogAnalyzerProps {
  onRunInConsole: (command: string) => void;
}

export const LogAnalyzer: React.FC<LogAnalyzerProps> = ({ onRunInConsole }) => {
  const initialEvents: WindowsEventLogEntry[] = [
    {
      id: 'ev-init-1',
      eventId: 4624,
      channel: 'Security',
      timeCreated: new Date().toLocaleTimeString('fr-FR'),
      level: 'INFORMATION',
      source: 'Microsoft-Windows-Security-Auditing',
      user: 'NT AUTHORITY\\SYSTEM',
      computer: 'SEC-LOCAL-WORKSTATION',
      description: 'Ouverture de session Windows réussie. Authentification Kerberos / NTLM vérifiée.',
      rawPayload: 'LogonType: 2 (Interactive) | AuthenticationPackage: Kerberos | ElevationType: Full',
      mitreTactic: 'Contrôle d\'Accès & Identité',
      isIsolatedThreat: false,
    },
    {
      id: 'ev-init-2',
      eventId: 1000,
      channel: 'System',
      timeCreated: new Date().toLocaleTimeString('fr-FR'),
      level: 'INFORMATION',
      source: 'Microsoft-Windows-Kernel-General',
      user: 'SYSTEM',
      computer: 'SEC-LOCAL-WORKSTATION',
      description: 'Démarrage du système d\'exploitation et chargement des sous-systèmes d\'intégrité.',
      rawPayload: 'OSBoot: Clean | HypervisorEnforcedCodeIntegrity: Active',
      mitreTactic: 'Intégrité du Système',
      isIsolatedThreat: false,
    },
    {
      id: 'ev-init-3',
      eventId: 1116,
      channel: 'Defender',
      timeCreated: new Date().toLocaleTimeString('fr-FR'),
      level: 'INFORMATION',
      source: 'Microsoft-Windows-Windows Defender',
      user: 'SYSTEM',
      computer: 'SEC-LOCAL-WORKSTATION',
      description: 'Protection en temps réel opérationnelle. Base virale à jour.',
      rawPayload: 'EngineVersion: 1.1.24050.5 | SignaturesVersion: 1.411.120.0 | Status: Healthy',
      mitreTactic: 'Protection Endpoint',
      isIsolatedThreat: false,
    },
  ];

  const [events, setEvents] = useState<WindowsEventLogEntry[]>(initialEvents);
  const [isLoadingLogs, setIsLoadingLogs] = useState<boolean>(false);
  const [channelFilter, setChannelFilter] = useState<string>('ALL');

  // Fetch real Windows Event Logs from host endpoint
  const fetchRealLogs = useCallback(async (channel = 'System') => {
    setIsLoadingLogs(true);
    try {
      const res = await apiFetch(`/api/system/eventlogs?channel=${encodeURIComponent(channel)}`);
      if (res.ok) {
        const data = await res.json();
        if (data.success && Array.isArray(data.events) && data.events.length > 0) {
          setEvents(data.events);
        }
      }
    } catch (err) {
      console.warn('[LogAnalyzer] Failed to fetch real logs:', err);
    } finally {
      setIsLoadingLogs(false);
    }
  }, []);

  useEffect(() => {
    fetchRealLogs(channelFilter === 'ALL' ? 'System' : channelFilter);
  }, [fetchRealLogs, channelFilter]);
  const [levelFilter, setLevelFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [isolatedOnly, setIsolatedOnly] = useState<boolean>(false);
  const [selectedEvent, setSelectedEvent] = useState<WindowsEventLogEntry | null>(null);

  // Raw Log Ingestion modal/toggle
  const [showRawIngestion, setShowRawIngestion] = useState<boolean>(false);
  const [rawInputText, setRawInputText] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopyRaw = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Ingestion parser
  const handleParseRawInput = () => {
    if (!rawInputText.trim()) return;

    const lines = rawInputText.split('\n').filter(l => l.trim().length > 0);
    const parsed: WindowsEventLogEntry[] = [];
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);

    lines.forEach((line, index) => {
      const lower = line.toLowerCase();
      const hasCritical = lower.includes('error') || lower.includes('fail') || lower.includes('trojan') || lower.includes('mimikatz') || lower.includes('bypass') || lower.includes('4625') || lower.includes('4104') || lower.includes('1102');
      const hasWarning = lower.includes('warn') || lower.includes('suspect') || lower.includes('7045');

      let detectedId = 4688;
      if (lower.includes('4625')) detectedId = 4625;
      else if (lower.includes('4104')) detectedId = 4104;
      else if (lower.includes('1102')) detectedId = 1102;
      else if (lower.includes('7045')) detectedId = 7045;
      else if (lower.includes('1116')) detectedId = 1116;

      let channel: WindowsEventLogEntry['channel'] = 'Security';
      if (lower.includes('powershell')) channel = 'PowerShell';
      else if (lower.includes('defender')) channel = 'Defender';
      else if (lower.includes('system') || lower.includes('service')) channel = 'System';

      const entry: WindowsEventLogEntry = {
        id: `raw-${Date.now()}-${index}`,
        eventId: detectedId,
        channel,
        timeCreated: timestamp,
        level: hasCritical ? 'CRITICAL' : hasWarning ? 'WARNING' : 'INFORMATION',
        source: 'Custom-Log-Ingestor',
        user: lower.includes('system') ? 'NT AUTHORITY\\SYSTEM' : 'User',
        computer: 'SEC-ENDPOINT-01',
        description: line.substring(0, 240),
        rawPayload: line,
        mitreTactic: hasCritical ? 'T1059 / T1562 Incident Flag' : undefined,
        isIsolatedThreat: hasCritical || hasWarning,
      };
      parsed.push(entry);
    });

    setEvents(prev => [...parsed, ...prev]);
    setRawInputText('');
    setShowRawIngestion(false);
  };

  const handleExportJson = () => {
    const jsonStr = JSON.stringify(events, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `Windows_EventLog_Threats_${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const filteredEvents = events.filter(evt => {
    if (isolatedOnly && !evt.isIsolatedThreat) return false;
    if (channelFilter !== 'ALL' && evt.channel !== channelFilter) return false;
    if (levelFilter !== 'ALL' && evt.level !== levelFilter) return false;

    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      const match = evt.eventId.toString().includes(q) ||
        evt.description.toLowerCase().includes(q) ||
        evt.source.toLowerCase().includes(q) ||
        (evt.mitreTactic && evt.mitreTactic.toLowerCase().includes(q)) ||
        (evt.user && evt.user.toLowerCase().includes(q));
      if (!match) return false;
    }

    return true;
  });

  const criticalCount = events.filter(e => e.level === 'CRITICAL').length;
  const warningCount = events.filter(e => e.level === 'WARNING').length;
  const isolatedThreatsCount = events.filter(e => e.isIsolatedThreat).length;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl space-y-4 p-5 font-mono text-xs">
      {/* Top Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <h3 className="text-base font-bold text-white tracking-tight font-['Plus_Jakarta_Sans']">
              LogAnalyzer : Parseur Windows EventLog & Isolation des Menaces
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Extraction et analyse automatique des journaux d'événements Windows (Security 4688, 4625, PowerShell 4104, Defender 1116) pour isoler les erreurs et attaques en temps réel.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            onClick={() => onRunInConsole('eventlog --security')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 font-semibold rounded-lg text-xs transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Get-WinEvent (Live)</span>
          </button>

          <button
            onClick={() => setShowRawIngestion(prev => !prev)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold rounded-lg text-xs transition-colors"
          >
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span>Ingérer Logs Bruts</span>
          </button>

          <button
            onClick={handleExportJson}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold rounded-lg text-xs transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Exporter JSON</span>
          </button>
        </div>
      </div>

      {/* KPI Stats Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
          <div className="text-slate-400 text-[11px] font-sans">Total Événements Parsés</div>
          <div className="text-lg font-bold text-slate-100 tabular-nums">{events.length}</div>
          <div className="text-[10px] text-slate-500 font-sans">Security, System, PowerShell</div>
        </div>

        <div className="p-3 bg-rose-950/40 border border-rose-800/60 rounded-lg space-y-1">
          <div className="text-rose-400 text-[11px] font-sans font-semibold">Erreurs Critiques Isolées</div>
          <div className="text-lg font-bold text-rose-400 tabular-nums">{criticalCount}</div>
          <div className="text-[10px] text-rose-300 font-sans">Attaques / Corruptions actives</div>
        </div>

        <div className="p-3 bg-amber-950/40 border border-amber-800/60 rounded-lg space-y-1">
          <div className="text-amber-400 text-[11px] font-sans font-semibold">Avertissements & Brute-force</div>
          <div className="text-lg font-bold text-amber-300 tabular-nums">{warningCount}</div>
          <div className="text-[10px] text-amber-300 font-sans">Échecs d'accès & pilotes suspects</div>
        </div>

        <div className="p-3 bg-cyan-950/40 border border-cyan-800/60 rounded-lg space-y-1">
          <div className="text-cyan-400 text-[11px] font-sans font-semibold">Menaces Isolées (Triage)</div>
          <div className="text-lg font-bold text-cyan-300 tabular-nums">{isolatedThreatsCount}</div>
          <div className="text-[10px] text-cyan-300 font-sans">Prêtes pour action corrective</div>
        </div>
      </div>

      {/* Raw Log Ingestion Box */}
      {showRawIngestion && (
        <div className="p-4 bg-slate-950 border border-cyan-800/60 rounded-lg space-y-3">
          <div className="flex items-center justify-between">
            <span className="font-bold text-cyan-300 text-xs">
              Parseur de Logs Bruts (Copier/Coller du résultat de Get-WinEvent ou wevtutil) :
            </span>
            <button
              onClick={() => setShowRawIngestion(false)}
              className="text-xs text-slate-400 hover:text-slate-200"
            >
              Fermer
            </button>
          </div>
          <textarea
            value={rawInputText}
            onChange={e => setRawInputText(e.target.value)}
            rows={4}
            placeholder="Collez ici les lignes d'EventLog (ex: 4688: Process Created powershell.exe -enc ... ou Event ID 4625 Failed login...)"
            className="w-full p-2.5 bg-black border border-slate-800 rounded text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
          />
          <div className="flex items-center justify-end gap-2">
            <button
              onClick={handleParseRawInput}
              className="px-4 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded text-xs transition-colors"
            >
              Parser & Isoler Automatiquement
            </button>
          </div>
        </div>
      )}

      {/* Search & Channel Filters */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 p-3 bg-slate-950 rounded-lg border border-slate-800">
        <div className="relative flex-1 max-w-sm">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            placeholder="Rechercher Event ID (4688, 4104), mot-clé..."
            className="w-full pl-8 pr-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Channel Filter */}
          <div className="flex items-center gap-1 bg-slate-900 p-1 rounded border border-slate-800 text-[11px]">
            <span className="text-slate-500 px-1">Canal:</span>
            {['ALL', 'Security', 'PowerShell', 'Defender', 'System'].map(ch => (
              <button
                key={ch}
                onClick={() => setChannelFilter(ch)}
                className={`px-2 py-0.5 rounded transition-colors ${
                  channelFilter === ch
                    ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-800/60'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {ch}
              </button>
            ))}
          </div>

          {/* Level Filter */}
          <div className="flex items-center gap-1 bg-slate-900 p-1 rounded border border-slate-800 text-[11px]">
            <span className="text-slate-500 px-1">Niveau:</span>
            {['ALL', 'CRITICAL', 'WARNING', 'INFORMATION'].map(lvl => (
              <button
                key={lvl}
                onClick={() => setLevelFilter(lvl)}
                className={`px-2 py-0.5 rounded transition-colors ${
                  levelFilter === lvl
                    ? 'bg-rose-950 text-rose-300 font-bold border border-rose-800/60'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {lvl === 'ALL' ? 'Tous' : lvl}
              </button>
            ))}
          </div>

          <label className="flex items-center gap-1.5 text-xs text-rose-300 cursor-pointer select-none ml-2">
            <input
              type="checkbox"
              checked={isolatedOnly}
              onChange={e => setIsolatedOnly(e.target.checked)}
              className="rounded bg-slate-900 border-slate-700 text-rose-500 focus:ring-0"
            />
            <span className="font-semibold">Isoler Menaces Uniquement</span>
          </label>
        </div>
      </div>

      {/* Events Table */}
      <div className="border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto max-h-[380px] scrollbar-thin">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 sticky top-0 z-10">
              <tr>
                <th className="py-2.5 px-3 font-semibold">Event ID</th>
                <th className="py-2.5 px-3 font-semibold">Niveau</th>
                <th className="py-2.5 px-3 font-semibold">Canal / Horodatage</th>
                <th className="py-2.5 px-3 font-semibold">Description & Contexte de Sécurité</th>
                <th className="py-2.5 px-3 font-semibold">MITRE ATT&CK</th>
                <th className="py-2.5 px-3 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
              {filteredEvents.map(evt => {
                const isCrit = evt.level === 'CRITICAL';
                const isWarn = evt.level === 'WARNING';

                return (
                  <tr
                    key={evt.id}
                    onClick={() => setSelectedEvent(evt)}
                    className={`cursor-pointer transition-colors ${
                      isCrit
                        ? 'bg-rose-950/20 hover:bg-rose-950/30'
                        : isWarn
                        ? 'bg-amber-950/15 hover:bg-amber-950/25'
                        : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <td className="py-2 px-3 tabular-nums font-bold">
                      <span className={isCrit ? 'text-rose-400' : isWarn ? 'text-amber-400' : 'text-slate-300'}>
                        {evt.eventId}
                      </span>
                    </td>
                    <td className="py-2 px-3">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          isCrit
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : isWarn
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {evt.level}
                      </span>
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap text-slate-400 text-[11px]">
                      <div className="font-semibold text-slate-300">{evt.channel}</div>
                      <div className="text-slate-500">{evt.timeCreated}</div>
                    </td>
                    <td className="py-2 px-3 max-w-md">
                      <div className="text-slate-200 line-clamp-2 leading-relaxed">
                        {evt.description}
                      </div>
                      {evt.user && (
                        <div className="text-[10px] text-slate-500 mt-0.5">
                          Compte : <span className="text-slate-400">{evt.user}</span>
                        </div>
                      )}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap text-[11px]">
                      {evt.mitreTactic ? (
                        <span className="text-cyan-400 font-semibold">{evt.mitreTactic}</span>
                      ) : (
                        <span className="text-slate-500">-</span>
                      )}
                    </td>
                    <td className="py-2 px-3 text-right whitespace-nowrap">
                      {isCrit || isWarn ? (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            if (evt.eventId === 4688 || evt.eventId === 4104) {
                              onRunInConsole('kill 5824');
                            } else if (evt.eventId === 1116) {
                              onRunInConsole('unlock C:\\Windows\\System32\\drivers\\suspicious_kernel_hook.sys');
                            } else if (evt.eventId === 4625) {
                              onRunInConsole('netsh advfirewall firewall add rule name="Block-C2-185.220" dir=in action=block remoteip=185.220.101.4');
                            } else {
                              onRunInConsole(`inspect-event ${evt.eventId}`);
                            }
                          }}
                          className="px-2.5 py-1 bg-rose-600 hover:bg-rose-500 text-white font-semibold rounded text-[11px] transition-colors"
                        >
                          Isoler & Bloquer
                        </button>
                      ) : (
                        <span className="text-slate-500 text-[11px]">Audit OK</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Event Payload Drawer */}
      {selectedEvent && (
        <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-3">
          <div className="flex items-center justify-between border-b border-slate-900 pb-2">
            <div className="flex items-center gap-2">
              <Info className="w-4 h-4 text-cyan-400" />
              <span className="font-bold text-white text-xs">
                Payload Brut Event ID {selectedEvent.eventId} ({selectedEvent.channel})
              </span>
              <span className="text-slate-500 text-[11px]">· Source: {selectedEvent.source}</span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => handleCopyRaw(selectedEvent.rawPayload || selectedEvent.description, selectedEvent.id)}
                className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300"
              >
                {copiedId === selectedEvent.id ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedId === selectedEvent.id ? 'Copié !' : 'Copier Payload'}</span>
              </button>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-xs text-slate-400 hover:text-slate-200 ml-2"
              >
                Fermer
              </button>
            </div>
          </div>

          <pre className="p-3 bg-black border border-slate-800 rounded text-slate-300 text-[11px] font-mono overflow-x-auto max-h-36 scrollbar-thin whitespace-pre-wrap">
            {selectedEvent.rawPayload || selectedEvent.description}
          </pre>
        </div>
      )}
    </div>
  );
};
