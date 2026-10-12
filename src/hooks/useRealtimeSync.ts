import { useState, useEffect, useRef, useCallback } from 'react';
import { ThreatItem, ConsoleLogMessage, OperatorSession, ThreatNotification } from '../types/cyberdefense';

interface UseRealtimeSyncProps {
  onNotification?: (notification: Omit<ThreatNotification, 'id' | 'timestamp'>) => void;
  onSystemLog?: (level: ConsoleLogMessage['level'], text: string, tag?: string) => void;
}

export function useRealtimeSync({ onNotification, onSystemLog }: UseRealtimeSyncProps = {}) {
  const [threats, setThreats] = useState<ThreatItem[]>([]);
  const [logs, setLogs] = useState<ConsoleLogMessage[]>([]);
  const [blockedIps, setBlockedIps] = useState<string[]>([]);
  const [blockedWifiBssids, setBlockedWifiBssids] = useState<string[]>([]);
  const [activeUsersCount, setActiveUsersCount] = useState<number>(1);
  const [activeOperators, setActiveOperators] = useState<OperatorSession[]>([]);
  const [currentOperator, setCurrentOperator] = useState<OperatorSession | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'connecting' | 'disconnected'>('connecting');
  const [lastSyncTime, setLastSyncTime] = useState<string>('');

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<any>(null);
  const isMountedRef = useRef<boolean>(true);
  const initialFetchDoneRef = useRef<boolean>(false);

  // Fallback REST fetch to ensure fast first render
  const fetchInitialState = useCallback(async () => {
    try {
      const res = await fetch('/api/shared/state');
      if (res.ok) {
        const data = await res.json();
        if (data.success && data.state) {
          if (Array.isArray(data.state.threats) && data.state.threats.length > 0) {
            setThreats(data.state.threats);
          }
          if (Array.isArray(data.state.logs) && data.state.logs.length > 0) {
            setLogs(data.state.logs);
          }
          if (Array.isArray(data.state.blockedIps)) {
            setBlockedIps(data.state.blockedIps);
          }
          if (Array.isArray(data.state.blockedWifiBssids)) {
            setBlockedWifiBssids(data.state.blockedWifiBssids);
          }
          if (typeof data.state.activeUsersCount === 'number') {
            setActiveUsersCount(Math.max(1, data.state.activeUsersCount));
          }
          if (Array.isArray(data.state.activeOperators)) {
            setActiveOperators(data.state.activeOperators);
          }
          setLastSyncTime(new Date().toLocaleTimeString('fr-FR'));
          initialFetchDoneRef.current = true;
        }
      }
    } catch (err) {
      console.warn('[Sync] Fallback REST fetch error:', err);
    }
  }, []);

  // Connect WebSocket
  const connectWebSocket = useCallback(() => {
    if (!isMountedRef.current) return;

    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    setConnectionStatus('connecting');

    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!isMountedRef.current) return;
        setConnectionStatus('connected');
        setLastSyncTime(new Date().toLocaleTimeString('fr-FR'));
      };

      ws.onmessage = (event) => {
        if (!isMountedRef.current) return;
        try {
          const data = JSON.parse(event.data);

          if (data.type === 'SYNC_INIT') {
            if (data.state) {
              setThreats(data.state.threats || []);
              setLogs(data.state.logs || []);
              setBlockedIps(data.state.blockedIps || []);
              setBlockedWifiBssids(data.state.blockedWifiBssids || []);
              setActiveUsersCount(Math.max(1, data.state.activeUsersCount || 1));
              if (Array.isArray(data.state.activeOperators)) {
                setActiveOperators(data.state.activeOperators);
              }
            }
            if (data.operator) {
              setCurrentOperator(data.operator);
            }
            if (data.activeOperators) {
              setActiveOperators(data.activeOperators);
            }
            setLastSyncTime(new Date().toLocaleTimeString('fr-FR'));
          } else if (data.type === 'USER_JOINED') {
            const count = data.activeUsersCount || 1;
            setActiveUsersCount(count);
            if (data.activeOperators) {
              setActiveOperators(data.activeOperators);
            }

            const joinedOp = data.operator?.name || 'Un nouvel analyste';
            if (onNotification) {
              onNotification({
                title: 'Opérateur Connecté au Centre',
                description: `${joinedOp} a rejoint la salle d'opérations SpaceSec (Total: ${count} en ligne).`,
                severity: 'LOW',
                category: 'Collab',
                source: 'CENTRE-COLLAB',
                targetTab: 'overview',
              });
            }
            if (onSystemLog) {
              onSystemLog('INFO', `[COLLABORATION] ${joinedOp} est désormais synchronisé avec ce centre de commande (Opérateurs actifs: ${count}).`, 'COLLAB');
            }
          } else if (data.type === 'USER_LEFT') {
            const count = data.activeUsersCount || 1;
            setActiveUsersCount(count);
            if (data.activeOperators) {
              setActiveOperators(data.activeOperators);
            }
            const leftOp = data.operator?.name || 'Un opérateur';
            if (onSystemLog) {
              onSystemLog('WARN', `[COLLABORATION] ${leftOp} s'est déconnecté. Opérateurs restants : ${count}.`, 'COLLAB');
            }
          } else if (data.type === 'STATE_DELTA') {
            const { action, payload, senderOperator, state } = data;

            if (state) {
              if (state.threats) setThreats(state.threats);
              if (state.logs) setLogs(state.logs);
              if (state.blockedIps) setBlockedIps(state.blockedIps);
              if (state.blockedWifiBssids) setBlockedWifiBssids(state.blockedWifiBssids);
              if (state.activeUsersCount) setActiveUsersCount(state.activeUsersCount);
              if (state.activeOperators) setActiveOperators(state.activeOperators);
            } else if (action === 'UPDATE_THREAT_STATUS') {
              setThreats(prev =>
                prev.map(t =>
                  t.id === payload.threatId || (payload.targetPath && t.targetPath === payload.targetPath)
                    ? { ...t, status: payload.status }
                    : t
                )
              );
            } else if (action === 'BULK_UPDATE_THREAT_STATUS') {
              const idSet = new Set(Array.isArray(payload.threatIds) ? payload.threatIds : []);
              setThreats(prev =>
                prev.map(t => (idSet.has(t.id) ? { ...t, status: payload.status } : t))
              );
            } else if (action === 'DISMISS_THREATS') {
              const idSet = new Set(Array.isArray(payload.threatIds) ? payload.threatIds : []);
              setThreats(prev =>
                prev.map(t => (idSet.has(t.id) ? { ...t, status: 'DISMISSED' } : t))
              );
            } else if (action === 'RESTORE_THREATS') {
              const idSet = new Set(Array.isArray(payload.threatIds) ? payload.threatIds : []);
              setThreats(prev =>
                prev.map(t => (idSet.has(t.id) ? { ...t, status: 'ACTIVE' } : t))
              );
            } else if (action === 'ADD_LOG') {
              setLogs(prev => {
                if (prev.some(l => l.id === payload.id)) return prev;
                return [...prev.slice(-199), payload];
              });
            } else if (action === 'CLEAR_LOGS') {
              setLogs([]);
            }

            setLastSyncTime(new Date().toLocaleTimeString('fr-FR'));

            // Notify user of external operator action
            const actorName = senderOperator?.name || 'Un opérateur distant';
            if (action === 'UPDATE_THREAT_STATUS') {
              const statusLabel =
                payload.status === 'SCHEDULED_BOOT_DELETE'
                  ? 'Éradication Kernel programmée'
                  : payload.status === 'NEUTRALIZED'
                  ? 'Neutralisée'
                  : payload.status === 'DISMISSED'
                  ? 'Ignorée / Rejetée'
                  : payload.status;
              if (onNotification) {
                onNotification({
                  title: 'Action Opérateur Distante',
                  description: `${actorName} a mis à jour la menace : ${payload.targetPath || payload.threatId} (${statusLabel}).`,
                  severity: 'HIGH',
                  category: 'Collab',
                  source: 'CENTRE-COLLAB',
                  targetTab: 'overview',
                });
              }
              if (onSystemLog) {
                onSystemLog('OK', `[ACTION-DISTANTE] ${actorName} a appliqué le protocole sur ${payload.targetPath || payload.threatId} -> ${statusLabel}.`, 'COLLAB');
              }
            } else if (action === 'BULK_UPDATE_THREAT_STATUS') {
              const count = Array.isArray(payload.threatIds) ? payload.threatIds.length : 0;
              const statusLabel =
                payload.status === 'SCHEDULED_BOOT_DELETE'
                  ? 'Éradication Kernel programmée'
                  : payload.status === 'QUARANTINED'
                  ? 'Mise en quarantaine'
                  : payload.status === 'DISMISSED'
                  ? 'Ignorée / Rejetée'
                  : payload.status;
              if (onNotification) {
                onNotification({
                  title: 'Action Groupée Distante',
                  description: `${actorName} a exécuté une action groupée sur ${count} menace(s) : ${statusLabel}.`,
                  severity: 'HIGH',
                  category: 'Collab',
                  source: 'CENTRE-COLLAB',
                  targetTab: 'overview',
                });
              }
              if (onSystemLog) {
                onSystemLog('OK', `[ACTION-GROUPEE] ${actorName} a exécuté une action collective sur ${count} menace(s) -> ${statusLabel}.`, 'COLLAB');
              }
            } else if (action === 'DISMISS_THREATS') {
              const count = Array.isArray(payload.threatIds) ? payload.threatIds.length : 0;
              if (onNotification) {
                onNotification({
                  title: 'Rejet en Masse Distant',
                  description: `${actorName} a rejeté en masse ${count} menace(s).`,
                  severity: 'MEDIUM',
                  category: 'Collab',
                  source: 'CENTRE-COLLAB',
                  targetTab: 'overview',
                });
              }
              if (onSystemLog) {
                onSystemLog('WARN', `[REJET-MASSE] ${actorName} a ignoré/rejeté ${count} menace(s).`, 'COLLAB');
              }
            } else if (action === 'BLOCK_IP') {
              if (onSystemLog) {
                onSystemLog('WARN', `[ACTION-DISTANTE] ${actorName} a bloqué l'IP C2 : ${payload.ip} au niveau du pare-feu.`, 'FIREWALL');
              }
            } else if (action === 'BLOCK_WIFI_BSSID') {
              if (onSystemLog) {
                onSystemLog('WARN', `[ACTION-DISTANTE] ${actorName} a bloqué le point d'accès WiFi pirate BSSID : ${payload.bssid}.`, 'WIFI-DEFENSE');
              }
            }
          }
        } catch (err) {
          console.error('[Sync] Error parsing WS message:', err);
        }
      };

      ws.onclose = () => {
        if (!isMountedRef.current) return;
        setConnectionStatus('disconnected');
        // Auto-reconnect with 3-second delay
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = setTimeout(() => {
          connectWebSocket();
        }, 3000);
      };

      ws.onerror = () => {
        if (!isMountedRef.current) return;
        setConnectionStatus('disconnected');
        try {
          ws.close();
        } catch {}
      };
    } catch {
      setConnectionStatus('disconnected');
    }
  }, [onNotification, onSystemLog]);

  // Initial load effect
  useEffect(() => {
    isMountedRef.current = true;
    fetchInitialState();
    connectWebSocket();

    return () => {
      isMountedRef.current = false;
      clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) {
        try {
          wsRef.current.close();
        } catch {}
      }
    };
  }, [fetchInitialState, connectWebSocket]);

  // Broadcast helper
  const sendMutation = useCallback((action: string, payload: any) => {
    const message = {
      type: 'MUTATE',
      action,
      payload,
      operator: currentOperator,
    };

    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      try {
        wsRef.current.send(JSON.stringify(message));
      } catch (err) {
        console.warn('[Sync] WS send failed, fallback to REST:', err);
        // Fallback REST call
        fetch('/api/shared/mutate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action, payload, operator: currentOperator }),
        }).catch(() => {});
      }
    } else {
      // Offline/connecting fallback REST
      fetch('/api/shared/mutate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, payload, operator: currentOperator }),
      }).catch(() => {});
    }
  }, [currentOperator]);

  // Public state mutations with local optimistic update + broadcast
  const mutateThreatStatus = useCallback((threatId: string, targetPath: string, status: ThreatItem['status']) => {
    // 1. Optimistic local update
    setThreats(prev =>
      prev.map(t =>
        t.id === threatId || (targetPath && t.targetPath === targetPath)
          ? { ...t, status }
          : t
      )
    );
    // 2. Transmit to server & all other clients
    sendMutation('UPDATE_THREAT_STATUS', { threatId, targetPath, status });
  }, [sendMutation]);

  const addSharedLog = useCallback((newLog: ConsoleLogMessage) => {
    // 1. Optimistic local append
    setLogs(prev => {
      if (prev.some(l => l.id === newLog.id)) return prev;
      return [...prev.slice(-199), newLog];
    });
    // 2. Broadcast
    sendMutation('ADD_LOG', newLog);
  }, [sendMutation]);

  const clearSharedLogs = useCallback(() => {
    setLogs([]);
    sendMutation('CLEAR_LOGS', {});
  }, [sendMutation]);

  const blockIp = useCallback((ip: string) => {
    setBlockedIps(prev => (!prev.includes(ip) ? [...prev, ip] : prev));
    sendMutation('BLOCK_IP', { ip });
  }, [sendMutation]);

  const unblockIp = useCallback((ip: string) => {
    setBlockedIps(prev => prev.filter(i => i !== ip));
    sendMutation('UNBLOCK_IP', { ip });
  }, [sendMutation]);

  const blockWifiBssid = useCallback((bssid: string) => {
    setBlockedWifiBssids(prev => (!prev.includes(bssid) ? [...prev, bssid] : prev));
    sendMutation('BLOCK_WIFI_BSSID', { bssid });
  }, [sendMutation]);

  const mutateBulkThreatStatus = useCallback(
    (threatIds: string[], status: ThreatItem['status'], command?: string) => {
      const idSet = new Set(threatIds);
      // 1. Optimistic local update
      setThreats(prev =>
        prev.map(t => (idSet.has(t.id) ? { ...t, status } : t))
      );
      // 2. Transmit to server & all other clients
      sendMutation('BULK_UPDATE_THREAT_STATUS', { threatIds, status, command });
    },
    [sendMutation]
  );

  const massDismissThreats = useCallback(
    (threatIds: string[]) => {
      const idSet = new Set(threatIds);
      setThreats(prev =>
        prev.map(t => (idSet.has(t.id) ? { ...t, status: 'DISMISSED' } : t))
      );
      sendMutation('DISMISS_THREATS', { threatIds });
    },
    [sendMutation]
  );

  const restoreThreats = useCallback(
    (threatIds: string[]) => {
      const idSet = new Set(threatIds);
      setThreats(prev =>
        prev.map(t => (idSet.has(t.id) ? { ...t, status: 'ACTIVE' } : t))
      );
      sendMutation('RESTORE_THREATS', { threatIds });
    },
    [sendMutation]
  );

  return {
    threats,
    setThreats,
    logs,
    setLogs,
    blockedIps,
    blockedWifiBssids,
    activeUsersCount,
    activeOperators,
    currentOperator,
    connectionStatus,
    lastSyncTime,
    mutateThreatStatus,
    mutateBulkThreatStatus,
    massDismissThreats,
    restoreThreats,
    addSharedLog,
    clearSharedLogs,
    blockIp,
    unblockIp,
    blockWifiBssid,
    resetThreats,
    reconnect: connectWebSocket,
  };
}
