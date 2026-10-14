import { z } from 'zod';
import type { Request, Response, NextFunction } from 'express';

// Zod schemas for system, malware, threat, settings operations
export const killProcessSchema = z.object({
  pid: z.coerce.number().int().positive({ message: 'Le PID doit être un entier positif' }),
});

export const quarantineActionSchema = z.object({
  targetPath: z.string().min(1, 'Le chemin cible est requis').max(1024),
  reason: z.string().max(500).optional(),
});

export const threatStatusEnum = z.enum([
  'ACTIVE',
  'QUARANTINED',
  'SCHEDULED_BOOT_DELETE',
  'NEUTRALIZED',
  'DISMISSED',
], {
  message: 'Statut de menace invalide (ACTIVE, QUARANTINED, SCHEDULED_BOOT_DELETE, NEUTRALIZED, DISMISSED acceptés)',
});
export type ThreatStatus = z.infer<typeof threatStatusEnum>;

export const threatStatusUpdateSchema = z.object({
  threatId: z.string().min(1, 'Identifiant de menace requis').max(128),
  status: threatStatusEnum,
  targetPath: z.string().max(1024).optional(),
});

export const bulkThreatStatusSchema = z.object({
  threatIds: z.array(z.string().min(1).max(128)).min(1, 'Au moins un identifiant requis').max(500),
  status: threatStatusEnum,
  command: z.string().max(500).optional(),
});

export const dismissThreatsSchema = z.object({
  threatIds: z.array(z.string().min(1).max(128)).min(1, 'Au moins un identifiant requis').max(500),
});

export const restoreThreatsSchema = z.object({
  threatIds: z.array(z.string().min(1).max(128)).min(1, 'Au moins un identifiant requis').max(500),
});

export const ipTargetSchema = z.object({
  ip: z.string().max(100).optional(),
});

export const blockIpSchema = z.object({
  ip: z.string().min(1, 'Adresse IP requise').max(100),
  reason: z.string().max(256).optional(),
});

export const unblockIpSchema = z.object({
  ip: z.string().min(1, 'Adresse IP requise').max(100),
});

export const blockWifiSchema = z.object({
  bssid: z.string().min(1, 'BSSID requis').max(50),
  reason: z.string().max(256).optional(),
});

export const addLogPayloadSchema = z.object({
  id: z.string().max(128).optional(),
  timestamp: z.string().max(64).optional(),
  level: z.enum(['OK', 'WARN', 'CRITICAL', 'INFO', 'KERNEL']),
  tag: z.string().max(64).optional(),
  text: z.string().min(1, 'Message de journal requis').max(2048),
  operatorName: z.string().max(128).optional(),
});

export const threatItemValidationSchema = z.object({
  id: z.string().min(1, 'Identifiant requis').max(128),
  name: z.string().min(1, 'Nom requis').max(256),
  category: z.enum(['Rootkit', 'Trojan', 'Persistence', 'C2', 'Privilege', 'Memory', 'Kernel', 'Network', 'Defender']),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  targetPath: z.string().max(1024),
  mitreTechnique: z.string().max(128).optional().default('T1000'),
  lockedBySystem: z.boolean().optional().default(false),
  trustedInstallerLocked: z.boolean().optional().default(false),
  status: threatStatusEnum,
  description: z.string().max(1024).optional(),
  detectedAt: z.string().max(64).optional(),
});

export const recordScannedThreatsPayloadSchema = z.object({
  threats: z.array(threatItemValidationSchema).min(1, 'Au moins une menace requise').max(500),
});

export const resetThreatsPayloadSchema = z.object({
  reason: z.string().max(256).optional(),
}).optional().default({});

export const clearLogsPayloadSchema = z.object({
  confirmClear: z.boolean().optional(),
  reason: z.string().max(256).optional(),
}).optional().default({});

export const ALLOWED_MUTATE_ACTIONS = [
  'UPDATE_THREAT_STATUS',
  'BULK_UPDATE_THREAT_STATUS',
  'DISMISS_THREATS',
  'RESTORE_THREATS',
  'BLOCK_IP',
  'UNBLOCK_IP',
  'BLOCK_WIFI_BSSID',
  'ADD_LOG',
  'ADD_THREAT',
  'RECORD_SCANNED_THREATS',
  'RESET_THREATS',
  'CLEAR_LOGS',
] as const;

export const sharedMutateActionEnum = z.enum(ALLOWED_MUTATE_ACTIONS, {
  message: `Action non autorisée. Actions acceptées : ${ALLOWED_MUTATE_ACTIONS.join(', ')}`,
});

/**
 * Strict Zod validation for /api/shared/mutate and WebSocket MUTATE messages.
 * Validates that every action is whitelisted and its associated payload matches exact requirements.
 */
export const sharedMutateSchema = z.object({
  action: sharedMutateActionEnum,
  payload: z.any({ required_error: 'Le payload est requis' }),
  operator: z.object({
    id: z.string().optional(),
    name: z.string().optional(),
    role: z.string().optional(),
  }).optional(),
}).superRefine((val, ctx) => {
  const { action, payload } = val;
  let result: { success: boolean; error?: z.ZodError };

  if (!payload || typeof payload !== 'object') {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['payload'],
      message: 'Le payload doit être un objet JSON valide.',
    });
    return;
  }

  switch (action) {
    case 'UPDATE_THREAT_STATUS':
      result = threatStatusUpdateSchema.safeParse(payload);
      break;
    case 'BULK_UPDATE_THREAT_STATUS':
      result = bulkThreatStatusSchema.safeParse(payload);
      break;
    case 'DISMISS_THREATS':
      result = dismissThreatsSchema.safeParse(payload);
      break;
    case 'RESTORE_THREATS':
      result = restoreThreatsSchema.safeParse(payload);
      break;
    case 'BLOCK_IP':
      result = blockIpSchema.safeParse(payload);
      break;
    case 'UNBLOCK_IP':
      result = unblockIpSchema.safeParse(payload);
      break;
    case 'BLOCK_WIFI_BSSID':
      result = blockWifiSchema.safeParse(payload);
      break;
    case 'ADD_LOG':
      result = addLogPayloadSchema.safeParse(payload);
      break;
    case 'ADD_THREAT':
      result = threatItemValidationSchema.safeParse(payload);
      break;
    case 'RECORD_SCANNED_THREATS':
      result = recordScannedThreatsPayloadSchema.safeParse(payload);
      break;
    case 'RESET_THREATS':
      result = resetThreatsPayloadSchema.safeParse(payload);
      break;
    case 'CLEAR_LOGS':
      result = clearLogsPayloadSchema.safeParse(payload);
      break;
    default:
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['action'],
        message: `Action non reconnue : ${action}`,
      });
      return;
  }

  if (!result.success && result.error) {
    for (const issue of result.error.issues) {
      ctx.addIssue({
        ...issue,
        path: ['payload', ...issue.path],
      });
    }
  }
});

export const executeCommandSchema = z.object({
  command: z.string().min(1, 'Commande requise').max(1000),
  operatorName: z.string().max(128).optional(),
});

export const quarantineRestoreSchema = z.object({
  id: z.string().min(1, 'Identifiant requis').max(128),
});

export const specsSyncSchema = z.object({
  hostname: z.string().max(128).optional(),
  osName: z.string().max(128).optional(),
  cpuModel: z.string().max(256).optional(),
  cores: z.coerce.number().positive().max(256).optional(),
  totalRamGb: z.coerce.number().positive().max(1024).optional(),
  manufacturer: z.string().max(128).optional(),
}).optional();

export const reportGenerateSchema = z.object({
  format: z.enum(['html', 'csv', 'json']).default('html'),
}).optional();


export const settingsUpdateSchema = z.object({
  alertThreshold: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).optional(),
  excludedFolders: z.array(z.string().max(500)).optional(),
  language: z.enum(['fr', 'en']).optional(),
  autoScanInterval: z.enum(['disabled', '5m', '15m', '30m', '1h']).optional(),
  notifyOnCritical: z.boolean().optional(),
  soundAlerts: z.boolean().optional(),
  strictNetworkKillSwitch: z.boolean().optional(),
  autoQuarantineMalware: z.boolean().optional(),
  virusTotalApiKey: z.string().max(128).optional(),
  abuseIpDbApiKey: z.string().max(128).optional(),
  theme: z.enum(['dark-cyber', 'stealth']).optional(),
}).strict();

export const threatIntelCheckSchema = z.object({
  target: z.string().min(1, 'Cible d\'analyse requise').max(256),
  type: z.enum(['ip', 'hash', 'domain']).optional(),
});

export const edrRegisterSchema = z.object({
  id: z.string().max(128).optional(),
  hostname: z.string().min(1, 'Nom d\'hôte requis').max(256),
  ipAddress: z.string().min(1, 'Adresse IP requise').max(64),
  publicIp: z.string().max(64).optional(),
  macAddress: z.string().max(64).optional(),
  osVersion: z.string().max(256).optional(),
  agentVersion: z.string().max(64).optional(),
  healthScore: z.number().min(0).max(100).optional(),
});

export const edrHeartbeatSchema = z.object({
  endpointId: z.string().min(1, 'ID endpoint requis').max(128),
  cpuUsagePercent: z.number().min(0).max(100).optional(),
  ramUsagePercent: z.number().min(0).max(100).optional(),
  activeThreatsCount: z.number().min(0).optional(),
  networkIsolated: z.boolean().optional(),
});

export const edrTelemetrySchema = z.object({
  endpointId: z.string().min(1, 'ID endpoint requis').max(128),
  hostname: z.string().min(1, 'Nom d\'hôte requis').max(256),
  events: z.array(z.object({
    category: z.enum(['PROCESS', 'REGISTRY', 'NETWORK', 'SERVICE', 'BITS', 'DEFENDER', 'ANOMALY']),
    severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
    summary: z.string().min(1).max(512),
    details: z.any().optional(),
    mitreTechnique: z.string().max(128).optional(),
  })).min(1).max(100),
});

export const edrCommandCreateSchema = z.object({
  endpointId: z.string().min(1, 'ID endpoint requis').max(128),
  type: z.enum(['KILL_PROCESS', 'ISOLATE_NETWORK', 'UNISOLATE_NETWORK', 'SCAN_DEEP', 'REPAIR_THEMES', 'RESTORE_DEFENDER', 'CUSTOM_PS']),
  payload: z.object({
    pid: z.number().optional(),
    command: z.string().max(2000).optional(),
    reason: z.string().max(500).optional(),
  }).optional(),
});

export const edrCommandAckSchema = z.object({
  status: z.enum(['EXECUTED', 'FAILED']),
  result: z.string().max(4096).optional(),
});

// Middleware generators
export function validateBody(schema: z.ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      const formattedErrors = result.error.issues.map(i => ({
        path: i.path.join('.'),
        message: i.message,
      }));
      return res.status(400).json({
        success: false,
        error: 'Validation des données échouée',
        details: formattedErrors,
      });
    }
    req.body = result.data;
    next();
  };
}

export function validateQuery(schema: z.ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.query);
    if (!result.success) {
      const formattedErrors = result.error.issues.map(i => ({
        path: i.path.join('.'),
        message: i.message,
      }));
      return res.status(400).json({
        success: false,
        error: 'Paramètres de requête invalides',
        details: formattedErrors,
      });
    }
    req.query = result.data as any;
    next();
  };
}
