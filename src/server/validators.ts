import { z } from 'zod';
import { Request, Response, NextFunction } from 'express';

// Zod schemas for system, malware, threat, settings operations
export const killProcessSchema = z.object({
  pid: z.coerce.number().int().positive({ message: 'Le PID doit être un entier positif' }),
});

export const quarantineActionSchema = z.object({
  targetPath: z.string().min(1, 'Le chemin cible est requis').max(1024),
  reason: z.string().max(500).optional(),
});

export const threatStatusUpdateSchema = z.object({
  threatId: z.string().min(1, 'Identifiant de menace requis').max(128),
  status: z.enum(['ACTIVE', 'NEUTRALIZED', 'DISMISSED'], {
    message: 'Statut invalide (ACTIVE, NEUTRALIZED, DISMISSED acceptés)',
  }),
  targetPath: z.string().max(1024).optional(),
});

export const bulkThreatStatusSchema = z.object({
  threatIds: z.array(z.string().min(1).max(128)).min(1, 'Au moins un identifiant requis').max(200),
  status: z.enum(['ACTIVE', 'NEUTRALIZED', 'DISMISSED']),
  command: z.string().max(500).optional(),
});

export const dismissThreatsSchema = z.object({
  threatIds: z.array(z.string().min(1).max(128)).min(1).max(200),
});

export const ipTargetSchema = z.object({
  ip: z.string().max(100).optional(),
});

export const blockIpSchema = z.object({
  ip: z.string().min(1, 'Adresse IP requise').max(100),
  reason: z.string().max(256).optional(),
});

export const blockWifiSchema = z.object({
  bssid: z.string().min(1, 'BSSID requis').max(50),
  reason: z.string().max(256).optional(),
});

export const executeCommandSchema = z.object({
  command: z.string().min(1, 'Commande requise').max(1000),
});

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
