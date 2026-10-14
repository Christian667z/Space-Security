import { dbManager } from './db.ts';
import { logger } from './logger.ts';

export interface ThreatIntelResult {
  target: string;
  targetType: 'IP' | 'HASH';
  source: 'VIRUSTOTAL_API' | 'MALWAREBAZAAR_API' | 'ABUSEIPDB_API' | 'LOCAL_RFC1918' | 'CACHED' | 'UNAVAILABLE';
  reputationScore: number; // 0 to 100 (0 = clean, 100 = critical threat)
  verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  detectionRatio?: string; // e.g. "45/72"
  positiveEngines?: number;
  totalEngines?: number;
  lastAnalysisDate?: string;
  categories?: string[];
  externalUrl: string;
  rawDetails?: any;
  reason?: string;
}

/**
 * Real Hash Reputation Lookup:
 * 1. Local SQLite cache
 * 2. VirusTotal API v3 (if VIRUSTOTAL_API_KEY configured)
 * 3. MalwareBazaar API (https://mb-api.abuse.ch/api/v1/ - public free malware database)
 * 4. Otherwise returns authentic UNAVAILABLE without fabricating detections
 */
export async function checkHashReputation(hash: string): Promise<ThreatIntelResult> {
  const cleanHash = hash.trim().toLowerCase();

  // 1. Check local SQLite cache first
  const cached = dbManager.getIntelCache(cleanHash);
  if (cached) {
    return { ...cached, source: 'CACHED' };
  }

  const settings = dbManager.getAllSettings();
  const vtApiKey = process.env.VIRUSTOTAL_API_KEY || settings.virusTotalApiKey;

  // 2. Query VirusTotal API v3 if API key available
  if (vtApiKey && vtApiKey.trim().length > 10) {
    try {
      const response = await fetch(`https://www.virustotal.com/api/v3/files/${cleanHash}`, {
        headers: { 'x-apikey': vtApiKey.trim() },
      });

      if (response.ok) {
        const data = await response.json();
        const stats = data?.data?.attributes?.last_analysis_stats || {};
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const harmless = stats.harmless || 0;
        const undetected = stats.undetected || 0;
        const total = malicious + suspicious + harmless + undetected || 1;

        const score = Math.min(100, Math.round(((malicious * 2 + suspicious) / total) * 100));
        const verdict = malicious >= 3 ? 'MALICIOUS' : (malicious > 0 || suspicious > 2) ? 'SUSPICIOUS' : 'CLEAN';

        const result: ThreatIntelResult = {
          target: cleanHash,
          targetType: 'HASH',
          source: 'VIRUSTOTAL_API',
          reputationScore: score,
          verdict,
          detectionRatio: `${malicious}/${total}`,
          positiveEngines: malicious,
          totalEngines: total,
          lastAnalysisDate: data?.data?.attributes?.last_analysis_date
            ? new Date(data.data.attributes.last_analysis_date * 1000).toISOString()
            : new Date().toISOString(),
          externalUrl: `https://www.virustotal.com/gui/file/${cleanHash}`,
          rawDetails: stats,
        };

        dbManager.setIntelCache(cleanHash, 'HASH', score, verdict, result);
        return result;
      }
    } catch (err) {
      logger.error({ err, hash: cleanHash }, '[ThreatIntel] VirusTotal API lookup failed');
    }
  }

  // 3. Query MalwareBazaar public API (abuse.ch) - Real-time verified malware database (free, no API key required)
  try {
    const mbRes = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ query: 'get_info', hash: cleanHash }).toString(),
    });

    if (mbRes.ok) {
      const mbData = await mbRes.json();
      if (mbData.query_status === 'ok' && Array.isArray(mbData.data) && mbData.data.length > 0) {
        const sample = mbData.data[0];
        const result: ThreatIntelResult = {
          target: cleanHash,
          targetType: 'HASH',
          source: 'MALWAREBAZAAR_API',
          reputationScore: 95,
          verdict: 'MALICIOUS',
          detectionRatio: `${sample.signature || sample.file_type || 'Malware'}` ,
          positiveEngines: 1,
          totalEngines: 1,
          lastAnalysisDate: sample.first_seen || new Date().toISOString(),
          categories: sample.tags || ['Malware'],
          externalUrl: `https://bazaar.abuse.ch/sample/${cleanHash}/`,
          rawDetails: sample,
        };
        dbManager.setIntelCache(cleanHash, 'HASH', 95, 'MALICIOUS', result);
        return result;
      } else if (mbData.query_status === 'hash_not_found') {
        const cleanResult: ThreatIntelResult = {
          target: cleanHash,
          targetType: 'HASH',
          source: 'MALWAREBAZAAR_API',
          reputationScore: 0,
          verdict: 'CLEAN',
          detectionRatio: '0/1',
          positiveEngines: 0,
          totalEngines: 1,
          externalUrl: `https://bazaar.abuse.ch/browse/`,
          reason: 'Empreinte non répertoriée dans la base de malwares MalwareBazaar.',
        };
        dbManager.setIntelCache(cleanHash, 'HASH', 0, 'CLEAN', cleanResult);
        return cleanResult;
      }
    }
  } catch (err) {
    logger.debug({ err, hash: cleanHash }, '[ThreatIntel] MalwareBazaar query error');
  }

  // 4. No verified threat intel source available
  const fallbackResult: ThreatIntelResult = {
    target: cleanHash,
    targetType: 'HASH',
    source: 'UNAVAILABLE',
    reputationScore: 0,
    verdict: 'UNKNOWN',
    externalUrl: `https://www.virustotal.com/gui/file/${cleanHash}`,
    reason: 'Aucune donnée de renseignement sur les menaces disponible (clé VirusTotal non configurée et non répertorié sur MalwareBazaar).',
  };

  return fallbackResult;
}

/**
 * Real IP Reputation Lookup:
 * 1. Local SQLite cache
 * 2. RFC 1918 Private LAN / Loopback detection
 * 3. AbuseIPDB API v2 (if ABUSEIPDB_API_KEY configured)
 * 4. VirusTotal IP v3 (if VIRUSTOTAL_API_KEY configured)
 * 5. Otherwise returns authentic UNAVAILABLE without fabricated score
 */
export async function checkIpReputation(ip: string): Promise<ThreatIntelResult> {
  const cleanIp = ip.trim();

  // 1. Check local SQLite cache
  const cached = dbManager.getIntelCache(cleanIp);
  if (cached) {
    return { ...cached, source: 'CACHED' };
  }

  // 2. Private LAN check
  const isPrivate =
    cleanIp === '127.0.0.1' ||
    cleanIp === 'localhost' ||
    cleanIp === '::1' ||
    cleanIp.startsWith('192.168.') ||
    cleanIp.startsWith('10.') ||
    (cleanIp.startsWith('172.') && parseInt(cleanIp.split('.')[1] || '0', 10) >= 16 && parseInt(cleanIp.split('.')[1] || '0', 10) <= 31);

  if (isPrivate) {
    const localResult: ThreatIntelResult = {
      target: cleanIp,
      targetType: 'IP',
      source: 'LOCAL_RFC1918',
      reputationScore: 0,
      verdict: 'CLEAN',
      detectionRatio: '0/0',
      positiveEngines: 0,
      totalEngines: 0,
      externalUrl: '',
      reason: 'Adresse IP privée locale non routable sur Internet (RFC 1918).',
    };
    dbManager.setIntelCache(cleanIp, 'IP', 0, 'CLEAN', localResult);
    return localResult;
  }

  const settings = dbManager.getAllSettings();
  const abuseApiKey = process.env.ABUSEIPDB_API_KEY || settings.abuseIpDbApiKey;
  const vtApiKey = process.env.VIRUSTOTAL_API_KEY || settings.virusTotalApiKey;

  // 3. Query AbuseIPDB v2 if key available
  if (abuseApiKey && abuseApiKey.trim().length > 10) {
    try {
      const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(cleanIp)}&maxAgeInDays=90&verbose=true`, {
        headers: {
          'Key': abuseApiKey.trim(),
          'Accept': 'application/json',
        },
      });

      if (response.ok) {
        const body = await response.json();
        const data = body?.data;
        if (data) {
          const abuseScore = data.abuseConfidenceScore || 0;
          const verdict = abuseScore >= 50 ? 'MALICIOUS' : abuseScore >= 20 ? 'SUSPICIOUS' : 'CLEAN';

          const result: ThreatIntelResult = {
            target: cleanIp,
            targetType: 'IP',
            source: 'ABUSEIPDB_API',
            reputationScore: abuseScore,
            verdict,
            detectionRatio: `${data.totalReports || 0} signalements`,
            positiveEngines: data.totalReports || 0,
            totalEngines: 100,
            lastAnalysisDate: data.lastReportedAt || new Date().toISOString(),
            externalUrl: `https://www.abuseipdb.com/check/${cleanIp}`,
            rawDetails: {
              usageType: data.usageType,
              isp: data.isp,
              domain: data.domain,
              countryCode: data.countryCode,
              totalReports: data.totalReports,
              numDistinctUsers: data.numDistinctUsers,
            },
          };

          dbManager.setIntelCache(cleanIp, 'IP', abuseScore, verdict, result);
          return result;
        }
      }
    } catch (err) {
      logger.error({ err, ip: cleanIp }, '[ThreatIntel] AbuseIPDB API lookup failed');
    }
  }

  // 4. Query VirusTotal IP v3 if key available
  if (vtApiKey && vtApiKey.trim().length > 10) {
    try {
      const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${cleanIp}`, {
        headers: { 'x-apikey': vtApiKey.trim() },
      });

      if (response.ok) {
        const data = await response.json();
        const stats = data?.data?.attributes?.last_analysis_stats || {};
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0) || 1;

        const score = Math.min(100, Math.round(((malicious * 2.5 + suspicious) / total) * 100));
        const verdict = malicious >= 2 ? 'MALICIOUS' : (malicious > 0 || suspicious > 1) ? 'SUSPICIOUS' : 'CLEAN';

        const result: ThreatIntelResult = {
          target: cleanIp,
          targetType: 'IP',
          source: 'VIRUSTOTAL_API',
          reputationScore: score,
          verdict,
          detectionRatio: `${malicious}/${total}`,
          positiveEngines: malicious,
          totalEngines: total,
          externalUrl: `https://www.virustotal.com/gui/ip-address/${cleanIp}`,
          rawDetails: stats,
        };

        dbManager.setIntelCache(cleanIp, 'IP', score, verdict, result);
        return result;
      }
    } catch (err) {
      logger.error({ err, ip: cleanIp }, '[ThreatIntel] VirusTotal IP lookup failed');
    }
  }

  // 5. No key available for IP threat intelligence
  const fallbackResult: ThreatIntelResult = {
    target: cleanIp,
    targetType: 'IP',
    source: 'UNAVAILABLE',
    reputationScore: 0,
    verdict: 'UNKNOWN',
    externalUrl: `https://www.virustotal.com/gui/ip-address/${cleanIp}`,
    reason: 'Clé d\'API AbuseIPDB ou VirusTotal requise pour la réputation IP complète.',
  };

  return fallbackResult;
}
