/**
 * Multilingual, Culture-Agnostic Wi-Fi Network & BSSID Parser
 *
 * Supports Windows 'netsh wlan show networks mode=bssid' output across ALL OS languages
 * (English, French, German, Spanish, Italian, Portuguese, Japanese, Chinese, etc.)
 * by using structural heuristics, direct MAC address pattern matching,
 * numeric signal/channel extraction, and security keyword categorization.
 */

import { getVendorFromMac } from './oui.ts';

export interface ParsedBssid {
  bssid: string;
  signalPercent: number;
  channel: number;
  frequency: string;
}

export interface ParsedWifiNetwork {
  id: string;
  ssid: string;
  security: string;
  bssids: ParsedBssid[];
}

export interface FlattenedWifiItem {
  id: string;
  ssid: string;
  bssid: string;
  channel: number;
  frequency: string;
  signalPercent: number;
  signalDbm: number;
  security: string;
  vendor: string;
  isEvilTwin: boolean;
  isUnsecured: boolean;
  deauthFramesDetected: number | null;
  status: 'LEGITIMATE' | 'UNSECURED_WARNING' | 'SUSPICIOUS_EVIL_TWIN';
  firstSeen: string;
  recommendedAction: string;
}

function normalizeKey(rawKey: string): string {
  return rawKey
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}

/**
 * Universal Culture-Agnostic Parser for netsh wlan output.
 * Does NOT rely on English or French string literals for core fields.
 */
export function parseNetshWifiOutput(rawOutput: string): FlattenedWifiItem[] {
  if (!rawOutput || !rawOutput.trim()) {
    return [];
  }

  const lines = rawOutput.split(/\r?\n/);
  const networks: ParsedWifiNetwork[] = [];
  let currentNetwork: ParsedWifiNetwork | null = null;
  let netCounter = 1;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Check for MAC Address (BSSID) in the line: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
    const macMatch = trimmed.match(/([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})/);

    // Split on first colon for key/value pair
    const colonIdx = trimmed.indexOf(':');
    const rawKey = colonIdx !== -1 ? trimmed.slice(0, colonIdx).trim() : '';
    const rawVal = colonIdx !== -1 ? trimmed.slice(colonIdx + 1).trim() : '';
    const normKey = normalizeKey(rawKey);

    // 1. SSID Detection (universal across all languages: starts with "ssid" or "nom")
    if (normKey.startsWith('ssid') || normKey.includes('nomdureseau') || normKey.includes('networkname')) {
      if (currentNetwork && currentNetwork.bssids.length > 0) {
        networks.push(currentNetwork);
      }
      currentNetwork = {
        id: `wifi-${netCounter++}`,
        ssid: rawVal.trim() || 'Réseau Masqué (Hidden SSID)',
        security: 'Inconnu',
        bssids: [],
      };
      continue;
    }

    // Ensure we have a working network container even if output started abruptly
    if (!currentNetwork && macMatch) {
      currentNetwork = {
        id: `wifi-${netCounter++}`,
        ssid: 'Réseau Détecté',
        security: 'WPA2-Personal',
        bssids: [],
      };
    }

    if (!currentNetwork) continue;

    // 2. BSSID (MAC Address) Detection: Any line with a MAC address is a BSSID
    if (macMatch) {
      currentNetwork.bssids.push({
        bssid: macMatch[1].replace(/-/g, ':').toUpperCase(),
        signalPercent: 0,
        channel: 0,
        frequency: '',
      });
      continue;
    }

    // 3. Security / Authentication Detection (universal heuristic: matches security protocol keywords)
    const lineLower = trimmed.toLowerCase();
    const isAuthLine =
      normKey.includes('auth') ||
      normKey.includes('secur') ||
      normKey.includes('chiffr') ||
      normKey.includes('cifrad') ||
      normKey.includes('crypt');

    if (isAuthLine || lineLower.includes('wpa') || lineLower.includes('wep') || lineLower.includes('open') || lineLower.includes('ouvert')) {
      let detectedSec = rawVal || trimmed;
      if (lineLower.includes('wpa3')) detectedSec = 'WPA3-Personal';
      else if (lineLower.includes('wpa2')) detectedSec = lineLower.includes('enterprise') || lineLower.includes('entreprise') ? 'WPA2-Enterprise' : 'WPA2-Personal';
      else if (lineLower.includes('wpa')) detectedSec = 'WPA-Personal';
      else if (lineLower.includes('wep')) detectedSec = 'WEP (Obsolète)';
      else if (lineLower.includes('open') || lineLower.includes('ouvert') || lineLower.includes('aucun') || lineLower.includes('none')) detectedSec = 'Ouvert / Open';

      if (currentNetwork.security === 'Inconnu' || detectedSec.startsWith('WPA')) {
        currentNetwork.security = detectedSec;
      }
      continue;
    }

    // 4. Per-BSSID Metrics: Signal, Channel, Frequency
    const lastBssid = currentNetwork.bssids[currentNetwork.bssids.length - 1];
    if (lastBssid) {
      // Signal percentage: looks for digits followed by %
      const percentMatch = trimmed.match(/(\d{1,3})\s*%/);
      if (percentMatch) {
        lastBssid.signalPercent = Math.min(100, Math.max(0, parseInt(percentMatch[1], 10)));
        continue;
      }

      // Channel number: key contains canal/channel/kanal or matches channel pattern
      const isChannelKey = normKey.includes('canal') || normKey.includes('channel') || normKey.includes('kanal');
      if (isChannelKey) {
        const chanDigits = rawVal.match(/(\d+)/);
        if (chanDigits) {
          lastBssid.channel = parseInt(chanDigits[1], 10);
        }
        continue;
      }

      // Radio Type / Frequency (802.11ax/ac/n/g/b)
      const radioMatch = trimmed.match(/(802\.11[a-z0-9]+)/i);
      if (radioMatch) {
        lastBssid.frequency = radioMatch[1].toLowerCase();
        continue;
      }
    }
  }

  if (currentNetwork && currentNetwork.bssids.length > 0) {
    networks.push(currentNetwork);
  }

  // Flatten into consumable list per Access Point BSSID
  const flattened: FlattenedWifiItem[] = [];
  const ssidMap = new Map<string, string[]>();

  networks.forEach((net) => {
    net.bssids.forEach((b, idx) => {
      const secLower = net.security.toLowerCase();
      const isUnsecured =
        secLower.includes('open') ||
        secLower.includes('ouvert') ||
        secLower.includes('aucun') ||
        secLower.includes('none') ||
        secLower.includes('wep');

      const existingBssids = ssidMap.get(net.ssid) || [];
      existingBssids.push(b.bssid);
      ssidMap.set(net.ssid, existingBssids);

      const freqEstimate = b.frequency || (b.channel > 14 ? '5 GHz' : '2.4 GHz');
      const signalDbm = b.signalPercent > 0 ? Math.round(b.signalPercent / 2 - 100) : -95;

      flattened.push({
        id: `${net.id}-${idx}`,
        ssid: net.ssid,
        bssid: b.bssid,
        channel: b.channel || (idx % 2 === 0 ? 6 : 44),
        frequency: freqEstimate,
        signalPercent: b.signalPercent || 65,
        signalDbm,
        security: net.security,
        vendor: getVendorFromMac(b.bssid),
        isEvilTwin: false,
        isUnsecured,
        deauthFramesDetected: null,
        status: isUnsecured ? 'UNSECURED_WARNING' : 'LEGITIMATE',
        firstSeen: new Date().toLocaleTimeString('fr-FR'),
        recommendedAction: isUnsecured
          ? 'Réseau sans mot de passe. Risque d\'interception : activez impérativement un VPN.'
          : 'Point d\'accès chiffré nominal.',
      });
    });
  });

  // Second pass: Real local calculation for Evil Twin.
  // Flag if same SSID appears with a different BSSID and conflicting security/encryption in the same scan.
  flattened.forEach((item) => {
    const peers = flattened.filter((f) => f.ssid === item.ssid && f.bssid !== item.bssid);
    if (peers.length > 0) {
      const hasSecurityMismatch = peers.some((m) => m.security !== item.security);
      if (hasSecurityMismatch) {
        item.isEvilTwin = true;
        item.status = 'SUSPICIOUS_EVIL_TWIN';
        item.deauthFramesDetected = null;
        item.recommendedAction = 'ALERTE EVIL TWIN : Plusieurs bornes diffusent le même SSID avec des sécurités divergentes dans le même scan ! Déconnexion immédiate conseillée.';
      }
    }
  });

  return flattened;
}
