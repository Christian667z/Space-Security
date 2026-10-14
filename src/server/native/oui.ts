/**
 * IEEE OUI (Organizationally Unique Identifier) Vendor Resolution Table
 * Maps the first 3 octets (24 bits) of a MAC address (BSSID) to the hardware manufacturer.
 */

const OUI_TABLE: Record<string, string> = {
  // Cisco & Meraki
  '00:0C:29': 'Cisco Systems / VMware',
  '00:14:22': 'Dell / Cisco Systems',
  '00:40:96': 'Cisco Systems',
  '04:6C:9D': 'Cisco Systems',
  'E4:8D:8C': 'Cisco Systems / Meraki',
  '00:18:0A': 'Cisco Meraki',
  'AC:17:C8': 'Cisco Systems',

  // TP-Link
  '24:0A:C4': 'Espressif / TP-Link',
  '50:D4:F7': 'TP-Link Corporation',
  '60:E3:27': 'TP-Link Corporation',
  '70:4F:57': 'TP-Link Corporation',
  'B0:95:75': 'TP-Link Corporation',
  'D8:07:B6': 'TP-Link Corporation',
  'E8:48:B8': 'TP-Link Corporation',

  // Netgear
  '00:09:5B': 'Netgear Inc.',
  '00:14:6C': 'Netgear Inc.',
  '00:26:F2': 'Netgear Inc.',
  '20:4E:7F': 'Netgear Inc.',
  '28:C6:8E': 'Netgear Inc.',
  'A0:04:60': 'Netgear Inc.',

  // Ubiquiti Networks
  '04:18:D6': 'Ubiquiti Networks',
  '24:A4:3C': 'Ubiquiti Networks',
  '44:D9:E7': 'Ubiquiti Networks',
  '68:D7:9A': 'Ubiquiti Networks',
  '78:8A:20': 'Ubiquiti Networks',
  'B4:FB:E4': 'Ubiquiti Networks',
  'DC:9F:DB': 'Ubiquiti Networks',

  // Aruba / Hewlett Packard Enterprise
  '00:0B:86': 'Aruba Networks (HPE)',
  '24:DE:C6': 'Aruba Networks (HPE)',
  '94:B4:0F': 'Aruba Networks (HPE)',
  'AC:A3:1E': 'Aruba Networks (HPE)',

  // Apple
  '00:17:F2': 'Apple Inc.',
  '00:1C:B3': 'Apple Inc.',
  '28:CF:E9': 'Apple Inc.',
  '3C:07:54': 'Apple Inc.',
  '48:43:7C': 'Apple Inc.',
  '60:F8:1D': 'Apple Inc.',
  '70:3E:AC': 'Apple Inc.',
  'AC:BC:32': 'Apple Inc.',
  'F4:5C:89': 'Apple Inc.',

  // Intel
  '00:1B:77': 'Intel Corporate',
  '00:21:6A': 'Intel Corporate',
  '34:13:E8': 'Intel Corporate',
  '48:51:B7': 'Intel Corporate',
  '80:86:F2': 'Intel Corporate',

  // Espressif (IoT, ESP32, ESP8266)
  '24:62:AB': 'Espressif Systems',
  '30:AE:A4': 'Espressif Systems',
  '84:0D:8E': 'Espressif Systems',
  'A4:CF:12': 'Espressif Systems',
  'C4:4F:33': 'Espressif Systems',

  // Huawei
  '00:1E:10': 'Huawei Technologies',
  '08:19:A6': 'Huawei Technologies',
  '20:08:89': 'Huawei Technologies',
  '48:7B:6B': 'Huawei Technologies',
  '70:54:F5': 'Huawei Technologies',

  // AVM (FRITZ!Box)
  '00:04:0E': 'AVM Audiovisuelles Marketing (FRITZ!Box)',
  '34:31:C4': 'AVM Audiovisuelles Marketing (FRITZ!Box)',
  '38:10:D5': 'AVM Audiovisuelles Marketing (FRITZ!Box)',
  'C8:0E:14': 'AVM Audiovisuelles Marketing (FRITZ!Box)',

  // Technicolor / Sagemcom (Orange Livebox, SFR Box, Freebox, Bouygues)
  '00:1D:CE': 'Freebox SAS',
  '14:0C:76': 'Freebox SAS',
  '34:27:92': 'Freebox SAS',
  '70:FC:8F': 'Freebox SAS',
  '00:19:70': 'Sagemcom Broadband',
  '30:7C:5E': 'Sagemcom Broadband',
  'E4:5D:51': 'Sagemcom Broadband',
  '00:14:7F': 'Technicolor Connected Home',
  '48:8D:36': 'Technicolor Connected Home',

  // MikroTik
  '00:0C:42': 'MikroTik',
  '48:8F:5A': 'MikroTik',
  '64:D1:54': 'MikroTik',
  'CC:2D:E0': 'MikroTik',

  // D-Link
  '00:17:9A': 'D-Link Corporation',
  '14:D6:4D': 'D-Link Corporation',
  '28:10:7B': 'D-Link Corporation',

  // Asus
  '04:D9:F5': 'ASUSTeK Computer',
  '08:60:6E': 'ASUSTeK Computer',
  'AC:9E:17': 'ASUSTeK Computer',
};

/**
 * Resolves the hardware vendor name for a given BSSID / MAC address.
 */
export function getVendorFromMac(macAddress?: string): string {
  if (!macAddress) return 'Inconnu';
  const clean = macAddress.replace(/[-]/g, ':').toUpperCase();
  const prefix = clean.slice(0, 8); // e.g. "00:0C:29"

  if (OUI_TABLE[prefix]) {
    return OUI_TABLE[prefix];
  }

  // Check 2-octet fallback or broadcast/multicast
  if (clean.startsWith('FF:FF:FF')) return 'Diffusion Générale (Broadcast)';
  if (clean.startsWith('01:00:5E') || clean.startsWith('33:33:')) return 'Multicast Réseau';

  return 'Borne Détectée (OUI Non Référencé)';
}
