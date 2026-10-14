# Guide de Signature de Code Authenticode & Réputation SmartScreen

Ce document détaille la stratégie et la configuration requise pour distribuer les binaires exécutables Windows (`.exe`, NSIS et Portable) de **Space Security CyberDefense Suite** sans déclencher d'alertes bloquantes Windows Defender SmartScreen (« Éditeur Inconnu ») ni de faux positifs antiviraux.

---

## 1. Pourquoi la signature Authenticode est cruciale pour Space Security

Space Security interagit avec le noyau et les composants sensibles du système Windows :
- Neutralisation forcée de processus malveillants (`taskkill /F /T`, `NtSuspendProcess`)
- Dépossession de permissions TrustedInstaller (`takeown.exe /A`, `icacls.exe`)
- Reconfiguration d'exclusions Windows Defender frauduleuses (`Set-MpPreference`)
- Verrouillage du pare-feu (`New-NetFirewallRule`) et coupure des interfaces réseau (Kill-Switch)

**Sans signature numérique Authenticode :**
1. **Windows SmartScreen** affiche un écran bleu bloquant « Windows a protégé votre ordinateur - Éditeur inconnu ».
2. **Microsoft Defender Antivirus** applique des heuristiques de détection comportementale agressives (ex: *Trojan:Win32/Wacatac*, *Behavior:Win32/ProcessTerminator.A*).
3. Les analystes SOC et RSSI refusent d'exécuter un outil de sécurité non signé sur leur parc informatique.

---

## 2. Solutions de Signature de Code Recommandées

### Option A : Microsoft Azure Trusted Signing (Recommandé en 2026)
*Remplacement officiel moderne des tokens USB matériels proposé par Microsoft.*

- **Coût** : ~9.99 $/mois par profil de signature.
- **Avantages** :
  - Identité vérifiée directement par Microsoft.
  - Attribution immédiate d'une réputation de confiance SmartScreen.
  - Aucun dongle USB physique : signature 100% cloud intégrée dans GitHub Actions.
  - Conforme aux exigences FIPS 140-2 / Microsoft Identity Verification.
- **Intégration** :
  Notre hook `scripts/sign-windows.cjs` détecte automatiquement `AZURE_TENANT_ID`, `AZURE_ACCOUNT` et `AZURE_CERT_PROFILE`.

### Option B : Certificat Commercial EV (Extended Validation)
- Fournisseurs certifiés : DigiCert, Sectigo, GlobalSign.
- Clé privée stockée sur module cryptographique matériel (HSM / Token YubiKey/SafeNet).
- Réputation SmartScreen instantanée dès la première version signée.

### Option C : Certificat de Développeur Local (Auto-signé)
Pour tester le pipeline de build et l'intégrité Authenticode en environnement de développement :
```bash
npm run cert:generate
```
Génère `certs/developer-cert.pfx` avec l'extension `Code Signing` (`1.3.6.1.5.5.7.3.3`) et algorithme SHA-256.

---

## 3. Configuration dans `electron-builder.json`

Notre fichier `electron-builder.json` applique les standards de sécurité Microsoft :

```json
{
  "win": {
    "publisherName": "Space Security Cybersecurity Labs",
    "requestedExecutionLevel": "requireAdministrator",
    "verifyUpdateCodeSignature": true,
    "signingHashAlgorithms": ["sha256"],
    "rfc3161TimeStampServer": "http://timestamp.digicert.com",
    "signAndEditExecutable": true,
    "legalTrademarks": "Space Security™",
    "sign": "scripts/sign-windows.cjs"
  }
}
```

- **`signingHashAlgorithms: ["sha256"]`** : Bannit SHA-1 (obsolète et rejeté par Windows 11).
- **`rfc3161TimeStampServer: "http://timestamp.digicert.com"`** : Garantit que la signature reste valide indéfiniment, même après expiration du certificat de signature.
- **`requestedExecutionLevel: "requireAdministrator"`** : Déclare formellement le manifeste UAC administrateur dans les ressources PE.

---

## 4. Configuration des Variables d'Environnement en CI (GitHub Actions)

Pour packager et signer automatiquement dans le workflow `.github/workflows/ci.yml`, définissez les Secrets de dépôt suivants :

| Variable Secret | Description |
|---|---|
| `WIN_CSC_LINK` | Contenu encodé en base64 de votre certificat PFX (`base64 -w 0 mon-certificat.pfx`) ou URL sécurisée HTTPS. |
| `WIN_CSC_KEY_PASSWORD` | Mot de passe de déchiffrement de la clé privée PFX. |

---

## 5. Prévention des Faux Positifs Microsoft Defender (Whitelisting & Reputation)

Même avec un certificat valide, un outil de sécurité fraîchement compilé doit établir sa réputation initiale. Suivez ce protocole avant chaque release publique :

1. **Soumission de Fichier à Microsoft Defender Security Intelligence :**
   - URL : `https://www.microsoft.com/en-us/wdsi/filesubmission`
   - Sélectionnez « Software Developer » et téléversez votre binaire `.exe` signé.
   - Catégorie : « Incorrectly detected as malware/threat (False Positive) ».
   - Ajoutez la description : « Space Security is an administrative cybersecurity and incident response utility. Actions on taskkill, firewall, and registry are intended security remediation procedures. »
   - Microsoft analyse le fichier par sandbox et publie une mise à jour des définitions Defender sous 1 à 4 heures, éliminant tout blocage SmartScreen.

2. **Vérification VirusTotal :**
   - Téléversez le binaire sur `https://www.virustotal.com`.
   - Contactez les éditeurs signalant un faux positif générique (ex: `Generic.Malware`, `Heur.Suspicious`).
