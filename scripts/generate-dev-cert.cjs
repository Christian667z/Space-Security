/**
 * Generator for local self-signed Authenticode Developer Certificate
 *
 * Generates certs/developer-cert.pfx for local signing verification.
 * Usage: npm run cert:generate
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const certDir = path.join(__dirname, '..', 'certs');
const pfxFile = path.join(certDir, 'developer-cert.pfx');
const certPassword = 'spacesec-dev-pass';

if (!fs.existsSync(certDir)) {
  fs.mkdirSync(certDir, { recursive: true });
}

console.log('🔐 [Cert Generator] Génération d\'un certificat de test Authenticode pour Space Security...');

if (process.platform === 'win32') {
  // Native Windows PowerShell generation with Code Signing EKU (1.3.6.1.5.5.7.3.3)
  try {
    const psScript = `
      $cert = New-SelfSignedCertificate -Type CodeSigningCert \
        -Subject "CN=Space Security Local Dev, O=Space Security Labs, C=FR" \
        -CertStoreLocation "Cert:\\CurrentUser\\My" \
        -HashAlgorithm "SHA256" \
        -NotAfter (Get-Date).AddYears(3);
      $pwd = ConvertTo-SecureString -String "${certPassword}" -Force -AsPlainText;
      Export-PfxCertificate -Cert $cert -FilePath "${pfxFile}" -Password $pwd | Out-Null;
    `.replace(/\n/g, ' ');

    execSync(`powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "${psScript}"`, { stdio: 'inherit' });
    console.log(`✅ Certificat PFX généré avec succès dans : ${pfxFile}`);
    console.log(`   Mot de passe : ${certPassword}`);
    console.log('   Note : Pour tester l\'absence d\'alerte SmartScreen en local, installez developer-cert.pfx dans "Autorités de certification racines de confiance".');
  } catch (err) {
    console.error('❌ Erreur lors de la génération PowerShell :', err.message);
  }
} else {
  // Linux / macOS OpenSSL generation with Code Signing EKU
  try {
    const keyFile = path.join(certDir, 'dev.key');
    const crtFile = path.join(certDir, 'dev.crt');
    const cnfFile = path.join(certDir, 'openssl.cnf');

    const cnfContent = `
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
C = FR
O = Space Security Cybersecurity Labs
CN = Space Security Local Developer

[ codesign_ext ]
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
basicConstraints = CA:FALSE
`;
    fs.writeFileSync(cnfFile, cnfContent);

    execSync(`openssl req -x509 -newkey rsa:4096 -keyout "${keyFile}" -out "${crtFile}" -days 730 -nodes -config "${cnfFile}" -extensions codesign_ext`, { stdio: 'ignore' });
    execSync(`openssl pkcs12 -export -out "${pfxFile}" -inkey "${keyFile}" -in "${crtFile}" -password pass:${certPassword}`, { stdio: 'ignore' });

    // Clean intermediate plain files
    if (fs.existsSync(keyFile)) fs.unlinkSync(keyFile);
    if (fs.existsSync(crtFile)) fs.unlinkSync(crtFile);
    if (fs.existsSync(cnfFile)) fs.unlinkSync(cnfFile);

    console.log(`✅ Certificat PFX généré avec succès dans : ${pfxFile}`);
    console.log(`   Algorithme : RSA 4096 / SHA-256 (Code Signing EKU)`);
    console.log(`   Mot de passe : ${certPassword}`);
  } catch (err) {
    console.error('❌ Erreur lors de la génération OpenSSL :', err.message);
  }
}
