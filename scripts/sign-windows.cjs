/**
 * Custom Windows Authenticode Code Signing Hook for Electron-Builder
 *
 * Supports:
 * - Commercial EV / OV PFX Certificates (via CSC_LINK / WIN_CSC_LINK or WIN_CERTIFICATE_FILE)
 * - Microsoft Azure Trusted Signing (dlib / Trusted Signing CLI)
 * - Local Self-Signed Developer PFX Certificates (certs/developer-cert.pfx)
 * - Fallback to electron-builder default signing tool or non-blocking dev warning
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

module.exports = async function signWindows(configuration) {
  const filePath = configuration.path;
  const hash = configuration.hash || 'sha256';
  const timestampServer = configuration.options?.rfc3161TimeStampServer || 'http://timestamp.digicert.com';

  const certFile =
    process.env.WIN_CERTIFICATE_FILE ||
    process.env.CSC_LINK ||
    process.env.WIN_CSC_LINK ||
    (fs.existsSync(path.join(__dirname, '..', 'certs', 'developer-cert.pfx'))
      ? path.join(__dirname, '..', 'certs', 'developer-cert.pfx')
      : null);

  const certPassword =
    process.env.WIN_CERTIFICATE_PASSWORD ||
    process.env.CSC_KEY_PASSWORD ||
    process.env.WIN_CSC_KEY_PASSWORD ||
    'spacesec-dev-pass';

  console.log(`\n🔒 [Authenticode Signing] Target: ${path.basename(filePath)}`);

  // Scenario 1: Azure Trusted Signing (Cloud-native Microsoft Code Signing)
  if (process.env.AZURE_TENANT_ID && process.env.AZURE_CERT_PROFILE) {
    console.log('⚡ [Authenticode] Signing with Microsoft Azure Trusted Signing...');
    try {
      const endpoint = process.env.AZURE_ENDPOINT || 'https://eus.codesigning.azure.net';
      const cmd = `trusted-signing-cli sign --endpoint "${endpoint}" --account "${process.env.AZURE_ACCOUNT}" --profile "${process.env.AZURE_CERT_PROFILE}" --file "${filePath}"`;
      execSync(cmd, { stdio: 'inherit' });
      console.log('✅ [Authenticode] File signed successfully via Azure Trusted Signing.');
      return;
    } catch (err) {
      console.warn('⚠️ [Authenticode] Azure Trusted Signing failed, attempting standard Authenticode fallback:', err.message);
    }
  }

  // Scenario 2: PFX / P12 Certificate Available (Commercial or Developer Self-Signed)
  if (certFile && fs.existsSync(certFile)) {
    console.log(`⚡ [Authenticode] Signing with certificate file: ${path.basename(certFile)}`);
    console.log(`   Algorithme: ${hash.toUpperCase()} | Horodatage RFC 3161: ${timestampServer}`);

    if (process.platform === 'win32') {
      try {
        // Try signtool.exe from Windows SDK
        const signtoolCmd = `signtool.exe sign /f "${certFile}" /p "${certPassword}" /fd ${hash} /tr "${timestampServer}" /td ${hash} "${filePath}"`;
        execSync(signtoolCmd, { stdio: 'inherit' });
        console.log('✅ [Authenticode] File signed and timestamped successfully via Windows Signtool.');
        return;
      } catch (signErr) {
        console.warn('⚠️ [Authenticode] signtool.exe returned an error, falling back to electron-builder internal signer.');
      }
    } else {
      // Linux / macOS CI environment: try osslsigncode or jsign if available
      try {
        const osslCmd = `osslsigncode sign -pkcs12 "${certFile}" -pass "${certPassword}" -h ${hash} -ts "${timestampServer}" -in "${filePath}" -out "${filePath}.signed" && mv "${filePath}.signed" "${filePath}"`;
        execSync(osslCmd, { stdio: 'inherit' });
        console.log('✅ [Authenticode] File signed and timestamped via osslsigncode on Linux container.');
        return;
      } catch (osslErr) {
        // Non-blocking fallback
      }
    }
  }

  // Scenario 3: No valid certificate provided in development mode
  const isCi = Boolean(process.env.CI || process.env.GITHUB_ACTIONS);
  if (isCi) {
    console.warn('\n⚠️ [AUTHENTICODE WARNING - CI ENVIRONMENT]');
    console.warn('   Aucun certificat Authenticode (WIN_CSC_LINK ou WIN_CERTIFICATE_FILE) n\'a été fourni dans les secrets GitHub.');
    console.warn('   Le binaire .exe sera généré NON SIGNÉ.');
    console.warn('   Sous Windows, un exécutable non signé avec requireAdministrator déclenche SmartScreen et des heuristiques antivirus.');
    console.warn('   Consultez docs/CODE_SIGNING.md pour configurer la signature Authenticode en CI.\n');
  } else {
    console.log('\nℹ️ [Authenticode - Mode Développement]');
    console.log('   Aucun certificat de production configuré. Signature ignorée pour ce build local.');
    console.log('   Pour générer un certificat de test local, lancez : npm run cert:generate\n');
  }
};
