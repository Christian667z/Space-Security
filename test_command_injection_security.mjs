import assert from 'node:assert';
import os from 'node:os';
import {
  safeExecFile,
  safeExecPowerShell,
  psString,
  validateAndParsePid,
  sanitizeIpAddress,
  sanitizeInterfaceName,
  sanitizePath,
  assertProcessNotProtected,
  CRITICAL_PROTECTED_PROCESS_NAMES,
  CRITICAL_PROTECTED_PIDS
} from './src/server/safeExec.ts';

async function runTests() {
  console.log('--- TEST 1: PID Validation & Sanitization ---');
  assert.strictEqual(validateAndParsePid(1234), 1234);
  assert.strictEqual(validateAndParsePid('5678'), 5678);

  const maliciousPids = [
    '1234; calc.exe',
    '1234 && whoami',
    '1234 | dir',
    '-1',
    '0',
    'abc',
    '12.34',
    '$(whoami)',
    '`calc`'
  ];

  for (const badPid of maliciousPids) {
    assert.throws(
      () => validateAndParsePid(badPid),
      /PID invalide/,
      `Expected PID validation to reject: ${badPid}`
    );
  }
  console.log('✓ PID validation strictly allows only positive integers and blocks command injection');

  console.log('\n--- TEST 2: IP Address Sanitization (net.isIP & IPv6 compression) ---');
  assert.strictEqual(sanitizeIpAddress('127.0.0.1'), '127.0.0.1');
  assert.strictEqual(sanitizeIpAddress('8.8.8.8'), '8.8.8.8');
  assert.strictEqual(sanitizeIpAddress('::1'), '::1');
  assert.strictEqual(sanitizeIpAddress('localhost'), 'localhost');
  // Compressed IPv6 formats
  assert.strictEqual(sanitizeIpAddress('fe80::1'), 'fe80::1');
  assert.strictEqual(sanitizeIpAddress('2001:db8::2:1'), '2001:db8::2:1');

  // Verify broken IPv4 regex edge case "1234" is now strictly rejected
  assert.throws(
    () => sanitizeIpAddress('1234'),
    /Format d'adresse IP invalide/,
    'Expected "1234" to be rejected as an invalid IP'
  );

  const maliciousIps = [
    '127.0.0.1; whoami',
    '127.0.0.1 && dir',
    '127.0.0.1 | calc',
    '127.0.0.1\nwhoami',
    '127.0.0.1 `calc`',
    '$(whoami)',
    '1.2.3.4.5',
    '999.999.999.999',
    '1234'
  ];

  for (const badIp of maliciousIps) {
    assert.throws(
      () => sanitizeIpAddress(badIp),
      /Format d'adresse IP invalide|Adresse IP invalide/,
      `Expected IP sanitization to reject: ${badIp}`
    );
  }
  console.log('✓ IP sanitization uses net.isIP() accepting compressed IPv6 and rejecting broken numbers like "1234"');

  console.log('\n--- TEST 3: Interface Name Sanitization ---');
  assert.strictEqual(sanitizeInterfaceName('Ethernet 2'), 'Ethernet 2');
  assert.strictEqual(sanitizeInterfaceName('Wi-Fi (Default)'), 'Wi-Fi (Default)');
  assert.strictEqual(sanitizeInterfaceName('vEthernet #1'), 'vEthernet #1');

  const maliciousIfaces = [
    'Ethernet; calc.exe',
    'Wi-Fi & whoami',
    'eth0 | powershell',
    'eth0\nrm -rf /',
    'eth0" `calc`'
  ];

  for (const badIface of maliciousIfaces) {
    assert.throws(
      () => sanitizeInterfaceName(badIface),
      /Caractères non autorisés|Nom d'interface invalide/,
      `Expected interface sanitization to reject: ${badIface}`
    );
  }
  console.log('✓ Interface name sanitization strictly prevents command delimiters (&, ;, |, newline, backtick)');

  console.log('\n--- TEST 4: Path Sanitization (UNC, Directory Traversal & Root Whitelist) ---');
  if (os.platform() === 'win32') {
    assert.strictEqual(sanitizePath('C:\\Windows\\System32\\calc.exe'), 'C:\\Windows\\System32\\calc.exe');
    assert.strictEqual(sanitizePath('d:\\data\\report.pdf'), 'd:\\data\\report.pdf');
  } else {
    assert.strictEqual(sanitizePath('/usr/bin/python3'), '/usr/bin/python3');
  }

  // 1. Control character rejection
  assert.throws(() => sanitizePath('C:\\Windows\\System32\\test\x00.exe'), /Caractères de contrôle interdits/);
  assert.throws(() => sanitizePath('C:\\Windows\\System32\ncalc.exe'), /Caractères de contrôle interdits/);

  // 2. UNC path rejection (blocks SMB NTLM credential leaks & remote execution)
  assert.throws(() => sanitizePath('\\\\attacker.com\\share\\malware.exe'), /Chemins réseau UNC interdits/);
  assert.throws(() => sanitizePath('//attacker.com/share/malware.exe'), /Chemins réseau UNC interdits/);
  assert.throws(() => sanitizePath('\\\\?\\UNC\\server\\share\\malware.exe'), /Chemins réseau UNC interdits/);

  // 3. Directory traversal rejection (..)
  assert.throws(() => sanitizePath('C:\\Windows\\..\\evil.exe'), /Séquences de traversée de répertoire/);
  assert.throws(() => sanitizePath('C:\\Windows\\System32\\..\\..\\malware.exe'), /Séquences de traversée de répertoire/);

  // 4. Relative paths rejection
  assert.throws(() => sanitizePath('relative\\path.exe'), /Le chemin doit être un chemin absolu/);
  assert.throws(() => sanitizePath('calc.exe'), /Le chemin doit être un chemin absolu/);

  // 5. Unwhitelisted root rejection
  if (os.platform() === 'win32') {
    assert.throws(() => sanitizePath('1:\\bad\\path.exe'), /Racine non autorisée|Le chemin doit être un chemin absolu/);
  }
  console.log('✓ Path sanitization strictly blocks UNC paths, directory traversal (..), relative paths, and unwhitelisted roots');

  console.log('\n--- TEST 5: Protected System Processes (BSOD Prevention) ---');
  // 1. System PIDs
  await assert.rejects(
    async () => await assertProcessNotProtected(0),
    /Processus système critique protégé/,
    'PID 0 (System Idle) must be protected'
  );
  await assert.rejects(
    async () => await assertProcessNotProtected(4),
    /Processus système critique protégé/,
    'PID 4 (System) must be protected'
  );
  await assert.rejects(
    async () => await assertProcessNotProtected(1),
    /Processus système critique protégé/,
    'PID 1 (Init) must be protected'
  );
  await assert.rejects(
    async () => await assertProcessNotProtected(process.pid),
    /Processus système critique protégé/,
    'Current process PID must be protected'
  );

  // 2. Critical Windows Process Names (BSOD culprits)
  const criticalNames = [
    'csrss.exe',
    'lsass.exe',
    'wininit.exe',
    'services.exe',
    'smss.exe',
    'winlogon.exe',
    'dwm.exe',
    'svchost.exe'
  ];

  for (const name of criticalNames) {
    await assert.rejects(
      async () => await assertProcessNotProtected(99999, name),
      /action bloquée pour éviter un écran bleu \(BSOD\)/,
      `Process "${name}" must be protected against taskkill`
    );
  }

  // 3. Normal / Rogue userland process should be permitted
  const allowed = await assertProcessNotProtected(99999, 'malicious_agent.exe');
  assert.strictEqual(allowed, 'malicious_agent.exe');
  console.log('✓ assertProcessNotProtected prevents killing csrss, lsass, wininit, services and other BSOD-causing processes');

  console.log('\n--- TEST 6: safeExecPowerShell Execution with Escaped / Malicious Strings ---');
  const { stdout: normalOut } = await safeExecPowerShell('Write-Output "HELLO_SPACESEC"');
  assert.ok(normalOut.includes('HELLO_SPACESEC'), 'Normal PowerShell script should execute');

  const complexString = 'Test"Value\'; `calc`; $env:TEMP; Write-Output "INJECTED_BAD"; \'';
  const scriptWithVar = `
    $val = ${psString(complexString)};
    Write-Output "RESULT:$val"
  `;
  const { stdout: injectTestOut } = await safeExecPowerShell(scriptWithVar);
  assert.ok(injectTestOut.includes('RESULT:Test"Value\'; `calc`; $env:TEMP; Write-Output "INJECTED_BAD"; \''));
  assert.ok(!injectTestOut.includes('\nINJECTED_BAD\n') && !injectTestOut.trim().endsWith('INJECTED_BAD'), 'Secondary command must NOT execute');
  console.log('✓ safeExecPowerShell with psString safely embeds complex strings without shell breakout');

  console.log('\n========================================');
  console.log('ALL COMMAND INJECTION & VALIDATION TESTS PASSED 100%!');
  console.log('========================================');
}

runTests().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
