import assert from 'node:assert';
import {
  safeExecFile,
  safeExecPowerShell,
  psString,
  validateAndParsePid,
  sanitizeIpAddress,
  sanitizeInterfaceName,
  sanitizePath
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

  console.log('\n--- TEST 2: IP Address Sanitization (Ping Probe Protection) ---');
  assert.strictEqual(sanitizeIpAddress('127.0.0.1'), '127.0.0.1');
  assert.strictEqual(sanitizeIpAddress('8.8.8.8'), '8.8.8.8');
  assert.strictEqual(sanitizeIpAddress('::1'), '::1');
  assert.strictEqual(sanitizeIpAddress('localhost'), 'localhost');

  const maliciousIps = [
    '127.0.0.1; whoami',
    '127.0.0.1 && dir',
    '127.0.0.1 | calc',
    '127.0.0.1\nwhoami',
    '127.0.0.1 `calc`',
    '$(whoami)',
    '1.2.3.4.5',
    '999.999.999.999'
  ];

  for (const badIp of maliciousIps) {
    assert.throws(
      () => sanitizeIpAddress(badIp),
      /Format d'adresse IP invalide|Adresse IP invalide/,
      `Expected IP sanitization to reject: ${badIp}`
    );
  }
  console.log('✓ IP sanitization strictly blocks command chaining and injection payloads');

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

  console.log('\n--- TEST 4: Path Sanitization ---');
  assert.strictEqual(sanitizePath('C:\\Windows\\System32\\calc.exe'), 'C:\\Windows\\System32\\calc.exe');

  const maliciousPaths = [
    'C:\\Windows\\System32\\test\x00.exe',
    'C:\\Windows\\System32\ncalc.exe',
    'C:\\Windows\\System32\rcalc.exe',
    'C:\\Windows\\System32\tcalc.exe',
  ];

  for (const badPath of maliciousPaths) {
    assert.throws(
      () => sanitizePath(badPath),
      /Caractères de contrôle interdits/,
      `Expected path sanitization to reject: ${badPath}`
    );
  }
  console.log('✓ Path sanitization rejects null-bytes and newline control characters');

  console.log('\n--- TEST 5: safeExecPowerShell Execution with Escaped / Malicious Strings ---');
  // 1. Verify basic execution
  const { stdout: normalOut } = await safeExecPowerShell('Write-Output "HELLO_SPACESEC"');
  assert.ok(normalOut.includes('HELLO_SPACESEC'), 'Normal PowerShell script should execute');

  // 2. Verify payload with quotes, double quotes, backticks, dollar signs and semicolons inside string literal does NOT breakout
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
  console.log('ALL COMMAND INJECTION SECURITY TESTS PASSED 100%!');
  console.log('========================================');
}

runTests().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
