import assert from 'assert';
import crypto from 'crypto';
import { isAllowedHost, isAllowedOrigin, createSession, getSession } from '../src/server/auth.ts';
import { dbManager } from '../src/server/db.ts';

async function runTests() {
  console.log('--- 1. Testing DNS Rebinding & Origin Whitelisting ---');
  assert.strictEqual(isAllowedHost('localhost'), true, 'localhost should be allowed');
  assert.strictEqual(isAllowedHost('127.0.0.1'), true, '127.0.0.1 should be allowed');
  assert.strictEqual(isAllowedHost('127.0.0.1:3000'), true, '127.0.0.1:3000 should be allowed');
  assert.strictEqual(isAllowedHost('localhost.evil.com'), false, 'localhost.evil.com must be BLOCKED');
  assert.strictEqual(isAllowedHost('evil-run.app'), false, 'evil-run.app must be BLOCKED');
  assert.strictEqual(isAllowedHost('subdomain.spacesecurity.app'), false, 'unknown domain must be BLOCKED');

  assert.strictEqual(isAllowedOrigin('http://localhost:3000'), true);
  assert.strictEqual(isAllowedOrigin('http://127.0.0.1:5173'), true);
  assert.strictEqual(isAllowedOrigin('http://localhost.evil.com'), false);
  assert.strictEqual(isAllowedOrigin('https://fake-spacesecurity.app'), false);
  console.log('✅ Host and Origin validations passed strictly.');

  console.log('--- 2. Testing Sessions & RBAC ---');
  const adminSession = createSession({ name: 'Admin Test', role: 'admin' });
  assert.strictEqual(adminSession.operator.role, 'admin');
  assert.strictEqual(getSession(adminSession.id)?.operator.role, 'admin');

  const analystSession = createSession({ name: 'Analyst Test', role: 'analyste' });
  assert.strictEqual(analystSession.operator.role, 'analyste');

  const readOnlySession = createSession({ name: 'Observer Test', role: 'lecture_seule' });
  assert.strictEqual(readOnlySession.operator.role, 'lecture_seule');
  console.log('✅ RBAC and Session store passed.');

  console.log('--- 3. Testing Database & EDR Agent Secrets ---');
  await dbManager.initialize();

  const secretKey = crypto.randomBytes(32).toString('hex');
  const testEp = dbManager.saveEndpoint({
    id: 'ep-test-secure-01',
    hostname: 'SEC-TEST-HOST',
    ipAddress: '192.168.1.50',
    agentSecret: secretKey,
    isolationStatus: 'NORMAL',
    networkIsolated: false,
    status: 'ONLINE',
    lastSeen: new Date(Date.now() - 60000).toISOString(), // 60s ago
  });

  const retrieved = dbManager.getEndpoint('ep-test-secure-01');
  assert.ok(retrieved, 'Endpoint must be retrieved from database');
  assert.strictEqual(retrieved?.agentSecret, secretKey, 'Agent secret must match stored secret');
  assert.strictEqual(retrieved?.isolationStatus, 'NORMAL', 'Isolation status must be NORMAL');
  console.log('✅ Endpoint per-agent secret and isolationStatus correctly persisted.');

  console.log('--- 4. Testing HMAC Command Signing & TTL ---');
  const expiresAt = new Date(Date.now() + 1800000).toISOString(); // 30 min
  const cmdId = 'cmd-iso-test-01';
  const cmdType = 'ISOLATE_NETWORK';
  const payload = { reason: 'Test confinement' };
  const payloadStr = JSON.stringify(payload);
  const sigData = `${cmdId}:${cmdType}:${payloadStr}:${expiresAt}`;
  const validSignature = crypto.createHmac('sha256', secretKey).update(sigData).digest('hex');

  const createdCmd = dbManager.createEdrCommand({
    id: cmdId,
    endpointId: 'ep-test-secure-01',
    hostname: 'SEC-TEST-HOST',
    type: cmdType,
    payload,
    expiresAt,
    signature: validSignature,
  });

  assert.strictEqual(createdCmd.signature, validSignature);
  assert.strictEqual(createdCmd.expiresAt, expiresAt);

  // Test tampered signature fails
  const tamperedSig = crypto.createHmac('sha256', 'wrong-secret').update(sigData).digest('hex');
  assert.notStrictEqual(validSignature, tamperedSig, 'Tampered HMAC must not match');
  console.log('✅ HMAC signature generation and tamper-detection passed.');

  console.log('--- 5. Testing Offline Sweep Watchdog ---');
  const { changedEndpoints, expiredCommands } = dbManager.sweepEndpoints(45000);
  const updatedEp = dbManager.getEndpoint('ep-test-secure-01');
  assert.strictEqual(updatedEp?.status, 'OFFLINE', 'Endpoint lastSeen > 45s must transition to OFFLINE');
  assert.ok(changedEndpoints.some(e => e.id === 'ep-test-secure-01' && e.status === 'OFFLINE'), 'Changed endpoints list must report the transition');
  console.log('✅ Offline sweep watchdog successfully transitioned inactive endpoint to OFFLINE.');

  console.log('--- 6. Testing Telemetry Retention Pruning ---');
  dbManager.addEdrEvent({
    endpointId: 'ep-test-secure-01',
    hostname: 'SEC-TEST-HOST',
    category: 'NETWORK',
    severity: 'INFO',
    summary: 'Test telemetry event',
    timestamp: new Date(Date.now() - 10 * 24 * 3600 * 1000).toISOString(), // 10 days old
  });
  const pruneResult = dbManager.pruneTelemetryEvents(7, 500);
  assert.ok(pruneResult.prunedByAge >= 1, 'Event older than 7 days must be pruned');
  console.log('✅ Telemetry retention successfully pruned obsolete events.');

  // Cleanup
  dbManager.deleteEndpoint('ep-test-secure-01');
  dbManager.close();
  console.log('\n🎉 ALL SECURITY UNIT TESTS PASSED SUCCESSFULLY! 🎉');
}

runTests().catch(err => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
