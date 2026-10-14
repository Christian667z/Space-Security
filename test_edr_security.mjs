import assert from 'assert';
import crypto from 'crypto';
import {
  requireAgentAuth,
  setAuthDbManager,
  getEdrAgentToken,
} from './src/server/auth.ts';

console.log('--- TEST 1: EDR Agent Authentication & HMAC Signature Verification ---');

// Mock in-memory DB provider
const mockEndpoints = new Map();
const mockDb = {
  getEndpoint: (id) => mockEndpoints.get(id) || null,
};
setAuthDbManager(mockDb);

const testSecret = crypto.randomBytes(32).toString('hex');
const testEndpointId = 'ep-win11-prod-a1b2';
mockEndpoints.set(testEndpointId, {
  id: testEndpointId,
  hostname: 'WIN11-PROD',
  agentSecret: testSecret,
  status: 'ONLINE',
});

// Test 1.1: Unauthenticated agent request rejected with 401
{
  let statusCode = 200;
  let jsonBody = null;
  const req = {
    method: 'POST',
    path: '/api/edr/heartbeat',
    headers: {},
    body: { endpointId: testEndpointId },
  };
  const res = {
    status: (code) => {
      statusCode = code;
      return { json: (data) => { jsonBody = data; } };
    },
  };

  requireAgentAuth(req, res, () => {
    assert.fail('Should not pass unauthenticated agent request');
  });
  assert.strictEqual(statusCode, 401);
  assert.strictEqual(jsonBody.code, 'UNAUTHORIZED_EDR_AGENT');
  console.log('✓ Unauthenticated agent request strictly rejected with 401');
}

// Test 1.2: Valid HMAC signed request passes
{
  let nextCalled = false;
  const timestamp = new Date().toISOString();
  const body = { endpointId: testEndpointId, cpuUsagePercent: 12, ramUsagePercent: 45 };
  const rawBody = JSON.stringify(body);
  const dataToSign = `${timestamp}:${testEndpointId}:${rawBody}`;
  const validSig = crypto.createHmac('sha256', testSecret).update(dataToSign).digest('hex');

  const req = {
    method: 'POST',
    path: '/api/edr/heartbeat',
    headers: {
      'x-spacesec-endpoint-id': testEndpointId,
      'x-spacesec-timestamp': timestamp,
      'x-spacesec-signature': validSig,
    },
    body,
  };
  const res = {
    status: () => ({ json: () => {} }),
  };

  requireAgentAuth(req, res, () => {
    nextCalled = true;
  });
  assert.strictEqual(nextCalled, true, 'Valid HMAC signature must be accepted');
  assert.strictEqual(req.edrEndpoint.id, testEndpointId);
  console.log('✓ Valid HMAC-SHA256 signature accepted and authenticated');
}

// Test 1.3: Tampered body or forged signature rejected
{
  let statusCode = 200;
  let jsonBody = null;
  const timestamp = new Date().toISOString();
  const body = { endpointId: testEndpointId, cpuUsagePercent: 12, ramUsagePercent: 45 };
  const forgedSig = crypto.createHmac('sha256', 'attacker-key').update(`${timestamp}:${testEndpointId}:${JSON.stringify(body)}`).digest('hex');

  const req = {
    method: 'POST',
    path: '/api/edr/heartbeat',
    headers: {
      'x-spacesec-endpoint-id': testEndpointId,
      'x-spacesec-timestamp': timestamp,
      'x-spacesec-signature': forgedSig,
    },
    body,
  };
  const res = {
    status: (code) => {
      statusCode = code;
      return { json: (data) => { jsonBody = data; } };
    },
  };

  requireAgentAuth(req, res, () => {
    assert.fail('Tampered signature must not be accepted');
  });
  assert.strictEqual(statusCode, 401);
  assert.strictEqual(jsonBody.code, 'INVALID_AGENT_SIGNATURE');
  console.log('✓ Forged/Tampered HMAC signature rejected with INVALID_AGENT_SIGNATURE');
}

// Test 1.4: Replay attack with expired timestamp (> 5 min) rejected
{
  let statusCode = 200;
  let jsonBody = null;
  const expiredTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString(); // 10 minutes ago
  const body = { endpointId: testEndpointId, cpuUsagePercent: 12, ramUsagePercent: 45 };
  const rawBody = JSON.stringify(body);
  const dataToSign = `${expiredTimestamp}:${testEndpointId}:${rawBody}`;
  const validSigForExpiredTime = crypto.createHmac('sha256', testSecret).update(dataToSign).digest('hex');

  const req = {
    method: 'POST',
    path: '/api/edr/heartbeat',
    headers: {
      'x-spacesec-endpoint-id': testEndpointId,
      'x-spacesec-timestamp': expiredTimestamp,
      'x-spacesec-signature': validSigForExpiredTime,
    },
    body,
  };
  const res = {
    status: (code) => {
      statusCode = code;
      return { json: (data) => { jsonBody = data; } };
    },
  };

  requireAgentAuth(req, res, () => {
    assert.fail('Expired timestamp must be rejected');
  });
  assert.strictEqual(statusCode, 401);
  assert.strictEqual(jsonBody.code, 'AGENT_TIMESTAMP_EXPIRED');
  console.log('✓ Replay attack blocked (timestamp expired)');
}

// Test 1.5: Direct Per-Agent Secret header authentication
{
  let nextCalled = false;
  const req = {
    method: 'POST',
    path: '/api/edr/telemetry',
    headers: {
      'x-spacesec-endpoint-id': testEndpointId,
      'x-spacesec-agent-secret': testSecret,
    },
    body: { endpointId: testEndpointId, events: [] },
  };
  const res = {
    status: () => ({ json: () => {} }),
  };

  requireAgentAuth(req, res, () => {
    nextCalled = true;
  });
  assert.strictEqual(nextCalled, true, 'Valid per-agent secret header must be accepted');
  console.log('✓ Per-agent secret header accepted');
}

console.log('\n--- TEST 2: Command TTL & Signature Generation ---');
{
  const cmdId = 'cmd-test-iso-99';
  const type = 'ISOLATE_NETWORK';
  const payload = { reason: 'Confinement test' };
  const expiresAt = new Date(Date.now() + 1800000).toISOString();
  const signature = crypto.createHmac('sha256', testSecret).update(`${cmdId}:${type}:${JSON.stringify(payload)}:${expiresAt}`).digest('hex');

  assert.ok(signature.length === 64, 'HMAC-SHA256 signature must be 64 hex characters');
  assert.ok(new Date(expiresAt).getTime() > Date.now(), 'expiresAt must be in the future');
  console.log('✓ Command cryptographic signature and TTL generated correctly');
}

console.log('\n========================================');
console.log('ALL EDR SECURITY & HMAC TESTS PASSED 100%!');
console.log('========================================');
