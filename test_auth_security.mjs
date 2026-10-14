import assert from 'assert';
import {
  isAllowedHost,
  corsAndCsrfProtection,
  createSession,
  getSession,
  touchSession,
  revokeSession,
  listActiveSessions,
  createWebSocketTicket,
  consumeWebSocketTicket,
  validateWebSocketRequest,
  validateWebSocketConnection,
  requireAuth,
  requireRole,
  requireEdrAuth,
  getLocalAuthToken,
  getEdrAgentToken,
  isValidToken,
  isValidEdrAgentToken,
} from './src/server/auth.ts';

console.log('--- TEST 1: Host and Origin Whitelist / DNS Rebinding Protection ---');
assert.strictEqual(isAllowedHost('localhost'), true, 'localhost must be allowed');
assert.strictEqual(isAllowedHost('localhost:3000'), true, 'localhost:3000 must be allowed');
assert.strictEqual(isAllowedHost('127.0.0.1'), true, '127.0.0.1 must be allowed');
assert.strictEqual(isAllowedHost('127.0.0.1:8080'), true, '127.0.0.1:8080 must be allowed');
assert.strictEqual(isAllowedHost('::1'), true, '::1 must be allowed');
assert.strictEqual(isAllowedHost('[::1]:3000'), true, '[::1]:3000 must be allowed');

// Attacker hosts must be strictly rejected
assert.strictEqual(isAllowedHost('localhost.evil.com'), false, 'localhost.evil.com must be rejected');
assert.strictEqual(isAllowedHost('127.0.0.1.attacker.net'), false, 'subdomain attack must be rejected');
assert.strictEqual(isAllowedHost('x.run.app'), false, 'arbitrary run.app when not enabled must be rejected');
assert.strictEqual(isAllowedHost('attacker-run.app'), false, 'attacker-run.app must be rejected');
assert.strictEqual(isAllowedHost('evil.com'), false, 'evil.com must be rejected');
assert.strictEqual(isAllowedHost(''), false, 'empty host must be rejected');
console.log('✓ Host whitelist & DNS rebinding tests passed');

console.log('\n--- TEST 2: CORS and CSRF Protection Middleware ---');
// Test 2.1: Hostile Host rejected with 400
{
  let statusCode = 200;
  let jsonBody = null;
  const req = {
    headers: { host: 'evil.attacker.com', origin: 'http://evil.attacker.com' },
    ip: '127.0.0.1',
    path: '/api/settings',
    method: 'POST',
  };
  const res = {
    setHeader: () => {},
    status: (code) => {
      statusCode = code;
      return { json: (data) => { jsonBody = data; } };
    },
  };
  corsAndCsrfProtection(req, res, () => { assert.fail('Should not call next() on hostile host'); });
  assert.strictEqual(statusCode, 400, 'Hostile Host must receive HTTP 400');
  assert.strictEqual(jsonBody.code, 'DNS_REBINDING_BLOCKED');
  console.log('✓ Hostile Host blocked by DNS Rebinding shield');
}

// Test 2.2: Hostile Origin rejected with 403
{
  let statusCode = 200;
  let jsonBody = null;
  const req = {
    headers: { host: 'localhost:3000', origin: 'http://localhost.evil.com' },
    ip: '127.0.0.1',
    path: '/api/settings',
    method: 'POST',
  };
  const res = {
    setHeader: () => {},
    status: (code) => {
      statusCode = code;
      return { json: (data) => { jsonBody = data; } };
    },
  };
  corsAndCsrfProtection(req, res, () => { assert.fail('Should not call next() on hostile origin'); });
  assert.strictEqual(statusCode, 403, 'Hostile Origin must receive HTTP 403');
  assert.strictEqual(jsonBody.code, 'CSRF_BLOCKED');
  console.log('✓ Hostile Origin (localhost.evil.com) blocked by CSRF shield');
}

// Test 2.3: Valid Origin sets strict CORS headers including DELETE method and no wildcard credentials
{
  const headers = {};
  const req = {
    headers: { host: '127.0.0.1:3000', origin: 'http://127.0.0.1:3000' },
    ip: '127.0.0.1',
    path: '/api/edr/endpoints/1',
    method: 'DELETE',
  };
  const res = {
    setHeader: (k, v) => { headers[k] = v; },
    status: () => res,
    json: () => {},
  };
  let nextCalled = false;
  corsAndCsrfProtection(req, res, () => { nextCalled = true; });
  assert.strictEqual(nextCalled, true, 'Next must be called for valid origin');
  assert.strictEqual(headers['Access-Control-Allow-Origin'], 'http://127.0.0.1:3000');
  assert.notStrictEqual(headers['Access-Control-Allow-Origin'], '*', 'Origin must never be wildcard with credentials');
  assert.strictEqual(headers['Access-Control-Allow-Credentials'], 'true');
  assert(headers['Access-Control-Allow-Methods'].includes('DELETE'), 'CORS methods must include DELETE');
  console.log('✓ Valid Origin sets strict RFC-compliant CORS headers with DELETE support');
}

console.log('\n--- TEST 3: Cryptographic Session Management & RBAC ---');
// Create session
const adminSession = createSession({ name: 'Admin Test', role: 'admin' });
assert(adminSession.id.startsWith('sess_'));
assert.strictEqual(adminSession.operator.role, 'admin');

const analystSession = createSession({ name: 'Analyst Test', role: 'analyste' });
assert.strictEqual(analystSession.operator.role, 'analyste');

const readOnlySession = createSession({ name: 'Guest Test', role: 'lecture_seule' });
assert.strictEqual(readOnlySession.operator.role, 'lecture_seule');

assert.strictEqual(getSession(adminSession.id).operator.name, 'Admin Test');
assert.strictEqual(getSession('invalid_sess'), null);

// Test requireAuth with session
{
  const req = {
    headers: { authorization: `Bearer ${analystSession.id}` },
    query: {},
    socket: { remoteAddress: '127.0.0.1' },
    path: '/api/shared/mutate',
    method: 'POST',
  };
  let nextCalled = false;
  requireAuth(req, {}, () => { nextCalled = true; });
  assert.strictEqual(nextCalled, true);
  assert.strictEqual(req.authenticatedOperator.role, 'analyste');
  console.log('✓ requireAuth successfully authenticated valid session token');
}

// Test requireAuth rejects unauthenticated
{
  let statusCode = 200;
  const req = {
    headers: {},
    query: {},
    socket: { remoteAddress: '127.0.0.1' },
    path: '/api/system/kill',
    method: 'POST',
  };
  const res = {
    status: (code) => {
      statusCode = code;
      return { json: () => {} };
    },
  };
  requireAuth(req, res, () => { assert.fail('Should not authenticate'); });
  assert.strictEqual(statusCode, 401, 'Unauthenticated request must receive 401');
  console.log('✓ requireAuth correctly rejects unauthenticated requests with 401');
}

// Test RBAC requireRole
{
  const adminReq = { authenticatedOperator: adminSession.operator, path: '/api/system/kill' };
  let adminNext = false;
  requireRole('admin')(adminReq, {}, () => { adminNext = true; });
  assert.strictEqual(adminNext, true, 'Admin must be permitted on admin routes');

  const analystReq = { authenticatedOperator: analystSession.operator, path: '/api/system/kill' };
  let analystBlocked = false;
  const res = {
    status: (code) => {
      assert.strictEqual(code, 403);
      analystBlocked = true;
      return { json: () => {} };
    },
  };
  requireRole('admin')(analystReq, res, () => { assert.fail('Analyst must not pass admin route'); });
  assert.strictEqual(analystBlocked, true, 'Analyst must be blocked from admin routes');

  const readOnlyReq = { authenticatedOperator: readOnlySession.operator, path: '/api/shared/mutate' };
  let readOnlyBlocked = false;
  requireRole('admin', 'analyste')(readOnlyReq, {
    status: (code) => {
      assert.strictEqual(code, 403);
      readOnlyBlocked = true;
      return { json: () => {} };
    },
  }, () => { assert.fail('lecture_seule must not pass mutation route'); });
  assert.strictEqual(readOnlyBlocked, true, 'lecture_seule must be blocked from mutation routes');
  console.log('✓ RBAC enforcement correctly differentiates admin, analyste, and lecture_seule');
}

console.log('\n--- TEST 4: Single-Use WebSocket Tickets ---');
const wsTicket = createWebSocketTicket(analystSession.operator, 60);
assert(wsTicket.startsWith('wst_'));

// First consumption succeeds
const consumedOp1 = consumeWebSocketTicket(wsTicket);
assert.notStrictEqual(consumedOp1, null);
assert.strictEqual(consumedOp1.name, 'Analyst Test');

// Second consumption MUST fail (single use guarantee!)
const consumedOp2 = consumeWebSocketTicket(wsTicket);
assert.strictEqual(consumedOp2, null, 'Ticket must be unusable after first consumption');
console.log('✓ Single-use WebSocket ticket consumed once and strictly invalidated on second attempt');

// WebSocket handshake request validation with ticket
const ticketForWs = createWebSocketTicket(adminSession.operator, 60);
const mockWsReq = {
  headers: { host: 'localhost:3000' },
  url: `/ws?ticket=${ticketForWs}`,
  socket: { remoteAddress: '127.0.0.1' },
};
const wsOp = validateWebSocketRequest(mockWsReq);
assert.notStrictEqual(wsOp, null);
assert.strictEqual(wsOp.role, 'admin');

// Re-using the same URL immediately fails
const wsOpSecond = validateWebSocketRequest(mockWsReq);
assert.strictEqual(wsOpSecond, null, 'Logged WebSocket URL ticket cannot be reused');
console.log('✓ validateWebSocketRequest verifies ticket and blocks replay attacks');

console.log('\n--- TEST 5: Dedicated Scoped EDR Agent Token ---');
const masterToken = getLocalAuthToken();
const edrToken = getEdrAgentToken();
assert.notStrictEqual(masterToken, edrToken, 'EDR token must not equal Master token');
assert.strictEqual(isValidEdrAgentToken(edrToken), true);
assert.strictEqual(isValidEdrAgentToken(masterToken), false, 'Master token is not a raw EDR token');

// requireEdrAuth accepts EDR token
{
  const edrReq = {
    headers: { authorization: `Bearer ${edrToken}` },
    query: {},
    socket: { remoteAddress: '127.0.0.1' },
    path: '/api/edr/telemetry',
    method: 'POST',
  };
  let edrNext = false;
  requireEdrAuth(edrReq, {}, () => { edrNext = true; });
  assert.strictEqual(edrNext, true, 'EDR token must be accepted on EDR telemetry');
}

// requireRole('admin') blocks EDR Agent
{
  const edrReq = {
    headers: { authorization: `Bearer ${edrToken}` },
    query: {},
    socket: { remoteAddress: '127.0.0.1' },
    path: '/api/system/kill',
    method: 'POST',
  };
  let edrBlocked = false;
  requireAuth(edrReq, {
    status: (code) => {
      assert.strictEqual(code, 401);
      edrBlocked = true;
      return { json: () => {} };
    },
  }, () => { assert.fail('EDR agent token cannot act as master admin'); });
  assert.strictEqual(edrBlocked, true, 'EDR agent token cannot call administrative routes');
  console.log('✓ Scoped EDR token cannot be used to execute administrative actions');
}

console.log('\n========================================');
console.log('ALL SECURITY AUDIT TESTS PASSED 100%!');
console.log('========================================');
