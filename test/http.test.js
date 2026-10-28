const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { IMessageServer, SERVER_VERSION } = require('../index');
const { OwnerOAuthProvider, savePassphrase } = require('../lib/auth');
const { createHttpApp, readPublicUrl } = require('../lib/http');

const PASSPHRASE = 'correct horse battery staple';
const REDIRECT_URI = 'https://client.example/callback';
const quietLogger = { error: () => {}, log: () => {} };

async function startServer() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'imessage-mcp-http-'));
  savePassphrase(PASSPHRASE, dir);
  const listener = http.createServer();
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${listener.address().port}`;
  const provider = new OwnerOAuthProvider({ resourceUrl: `${baseUrl}/mcp`, dir, logger: quietLogger });
  const imessage = new IMessageServer({ runScript: () => {}, handleSignals: false });
  const { app, closeAll } = createHttpApp({
    imessage,
    version: SERVER_VERSION,
    publicUrl: baseUrl,
    provider,
    logger: quietLogger,
  });
  listener.on('request', app);
  return {
    baseUrl,
    dir,
    provider,
    close: async () => {
      await closeAll();
      listener.closeAllConnections();
      await new Promise(resolve => listener.close(resolve));
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

function pkcePair() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

async function register(baseUrl) {
  const res = await fetch(`${baseUrl}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'Test client',
      redirect_uris: [REDIRECT_URI],
      token_endpoint_auth_method: 'none',
    }),
  });
  assert.equal(res.status, 201);
  return res.json();
}

async function openConsent(baseUrl, client, challenge) {
  const url = new URL('/authorize', baseUrl);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: 'state-123',
  }).toString();
  const res = await fetch(url, { redirect: 'manual' });
  assert.equal(res.status, 200);
  // Without the redirect origin in form-action, browsers block the redirect after Allow
  const formAction = res.headers.get('content-security-policy').match(/form-action ([^;]+)/)[1].split(' ');
  assert.ok(formAction.includes(new URL(REDIRECT_URI).origin), 'consent page allows the redirect origin');
  const html = await res.text();
  const match = html.match(/name="consent_id" value="([^"]+)"/);
  assert.ok(match, 'consent page has a consent id');
  return match[1];
}

function submitConsent(baseUrl, consentId, passphrase, decision = 'allow') {
  return fetch(`${baseUrl}/consent`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ consent_id: consentId, passphrase, decision }).toString(),
    redirect: 'manual',
  });
}

async function token(baseUrl, params) {
  const res = await fetch(`${baseUrl}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  });
  return { status: res.status, body: await res.json() };
}

async function signIn(baseUrl) {
  const client = await register(baseUrl);
  const { verifier, challenge } = pkcePair();
  const consentId = await openConsent(baseUrl, client, challenge);
  const res = await submitConsent(baseUrl, consentId, PASSPHRASE);
  assert.equal(res.status, 302);
  const location = new URL(res.headers.get('location'));
  assert.equal(location.origin + location.pathname, REDIRECT_URI);
  assert.equal(location.searchParams.get('state'), 'state-123');
  const result = await token(baseUrl, {
    grant_type: 'authorization_code',
    code: location.searchParams.get('code'),
    code_verifier: verifier,
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
  });
  assert.equal(result.status, 200);
  return { client, tokens: result.body };
}

async function mcpPost(baseUrl, accessToken, body, sessionId) {
  const headers = {
    authorization: `Bearer ${accessToken}`,
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
  };
  if (sessionId) headers['mcp-session-id'] = sessionId;
  const res = await fetch(`${baseUrl}/mcp`, { method: 'POST', headers, body: JSON.stringify(body) });
  const text = await res.text();
  const dataLine = text.split('\n').find(line => line.startsWith('data: '));
  const json = dataLine ? JSON.parse(dataLine.slice(6)) : (text ? JSON.parse(text) : null);
  return { status: res.status, sessionId: res.headers.get('mcp-session-id'), json };
}

const initializeRequest = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1.0.0' } },
};

test('readPublicUrl accepts an origin and rejects paths', () => {
  assert.equal(readPublicUrl('https://mac.example.ts.net/'), 'https://mac.example.ts.net');
  assert.throws(() => readPublicUrl('https://mac.example.ts.net/mcp'), /just the origin/);
  assert.throws(() => readPublicUrl(''), /IMESSAGE_MCP_PUBLIC_URL/);
});

test('health and discovery endpoints need no token', async (t) => {
  const server = await startServer();
  t.after(server.close);

  const health = await fetch(`${server.baseUrl}/health`);
  assert.equal(health.status, 200);
  const body = await health.json();
  assert.equal(body.status, 'ok');
  assert.equal(body.version, SERVER_VERSION);
  assert.ok(['readable', 'unreadable'].includes(body.messages_database));

  const resource = await (await fetch(`${server.baseUrl}/.well-known/oauth-protected-resource/mcp`)).json();
  assert.equal(resource.resource, `${server.baseUrl}/mcp`);
  const metadata = await (await fetch(`${server.baseUrl}/.well-known/oauth-authorization-server`)).json();
  assert.equal(metadata.registration_endpoint, `${server.baseUrl}/register`);
  assert.deepEqual(metadata.code_challenge_methods_supported, ['S256']);
});

test('the MCP endpoint rejects requests without a valid token', async (t) => {
  const server = await startServer();
  t.after(server.close);

  const res = await fetch(`${server.baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(initializeRequest),
  });
  assert.equal(res.status, 401);
  assert.match(res.headers.get('www-authenticate'), /resource_metadata=".*oauth-protected-resource\/mcp"/);

  const bad = await mcpPost(server.baseUrl, 'not-a-real-token', initializeRequest);
  assert.equal(bad.status, 401);
});

test('signing in with the passphrase gives a token that lists every tool', async (t) => {
  const server = await startServer();
  t.after(server.close);
  const { tokens } = await signIn(server.baseUrl);
  assert.ok(tokens.access_token);
  assert.ok(tokens.refresh_token);

  const init = await mcpPost(server.baseUrl, tokens.access_token, initializeRequest);
  assert.equal(init.status, 200);
  assert.ok(init.sessionId);
  assert.equal(init.json.result.serverInfo.name, 'imessage-server');

  await mcpPost(server.baseUrl, tokens.access_token, { jsonrpc: '2.0', method: 'notifications/initialized' }, init.sessionId);
  const list = await mcpPost(server.baseUrl, tokens.access_token, { jsonrpc: '2.0', id: 2, method: 'tools/list' }, init.sessionId);
  assert.equal(list.status, 200);
  const names = list.json.result.tools.map(tool => tool.name);
  for (const name of ['read_recent_messages', 'send_message', 'send_message_batch', 'react_to_message']) {
    assert.ok(names.includes(name), `${name} is listed`);
  }
});

test('a session cannot be used without initializing or by another client', async (t) => {
  const server = await startServer();
  t.after(server.close);
  const first = await signIn(server.baseUrl);
  const second = await signIn(server.baseUrl);

  const noInit = await mcpPost(server.baseUrl, first.tokens.access_token, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
  assert.equal(noInit.status, 400);

  const init = await mcpPost(server.baseUrl, first.tokens.access_token, initializeRequest);
  const stolen = await mcpPost(server.baseUrl, second.tokens.access_token, { jsonrpc: '2.0', id: 2, method: 'tools/list' }, init.sessionId);
  assert.equal(stolen.status, 404);
});

test('a wrong passphrase issues nothing, and repeated failures lock sign-in', async (t) => {
  const server = await startServer();
  t.after(server.close);
  const client = await register(server.baseUrl);
  const { challenge } = pkcePair();
  const consentId = await openConsent(server.baseUrl, client, challenge);

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const res = await submitConsent(server.baseUrl, consentId, 'wrong passphrase!!');
    assert.equal(res.status, 401);
    assert.equal(res.headers.get('location'), null);
  }
  const locked = await submitConsent(server.baseUrl, consentId, PASSPHRASE);
  assert.equal(locked.status, 401);
  assert.match(await locked.text(), /Too many wrong attempts/);
});

test('deny sends the client back with access_denied', async (t) => {
  const server = await startServer();
  t.after(server.close);
  const client = await register(server.baseUrl);
  const { challenge } = pkcePair();
  const consentId = await openConsent(server.baseUrl, client, challenge);
  const res = await submitConsent(server.baseUrl, consentId, '', 'deny');
  assert.equal(res.status, 302);
  assert.equal(new URL(res.headers.get('location')).searchParams.get('error'), 'access_denied');
});

test('refresh tokens rotate and cannot be reused', async (t) => {
  const server = await startServer();
  t.after(server.close);
  const { client, tokens } = await signIn(server.baseUrl);

  const refreshed = await token(server.baseUrl, {
    grant_type: 'refresh_token',
    refresh_token: tokens.refresh_token,
    client_id: client.client_id,
  });
  assert.equal(refreshed.status, 200);
  assert.notEqual(refreshed.body.access_token, tokens.access_token);

  const reused = await token(server.baseUrl, {
    grant_type: 'refresh_token',
    refresh_token: tokens.refresh_token,
    client_id: client.client_id,
  });
  assert.equal(reused.status, 400);
  assert.equal(reused.body.error, 'invalid_grant');
});

test('tokens survive a restart and are stored only as hashes', async (t) => {
  const server = await startServer();
  t.after(server.close);
  const { tokens } = await signIn(server.baseUrl);

  const saved = fs.readFileSync(path.join(server.dir, 'oauth.json'), 'utf8');
  assert.ok(!saved.includes(tokens.access_token));
  assert.ok(!saved.includes(tokens.refresh_token));
  assert.equal((fs.statSync(path.join(server.dir, 'oauth.json')).mode & 0o777), 0o600);

  const restarted = new OwnerOAuthProvider({ resourceUrl: `${server.baseUrl}/mcp`, dir: server.dir, logger: quietLogger });
  const info = await restarted.verifyAccessToken(tokens.access_token);
  assert.ok(info.expiresAt > Date.now() / 1000);
});

test('setting a new passphrase signs out existing clients', async (t) => {
  const server = await startServer();
  t.after(server.close);
  const { tokens } = await signIn(server.baseUrl);
  savePassphrase('a different passphrase', server.dir);
  const restarted = new OwnerOAuthProvider({ resourceUrl: `${server.baseUrl}/mcp`, dir: server.dir, logger: quietLogger });
  await assert.rejects(restarted.verifyAccessToken(tokens.access_token));
  assert.throws(() => savePassphrase('short', server.dir), /at least 12/);
});
