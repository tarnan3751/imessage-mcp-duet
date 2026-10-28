const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  InvalidGrantError,
  InvalidRequestError,
  InvalidTargetError,
  InvalidTokenError,
} = require('@modelcontextprotocol/sdk/server/auth/errors.js');

const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
const AUTH_CODE_TTL_SECONDS = 5 * 60;
const CONSENT_TTL_SECONDS = 10 * 60;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_SECONDS = 15 * 60;
const MAX_CLIENTS = 50;
const MIN_PASSPHRASE_LENGTH = 12;
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, keylen: 32 };

function stateDir() {
  return process.env.IMESSAGE_MCP_STATE_DIR || path.join(os.homedir(), '.imessage-mcp');
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw new Error(`Could not read ${file}: ${error.message}`);
  }
}

// Write to a temp file and rename so a crash never leaves half a file behind
function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function randomToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function hashPassphrase(passphrase) {
  const salt = crypto.randomBytes(16).toString('hex');
  const { N, r, p, keylen } = SCRYPT_PARAMS;
  const hash = crypto.scryptSync(passphrase, salt, keylen, { N, r, p }).toString('hex');
  return { algorithm: 'scrypt', salt, hash, N, r, p, keylen };
}

function verifyPassphrase(passphrase, record) {
  if (!record || typeof passphrase !== 'string' || passphrase.length === 0) return false;
  const expected = Buffer.from(record.hash, 'hex');
  const actual = crypto.scryptSync(passphrase, record.salt, record.keylen, {
    N: record.N,
    r: record.r,
    p: record.p,
  });
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function passphraseFile(dir = stateDir()) {
  return path.join(dir, 'passphrase.json');
}

function oauthStateFile(dir = stateDir()) {
  return path.join(dir, 'oauth.json');
}

function loadPassphraseRecord(dir = stateDir()) {
  return readJson(passphraseFile(dir), null);
}

/**
 * Save a new passphrase. Existing clients and tokens are dropped so anything
 * that was signed in with the old passphrase has to sign in again.
 */
function savePassphrase(passphrase, dir = stateDir()) {
  if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`);
  }
  writeJson(passphraseFile(dir), hashPassphrase(passphrase));
  fs.rmSync(oauthStateFile(dir), { force: true });
}

function promptHidden(question) {
  return new Promise((resolve, reject) => {
    const { stdin, stdout } = process;
    if (!stdin.isTTY) {
      reject(new Error('Run --set-passphrase from a terminal.'));
      return;
    }
    stdout.write(question);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let value = '';
    const onData = (chunk) => {
      for (const char of chunk) {
        if (char === '\r' || char === '\n') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener('data', onData);
          stdout.write('\n');
          resolve(value);
          return;
        }
        if (char === '\u0003') {
          stdin.setRawMode(false);
          stdout.write('\n');
          process.exit(130);
        }
        if (char === '\u007f' || char === '\b') {
          value = value.slice(0, -1);
        } else {
          value += char;
        }
      }
    };
    stdin.on('data', onData);
  });
}

async function setPassphraseInteractive() {
  const first = await promptHidden(`New passphrase (at least ${MIN_PASSPHRASE_LENGTH} characters): `);
  const second = await promptHidden('Repeat it: ');
  if (first !== second) throw new Error('The passphrases did not match. Nothing was changed.');
  savePassphrase(first);
  console.log(`Saved to ${passphraseFile()}. Restart the server, then sign in again from each client.`);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function consentPage({ consentId, clientName, redirectHost, error }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>iMessage MCP sign in</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 420px; margin: 48px auto; padding: 0 16px; color: #1d1d1f; }
  h1 { font-size: 20px; }
  p { line-height: 1.4; }
  input[type=password] { width: 100%; box-sizing: border-box; padding: 10px; font-size: 16px; margin: 8px 0 16px; }
  button { padding: 10px 16px; font-size: 16px; margin-right: 8px; }
  .error { color: #b00020; }
</style>
</head>
<body>
<h1>Allow access to your messages?</h1>
<p><strong>${escapeHtml(clientName)}</strong> wants to read and send messages through this Mac. It will return to <strong>${escapeHtml(redirectHost)}</strong>.</p>
${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
<form method="post" action="/consent">
  <input type="hidden" name="consent_id" value="${escapeHtml(consentId)}">
  <label for="passphrase">Passphrase</label>
  <input id="passphrase" name="passphrase" type="password" autocomplete="current-password" autofocus required>
  <button type="submit" name="decision" value="allow">Allow</button>
  <button type="submit" name="decision" value="deny" formnovalidate>Deny</button>
</form>
</body>
</html>`;
}

function setPageHeaders(res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'");
  res.setHeader('Referrer-Policy', 'no-referrer');
}

function redirectWith(res, redirectUri, params) {
  const target = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) target.searchParams.set(key, value);
  }
  res.redirect(302, target.href);
}

/**
 * OAuth provider for a single owner. Any client can register, but nothing is
 * issued until someone types the owner's passphrase on the consent page.
 * Tokens are stored only as hashes.
 */
class OwnerOAuthProvider {
  constructor({ resourceUrl, dir = stateDir(), passphraseRecord = loadPassphraseRecord(dir), logger = console } = {}) {
    if (!passphraseRecord) {
      throw new Error('No passphrase is set. Run "node index.js --set-passphrase" first.');
    }
    this.resourceUrl = new URL(resourceUrl);
    this.file = oauthStateFile(dir);
    this.passphraseRecord = passphraseRecord;
    this.logger = logger;
    this.state = readJson(this.file, { clients: {}, accessTokens: {}, refreshTokens: {} });
    this.pendingConsents = new Map();
    this.authorizationCodes = new Map();
    this.failedAttempts = [];
    this.lockedUntil = 0;

    this.clientsStore = {
      getClient: (clientId) => this.state.clients[clientId],
      registerClient: (client) => {
        this.state.clients[client.client_id] = client;
        this.pruneClients();
        this.save();
        this.logger.error(`[auth] registered client "${client.client_name || client.client_id}"`);
        return client;
      },
    };
  }

  save() {
    this.pruneExpired();
    writeJson(this.file, this.state);
  }

  pruneExpired() {
    const now = nowSeconds();
    for (const store of [this.state.accessTokens, this.state.refreshTokens]) {
      for (const [key, record] of Object.entries(store)) {
        if (record.expiresAt <= now) delete store[key];
      }
    }
  }

  // Registration is open to anyone who can reach the server, so cap how many
  // unused registrations pile up on disk
  pruneClients() {
    const ids = Object.keys(this.state.clients);
    if (ids.length <= MAX_CLIENTS) return;
    const inUse = new Set(Object.values(this.state.refreshTokens).map(record => record.clientId));
    const removable = ids
      .filter(id => !inUse.has(id))
      .sort((a, b) => (this.state.clients[a].client_id_issued_at || 0) - (this.state.clients[b].client_id_issued_at || 0));
    while (Object.keys(this.state.clients).length > MAX_CLIENTS && removable.length > 0) {
      delete this.state.clients[removable.shift()];
    }
  }

  // Clients differ on whether they send the /mcp path or just the origin, and
  // this server is the only resource on its origin, so compare origins
  checkResource(resource) {
    if (resource && resource.origin !== this.resourceUrl.origin) {
      throw new InvalidTargetError(`This server only issues tokens for ${this.resourceUrl.href}`);
    }
  }

  async authorize(client, params, res) {
    setPageHeaders(res);
    try {
      this.checkResource(params.resource);
    } catch (error) {
      redirectWith(res, params.redirectUri, { error: error.errorCode, error_description: error.message, state: params.state });
      return;
    }
    const consentId = randomToken();
    this.pendingConsents.set(consentId, {
      clientId: client.client_id,
      params,
      expiresAt: nowSeconds() + CONSENT_TTL_SECONDS,
    });
    res.status(200).type('html').send(consentPage({
      consentId,
      clientName: client.client_name || client.client_id,
      redirectHost: new URL(params.redirectUri).host,
    }));
  }

  isLockedOut() {
    return nowSeconds() < this.lockedUntil;
  }

  recordFailedAttempt() {
    const now = nowSeconds();
    this.failedAttempts = this.failedAttempts.filter(time => time > now - LOCKOUT_SECONDS);
    this.failedAttempts.push(now);
    if (this.failedAttempts.length >= MAX_FAILED_ATTEMPTS) {
      this.lockedUntil = now + LOCKOUT_SECONDS;
      this.failedAttempts = [];
      this.logger.error('[auth] too many wrong passphrases, sign-in locked for 15 minutes');
    }
  }

  // Express handler for the consent form
  handleConsent(req, res) {
    setPageHeaders(res);
    const consentId = req.body && req.body.consent_id;
    const pending = consentId && this.pendingConsents.get(consentId);
    if (!pending || pending.expiresAt <= nowSeconds()) {
      if (consentId) this.pendingConsents.delete(consentId);
      res.status(400).type('text').send('This sign-in request has expired. Start again from your client.');
      return;
    }
    const client = this.state.clients[pending.clientId];
    const { params } = pending;
    if (!client) {
      this.pendingConsents.delete(consentId);
      res.status(400).type('text').send('Unknown client. Start again from your client.');
      return;
    }

    if (req.body.decision === 'deny') {
      this.pendingConsents.delete(consentId);
      redirectWith(res, params.redirectUri, { error: 'access_denied', state: params.state });
      return;
    }

    const page = (error) => res.status(401).type('html').send(consentPage({
      consentId,
      clientName: client.client_name || client.client_id,
      redirectHost: new URL(params.redirectUri).host,
      error,
    }));

    if (this.isLockedOut()) {
      page('Too many wrong attempts. Try again in 15 minutes.');
      return;
    }
    if (!verifyPassphrase(req.body.passphrase, this.passphraseRecord)) {
      this.logger.error('[auth] wrong passphrase on consent page');
      this.recordFailedAttempt();
      page(this.isLockedOut() ? 'Too many wrong attempts. Try again in 15 minutes.' : 'Wrong passphrase.');
      return;
    }

    this.pendingConsents.delete(consentId);
    this.failedAttempts = [];
    const code = randomToken();
    this.authorizationCodes.set(code, {
      clientId: client.client_id,
      codeChallenge: params.codeChallenge,
      redirectUri: params.redirectUri,
      scopes: params.scopes || [],
      resource: params.resource ? params.resource.href : this.resourceUrl.href,
      expiresAt: nowSeconds() + AUTH_CODE_TTL_SECONDS,
    });
    this.logger.error(`[auth] approved sign-in for "${client.client_name || client.client_id}"`);
    redirectWith(res, params.redirectUri, { code, state: params.state });
  }

  getAuthorizationCode(client, code) {
    const record = this.authorizationCodes.get(code);
    if (!record || record.clientId !== client.client_id || record.expiresAt <= nowSeconds()) {
      throw new InvalidGrantError('Invalid or expired authorization code');
    }
    return record;
  }

  async challengeForAuthorizationCode(client, code) {
    return this.getAuthorizationCode(client, code).codeChallenge;
  }

  async exchangeAuthorizationCode(client, code, _codeVerifier, redirectUri, resource) {
    const record = this.getAuthorizationCode(client, code);
    this.authorizationCodes.delete(code);
    if (redirectUri && redirectUri !== record.redirectUri) {
      throw new InvalidGrantError('redirect_uri does not match the authorization request');
    }
    this.checkResource(resource);
    return this.issueTokens(client.client_id, record.scopes, record.resource);
  }

  async exchangeRefreshToken(client, refreshToken, scopes, resource) {
    const key = sha256(refreshToken);
    const record = this.state.refreshTokens[key];
    if (!record || record.clientId !== client.client_id || record.expiresAt <= nowSeconds()) {
      throw new InvalidGrantError('Invalid or expired refresh token');
    }
    this.checkResource(resource);
    if (scopes && scopes.some(scope => !record.scopes.includes(scope))) {
      throw new InvalidRequestError('Cannot widen scopes on refresh');
    }
    // Refresh tokens are single use
    delete this.state.refreshTokens[key];
    return this.issueTokens(client.client_id, scopes && scopes.length ? scopes : record.scopes, record.resource);
  }

  issueTokens(clientId, scopes, resource) {
    const now = nowSeconds();
    const accessToken = randomToken();
    const refreshToken = randomToken();
    this.state.accessTokens[sha256(accessToken)] = {
      clientId,
      scopes,
      resource,
      expiresAt: now + ACCESS_TOKEN_TTL_SECONDS,
    };
    this.state.refreshTokens[sha256(refreshToken)] = {
      clientId,
      scopes,
      resource,
      expiresAt: now + REFRESH_TOKEN_TTL_SECONDS,
    };
    this.save();
    return {
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      refresh_token: refreshToken,
      scope: scopes.length ? scopes.join(' ') : undefined,
    };
  }

  async verifyAccessToken(token) {
    const record = this.state.accessTokens[sha256(token)];
    if (!record || record.expiresAt <= nowSeconds() || !this.state.clients[record.clientId]) {
      throw new InvalidTokenError('Invalid or expired access token');
    }
    return {
      token,
      clientId: record.clientId,
      scopes: record.scopes,
      expiresAt: record.expiresAt,
      resource: record.resource ? new URL(record.resource) : undefined,
    };
  }

  async revokeToken(client, request) {
    const key = sha256(request.token);
    for (const store of [this.state.accessTokens, this.state.refreshTokens]) {
      if (store[key] && store[key].clientId === client.client_id) delete store[key];
    }
    this.save();
  }

  // Drop expired consent requests and codes that were never used
  sweep() {
    const now = nowSeconds();
    for (const map of [this.pendingConsents, this.authorizationCodes]) {
      for (const [key, record] of map) {
        if (record.expiresAt <= now) map.delete(key);
      }
    }
  }
}

module.exports = {
  OwnerOAuthProvider,
  hashPassphrase,
  verifyPassphrase,
  savePassphrase,
  loadPassphraseRecord,
  setPassphraseInteractive,
  stateDir,
};
