const crypto = require('crypto');
const express = require('express');
const { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } = require('@modelcontextprotocol/sdk/server/auth/router.js');
const { requireBearerAuth } = require('@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { isInitializeRequest } = require('@modelcontextprotocol/sdk/types.js');
const { OwnerOAuthProvider } = require('./auth');

const DEFAULT_PORT = 3847;
const DEFAULT_HOST = '127.0.0.1';
const SESSION_IDLE_MS = 60 * 60 * 1000;
const SWEEP_INTERVAL_MS = 5 * 60 * 1000;

function jsonRpcError(res, status, message) {
  res.status(status).json({ jsonrpc: '2.0', error: { code: -32000, message }, id: null });
}

/**
 * Build the Express app: OAuth endpoints, the consent form, /health and the
 * Streamable HTTP MCP endpoint at /mcp. Kept separate from listen() so tests
 * can run it on a random port.
 */
function createHttpApp({ imessage, version, publicUrl, provider, logger = console }) {
  const issuerUrl = new URL(publicUrl);
  const resourceUrl = new URL('/mcp', issuerUrl);
  const sessions = new Map();

  const app = express();
  app.disable('x-powered-by');
  // Tailscale Funnel connects from loopback and forwards the caller's address
  app.set('trust proxy', 'loopback');

  // Path only: query strings carry authorization codes
  app.use((req, res, next) => {
    const started = Date.now();
    res.on('finish', () => {
      logger.error(`[http] ${req.method} ${req.originalUrl.split('?')[0]} ${res.statusCode} ${Date.now() - started}ms`);
    });
    next();
  });

  app.get('/health', (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json({
      status: 'ok',
      version,
      messages_database: imessage.messagesDatabaseReadable() ? 'readable' : 'unreadable',
    });
  });

  app.use(mcpAuthRouter({
    provider,
    issuerUrl,
    resourceServerUrl: resourceUrl,
    resourceName: 'iMessage MCP',
    // Secrets that expire would silently disconnect a client after a month
    clientRegistrationOptions: { clientSecretExpirySeconds: 0 },
  }));

  app.post('/consent', express.urlencoded({ extended: false, limit: '16kb' }), (req, res) => {
    provider.handleConsent(req, res);
  });

  const auth = requireBearerAuth({
    verifier: provider,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resourceUrl),
  });

  // A session belongs to the client that opened it
  const existingSession = (req) => {
    const sessionId = req.headers['mcp-session-id'];
    if (!sessionId) return { sessionId: null, session: null };
    const session = sessions.get(sessionId);
    if (!session || session.clientId !== req.auth.clientId) return { sessionId, session: null };
    return { sessionId, session };
  };

  app.post('/mcp', auth, express.json({ limit: '4mb' }), async (req, res) => {
    try {
      let { sessionId, session } = existingSession(req);
      if (sessionId && !session) {
        jsonRpcError(res, 404, 'Session not found');
        return;
      }
      if (!session) {
        if (!isInitializeRequest(req.body)) {
          jsonRpcError(res, 400, 'Bad Request: send initialize first');
          return;
        }
        const server = imessage.createServer();
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => crypto.randomUUID(),
          onsessioninitialized: (id) => sessions.set(id, session),
        });
        transport.onclose = () => {
          if (transport.sessionId) sessions.delete(transport.sessionId);
        };
        session = { server, transport, clientId: req.auth.clientId, lastSeen: Date.now() };
        await server.connect(transport);
      }
      session.lastSeen = Date.now();
      await session.transport.handleRequest(req, res, req.body);
    } catch (error) {
      logger.error('[http] MCP request failed:', error.message);
      if (!res.headersSent) jsonRpcError(res, 500, 'Internal server error');
    }
  });

  const handleSessionRequest = async (req, res) => {
    const { session } = existingSession(req);
    if (!session) {
      jsonRpcError(res, req.headers['mcp-session-id'] ? 404 : 400, 'Session not found');
      return;
    }
    session.lastSeen = Date.now();
    try {
      await session.transport.handleRequest(req, res);
    } catch (error) {
      logger.error('[http] MCP request failed:', error.message);
      if (!res.headersSent) jsonRpcError(res, 500, 'Internal server error');
    }
  };
  app.get('/mcp', auth, handleSessionRequest);
  app.delete('/mcp', auth, handleSessionRequest);

  app.use((error, req, res, next) => {
    logger.error('[http] unhandled error:', error.message);
    if (res.headersSent) {
      next(error);
      return;
    }
    res.status(500).json({ error: 'server_error' });
  });

  const sweep = async () => {
    provider.sweep();
    const cutoff = Date.now() - SESSION_IDLE_MS;
    for (const [id, session] of sessions) {
      if (session.lastSeen < cutoff) {
        sessions.delete(id);
        await session.transport.close().catch(() => {});
      }
    }
  };

  const closeAll = async () => {
    for (const [id, session] of sessions) {
      sessions.delete(id);
      await session.transport.close().catch(() => {});
    }
  };

  return { app, sessions, sweep, closeAll };
}

function readPublicUrl(value) {
  if (!value) {
    throw new Error('Set IMESSAGE_MCP_PUBLIC_URL to the https address clients use, for example https://my-mac.tailnet-name.ts.net');
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`IMESSAGE_MCP_PUBLIC_URL is not a valid URL: ${value}`);
  }
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new Error('IMESSAGE_MCP_PUBLIC_URL must be just the origin, with no path, for example https://my-mac.tailnet-name.ts.net');
  }
  return url.origin;
}

async function startHttpServer({ imessage, version, env = process.env, logger = console }) {
  const publicUrl = readPublicUrl(env.IMESSAGE_MCP_PUBLIC_URL);
  const port = Number(env.IMESSAGE_MCP_PORT || DEFAULT_PORT);
  const host = env.IMESSAGE_MCP_HOST || DEFAULT_HOST;
  const provider = new OwnerOAuthProvider({ resourceUrl: new URL('/mcp', publicUrl), logger });
  const { app, sweep, closeAll } = createHttpApp({ imessage, version, publicUrl, provider, logger });

  const listener = await new Promise((resolve, reject) => {
    const server = app.listen(port, host, () => resolve(server));
    server.once('error', reject);
  });

  if (!imessage.messagesDatabaseReadable()) {
    logger.error('[http] cannot open the Messages database. Grant Full Disk Access to this node binary:', process.execPath);
  }

  const timer = setInterval(() => sweep().catch(() => {}), SWEEP_INTERVAL_MS);
  timer.unref();

  // launchd sends SIGTERM when the agent is stopped or the user logs out
  const shutdown = async () => {
    clearInterval(timer);
    await closeAll();
    listener.close(() => process.exit(0));
    listener.closeAllConnections();
    setTimeout(() => process.exit(0), 3000).unref();
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);

  logger.error(`iMessage MCP server v${version} listening on http://${host}:${port}, public address ${publicUrl}/mcp`);
  return listener;
}

module.exports = { createHttpApp, startHttpServer, readPublicUrl, DEFAULT_PORT };
