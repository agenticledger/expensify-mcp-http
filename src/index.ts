#!/usr/bin/env node
/**
 * Expensify MCP Server — Streamable HTTP, BROKER-FIRST (auth model "B").
 *
 * This MCP holds ZERO Expensify secrets. It is a *client* of the Connections Broker
 * (https://connectionsbroker.agenticledger.ai), which vaults each user's Expensify
 * API key (kind:"static") and hands it back per request. See broker-client.ts.
 *
 * Credential resolution (per request):
 *   1. Raw passthrough escape hatch (holds no secret): if the caller sends
 *      `Authorization: Bearer <expensify-api-key>`, use it directly.
 *   2. Broker-first (default): derive the caller's `principal`, sign a short-lived
 *      JWT, ask the broker POST /token for the Expensify key, construct the client.
 *      If not connected yet, return a connect-on-first-call message (never errors).
 *
 * Principal transport (the platform-gateway contract):
 *   - `X-Broker-Principal: <instanceId>:<agentId>` set by the gateway (per-agent).
 *   - Optional `X-Broker-Principal-Sig` (HMAC) enforced when BROKER_PRINCIPAL_HMAC_KEY
 *     is set — makes the header unforgeable on the public Railway host.
 *   - No header -> BROKER_FALLBACK_PRINCIPAL (standalone single-principal mode).
 */

import { randomUUID, createHmac } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { zodToJsonSchema as _zodToJsonSchema } from 'zod-to-json-schema';
import { ExpensifyClient } from './api-client.js';
import { tools } from './tools.js';
import {
  brokerConfigured,
  brokerBaseUrl,
  brokerClientNamespace,
  brokerProvider,
  brokerProviderKind,
  resolveToken,
  startConnect,
} from './broker-client.js';

function zodToJsonSchema(schema: any): any {
  return _zodToJsonSchema(schema);
}

// --- Config ---
const PORT = parseInt(process.env.PORT || '3100', 10);
const SERVER_BASE_URL = process.env.SERVER_BASE_URL || `http://localhost:${PORT}`;
const SLUG = 'expensify';
const NAME = 'Expensify MCP Server';
const VERSION = '2.0.0';

/** Construct a ExpensifyClient from a broker-resolved (or raw passthrough) credential. */
function makeClient(credential: string): ExpensifyClient {
  const o = JSON.parse(credential); return new ExpensifyClient(o.partnerUserID ?? o.id, o.partnerUserSecret ?? o.secret);
}

// --- Principal transport (platform-gateway contract) ---
const PRINCIPAL_HEADER = (process.env.BROKER_PRINCIPAL_HEADER || 'x-broker-principal').toLowerCase();
const PRINCIPAL_SIG_HEADER = 'x-broker-principal-sig';
const PRINCIPAL_HMAC_KEY = process.env.BROKER_PRINCIPAL_HMAC_KEY || '';
const FALLBACK_PRINCIPAL = process.env.BROKER_FALLBACK_PRINCIPAL || 'default';

function headerValue(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

function derivePrincipal(req: express.Request): { principal: string } | { error: string } {
  const raw = headerValue(req.headers[PRINCIPAL_HEADER]);
  if (raw && raw.trim()) {
    const principal = raw.trim();
    if (PRINCIPAL_HMAC_KEY) {
      const sig = headerValue(req.headers[PRINCIPAL_SIG_HEADER]);
      const expected = createHmac('sha256', PRINCIPAL_HMAC_KEY).update(principal).digest('base64url');
      if (!sig || sig !== expected) {
        return { error: `Missing or invalid ${PRINCIPAL_SIG_HEADER} for the supplied ${PRINCIPAL_HEADER}` };
      }
    }
    return { principal };
  }
  return { principal: FALLBACK_PRINCIPAL };
}

/** Raw passthrough escape hatch — holds no secret. */
function rawPassthrough(req: express.Request): string | null {
  const auth = req.headers.authorization;
  if (!auth) return null;
  const bearer = auth.replace(/^Bearer\s+/i, '').trim();
  return bearer || null;
}

// --- Express app ---
const app = express();
app.use(express.json());
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use('/static', express.static(path.join(__dirname, 'public')));

// OAuth-trap fix (phase 1): keep the OAuth AS discovery path 404 so Claude CLI
// never auto-initiates a self-hosted OAuth dance — this MCP is broker-first.
app.get('/_disabled/oauth-authorization-server', (_req, res) => {
  res.status(404).json({ error: 'not_found' });
});

app.get('/', (_req, res) => {
  res.json({
    name: NAME,
    provider: 'AgenticLedger',
    version: VERSION,
    description:
      'Expensify Banking — accounts, transactions, recipients, payments, invoicing, and treasury operations through MCP tools.',
    mcpEndpoint: '/mcp',
    transport: 'streamable-http',
    tools: tools.length,
    auth: {
      model: 'broker-first',
      description:
        'Credentials are owned by the Connections Broker. On first use the tool returns a one-time connect link; after you connect once, calls just work. No secret is ever pasted into this MCP.',
      broker: brokerBaseUrl,
      principalHeader: PRINCIPAL_HEADER,
      alternativeAuth: {
        type: 'bearer-passthrough',
        description: 'Escape hatch (no secret held): pass a raw Expensify API key as Bearer.',
      },
    },
    configTemplate: { mcpServers: { [SLUG]: { url: `${SERVER_BASE_URL}/mcp` } } },
    links: { health: '/health', documentation: `https://financemcps.agenticledger.ai/${SLUG}/` },
  });
});

app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    server: `${SLUG}-mcp-http`,
    version: VERSION,
    tools: tools.length,
    transport: 'streamable-http',
    authModel: 'broker-first',
    brokerConfigured,
    brokerBaseUrl,
    provider: brokerProvider,
    providerKind: brokerProviderKind,
    clientNamespace: brokerConfigured ? brokerClientNamespace : null,
    authModes: [
      'broker-first (default): resolves the Expensify key via the Connections Broker',
      'bearer-passthrough (escape hatch): Authorization: Bearer <expensify-api-key>',
    ],
  });
});

// ==================== MCP SERVER ====================

interface SessionState {
  server: Server;
  transport: StreamableHTTPServerTransport;
}

const sessions = new Map<string, SessionState>();

type ClientResolution =
  | { kind: 'client'; client: ExpensifyClient }
  | { kind: 'connect'; message: string }
  | { kind: 'error'; message: string };

type ClientResolver = () => Promise<ClientResolution>;

function createMCPServer(resolveClient: ClientResolver): Server {
  const server = new Server({ name: `${SLUG}-mcp-server`, version: VERSION }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: tools.map((tool) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: zodToJsonSchema(tool.inputSchema),
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const tool = tools.find((t) => t.name === name);
    if (!tool) throw new Error(`Unknown tool: ${name}`);

    const resolved = await resolveClient();
    if (resolved.kind === 'connect') {
      return { content: [{ type: 'text' as const, text: resolved.message }] };
    }
    if (resolved.kind === 'error') {
      return { content: [{ type: 'text' as const, text: `Error: ${resolved.message}` }], isError: true };
    }

    try {
      const result = await tool.handler(resolved.client, args as any);
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { content: [{ type: 'text' as const, text: `Error: ${message}` }], isError: true };
    }
  });

  return server;
}

/** Build the connect-on-first-call structured message. */
async function connectMessage(principal: string): Promise<string> {
  const started = await startConnect(principal);
  if ('error' in started) {
    return `Expensify isn't connected for this caller yet, and starting a connection failed: ${started.error}`;
  }
  return JSON.stringify(
    {
      status: 'connection_required',
      provider: brokerProvider,
      message:
        brokerProviderKind === 'static'
          ? 'Expensify is not connected for this caller yet. Connect it once via the link below (paste your Expensify API key into your platform’s broker connect flow), then run the tool again — it will work.'
          : 'Expensify is not connected for this caller yet. Open the connect link below once, then run the tool again — it will work.',
      connectUrl: started.authorizeUrl,
    },
    null,
    2
  );
}

app.post('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;

  if (sessionId && sessions.has(sessionId)) {
    const { transport } = sessions.get(sessionId)!;
    await transport.handleRequest(req, res, req.body);
    return;
  }

  let resolveClient: ClientResolver;

  const raw = rawPassthrough(req);
  if (raw) {
    const client = makeClient(raw);
    resolveClient = async () => ({ kind: 'client', client });
  } else {
    if (!brokerConfigured) {
      res.status(503).json({
        error: 'Broker not configured on this server.',
        hint: 'Set BROKER_INSTALL_BEARER, BROKER_JWT_KEY, BROKER_CLIENT_NAMESPACE (from the broker /register).',
        alternative: { Authorization: 'Bearer <your-expensify-api-key>' },
      });
      return;
    }
    const derived = derivePrincipal(req);
    if ('error' in derived) {
      res.status(401).json({ error: derived.error });
      return;
    }
    const principal = derived.principal;
    resolveClient = async () => {
      const tok = await resolveToken(principal);
      if (tok.status === 'connected') return { kind: 'client', client: makeClient(tok.accessToken) };
      if (tok.status === 'not_connected') return { kind: 'connect', message: await connectMessage(principal) };
      return { kind: 'error', message: tok.message };
    };
  }

  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });
  const server = createMCPServer(resolveClient);

  transport.onclose = () => {
    const sid = transport.sessionId;
    if (sid) {
      sessions.delete(sid);
      console.log(`[mcp] Session closed: ${sid}`);
    }
  };

  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);

  const newSessionId = transport.sessionId;
  if (newSessionId) {
    sessions.set(newSessionId, { server, transport });
    console.log(`[mcp] New session: ${newSessionId} (mode: ${raw ? 'passthrough' : 'broker'})`);
  }
});

app.get('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (!sessionId || !sessions.has(sessionId)) {
    res.status(400).json({ error: 'Invalid or missing session. Send initialization POST first.' });
    return;
  }
  const { transport } = sessions.get(sessionId)!;
  await transport.handleRequest(req, res);
});

app.delete('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (!sessionId || !sessions.has(sessionId)) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  const { transport, server } = sessions.get(sessionId)!;
  await transport.close();
  await server.close();
  sessions.delete(sessionId);
  res.status(200).json({ status: 'session closed' });
});

app.listen(PORT, () => {
  console.log(`${NAME} v${VERSION} (broker-first)`);
  console.log(`  MCP endpoint:   ${SERVER_BASE_URL}/mcp`);
  console.log(`  Health check:   ${SERVER_BASE_URL}/health`);
  console.log(`  Tools:          ${tools.length}`);
  console.log(`  Auth model:     broker-first (${brokerConfigured ? 'broker configured' : 'BROKER NOT CONFIGURED'})`);
  console.log(`  Broker:         ${brokerBaseUrl}`);
  console.log(`  Provider:       ${brokerProvider} (${brokerProviderKind})`);
});
