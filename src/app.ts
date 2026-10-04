import { randomUUID } from 'node:crypto';
import express from 'express';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema, JSONRPCMessageSchema, InitializeRequestSchema, SUPPORTED_PROTOCOL_VERSIONS } from '@modelcontextprotocol/sdk/types.js';
import { zodToJsonSchema } from 'zod-to-json-schema';
import { ExpensifyClient } from './api-client.js';
import { tools } from './tools.js';
import { AdmissionError, createAuthenticator, parseCredential, type Caller } from './auth.js';
import { brokerConfigFromEnv, createBrokerClient, type BrokerConfig } from './broker-client.js';

export type AppOptions = { broker?: BrokerConfig; hmacKey?: string; principalHeader?: string; outboundFetch?: typeof fetch };
type Session = { server: Server; transport: StreamableHTTPServerTransport; binding: string };
const VERSION = '2.1.0';
const failure = () => ({ content: [{ type: 'text' as const, text: 'Expensify request failed.' }], isError: true });

export function createApp(options: AppOptions = {}) {
  const outbound = options.outboundFetch ?? fetch;
  const broker = createBrokerClient(options.broker ?? brokerConfigFromEnv(), outbound);
  const hmacKey = options.hmacKey ?? process.env.BROKER_PRINCIPAL_HMAC_KEY ?? '';
  const principalHeader = options.principalHeader ?? process.env.BROKER_PRINCIPAL_HEADER ?? 'x-broker-principal';
  const authenticate = createAuthenticator({ brokerConfigured: broker.configured, hmacKey, principalHeader });
  const sessions = new Map<string, Session>();
  const app = express();
  const readiness = { brokerConfigured: broker.configured, brokerReady: broker.configured && Boolean(hmacKey.trim()), rawBearerAvailable: true };
  app.get('/', (_req, res) => res.json({ name: 'Expensify MCP Server', version: VERSION, description: 'Expensify reports, expenses and policies through MCP tools.', mcpEndpoint: '/mcp', transport: 'streamable-http', tools: tools.length, auth: { model: 'broker-first', principalHeader, ...readiness, description: 'Every MCP request requires partner Bearer credentials or a signed broker principal.' } }));
  app.get('/health', (_req, res) => res.json({ status: 'ok', server: 'expensify-mcp-http', version: VERSION, tools: tools.length, transport: 'streamable-http', authModel: 'broker-first', provider: 'expensify', providerKind: 'static', ...readiness }));
  app.get('/_disabled/oauth-authorization-server', (_req, res) => res.status(404).json({ error: 'not_found' }));

  function makeServer(caller: Caller) {
    const server = new Server({ name: 'expensify-mcp-server', version: VERSION }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: tools.map(tool => ({ name: tool.name, description: tool.description, inputSchema: zodToJsonSchema(tool.inputSchema as any) as any })) }));
    server.setRequestHandler(CallToolRequestSchema, async request => {
      try {
        const tool = tools.find(tool => tool.name === request.params.name);
        if (!tool) return failure();
        let credential;
        if (caller.mode === 'raw') credential = caller.credential;
        else {
          const token = await broker.resolveToken(caller.principal);
          if (token.status === 'not_connected') return { content: [{ type: 'text' as const, text: JSON.stringify({ status: 'connection_required', provider: 'expensify', message: 'Connect Expensify through your platform broker, then retry.', connectUrl: broker.connectUrl }) }] };
          if (token.status === 'error') return failure();
          credential = parseCredential(token.accessToken);
        }
        const client = new ExpensifyClient(credential.partnerUserID, credential.partnerUserSecret, outbound);
        const result = await tool.handler(client, request.params.arguments ?? {});
        return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
      } catch { return failure(); }
    });
    return server;
  }

  // Authentication precedes body parsing, lookup and SDK dispatch for every method.
  app.use('/mcp', (req, res, next) => {
    try { res.locals.caller = authenticate(req.headers); next(); } catch (error) { next(error); }
  }, express.json({ limit: '100kb' }));

  async function dispatch(req: express.Request, res: express.Response) {
    const caller = res.locals.caller as Caller;
    const protocol = req.headers['mcp-protocol-version'];
    if (protocol !== undefined && (typeof protocol !== 'string' || !SUPPORTED_PROTOCOL_VERSIONS.includes(protocol))) {
      throw new AdmissionError(400, 'Unsupported protocol version.');
    }
    // Keep SDK validation errors from echoing submitted values in protocol responses.
    if (req.method === 'POST') {
      const messages = Array.isArray(req.body) ? req.body : [req.body];
      if (!messages.length || messages.some(message =>
        !JSONRPCMessageSchema.safeParse(message).success
        || (message.method === 'initialize' && !InitializeRequestSchema.safeParse(message).success)
        || (message.method === 'tools/call' && !CallToolRequestSchema.safeParse(message).success))) {
        throw new AdmissionError(400, 'Invalid MCP message.');
      }
    }
    const id = req.headers['mcp-session-id'];
    if (id !== undefined) {
      const session = typeof id === 'string' ? sessions.get(id) : undefined;
      if (!session) { res.status(404).json({ error: 'Session not found.' }); return; }
      if (caller.binding !== session.binding) { res.status(403).json({ error: 'Session not available.' }); return; }
      // The SDK performs protocol validation and owns GET/DELETE lifecycle callbacks.
      await session.transport.handleRequest(req, res, req.body);
      return;
    }
    if (req.method !== 'POST') { res.status(400).json({ error: 'Initialization required.' }); return; }
    const server = makeServer(caller);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: randomUUID,
      onsessioninitialized: id => { sessions.set(id, { server, transport, binding: caller.binding }); },
    });
    server.onclose = () => { if (transport.sessionId) sessions.delete(transport.sessionId); };
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
      if (!transport.sessionId || res.statusCode >= 400) await server.close();
    } catch (error) { await server.close().catch(() => {}); throw error; }
  }
  for (const method of ['post', 'get', 'delete'] as const) {
    app[method]('/mcp', (req, res, next) => { void dispatch(req, res).catch(next); });
  }
  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    if (res.headersSent) { res.end(); return; }
    if (error instanceof AdmissionError) { res.status(error.status).json({ error: error.message }); return; }
    const status = (error as { status?: number })?.status;
    res.status(status === 413 ? 413 : status === 400 ? 400 : 500).json({ error: status === 413 ? 'Request too large.' : status === 400 ? 'Invalid request.' : 'Request failed.' });
  });
  return { app, async close() { await Promise.allSettled([...sessions.values()].map(s => s.server.close())); sessions.clear(); } };
}
