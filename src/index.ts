#!/usr/bin/env node
/**
 * Expensify MCP Server — Exposed via Streamable HTTP
 *
 * Auth model: Client sends their Expensify partner credentials as Bearer token.
 * Format: Bearer partnerUserID:partnerUserSecret
 * The server extracts both and creates a per-session API client.
 * No credentials are stored on the server.
 */

import { randomUUID, createHash } from 'node:crypto';
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

function zodToJsonSchema(schema: any): any {
  return _zodToJsonSchema(schema);
}

const PORT = parseInt(process.env.PORT || '3100', 10);
const SERVER_BASE_URL =
  process.env.SERVER_BASE_URL || `http://localhost:${PORT}`;

const app = express();
app.use(express.json());

const SLUG = 'expensify';

app.use(express.urlencoded({ extended: false }));

// --- OAuth token store (in-memory, ephemeral) ---
const TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour

interface OAuthToken {
  apiKey: string;
  expiresAt: number;
}

const oauthTokens = new Map<string, OAuthToken>();

setInterval(() => {
  const now = Date.now();
  for (const [token, data] of oauthTokens) {
    if (now > data.expiresAt) oauthTokens.delete(token);
  }
}, 10 * 60 * 1000);

// --- OAuth authorization code store (in-memory, ephemeral) ---
const AUTH_CODE_TTL_MS = 5 * 60 * 1000;

interface AuthCode {
  apiKey: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  redirectUri: string;
  expiresAt: number;
}

const authCodes = new Map<string, AuthCode>();

setInterval(() => {
  const now = Date.now();
  for (const [code, data] of authCodes) {
    if (now > data.expiresAt) authCodes.delete(code);
  }
}, 2 * 60 * 1000);

function verifyPKCE(codeVerifier: string, codeChallenge: string, method: string): boolean {
  if (method === 'S256') {
    const hash = createHash('sha256').update(codeVerifier).digest('base64url');
    return hash === codeChallenge;
  }
  if (method === 'plain') return codeVerifier === codeChallenge;
  return false;
}


// --- OAuth 2.0 Discovery ---
app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: SERVER_BASE_URL,
    authorization_endpoint: `${SERVER_BASE_URL}/authorize`,
    token_endpoint: `${SERVER_BASE_URL}/oauth/token`,
    revocation_endpoint: `${SERVER_BASE_URL}/oauth/revoke`,
    registration_endpoint: `${SERVER_BASE_URL}/oauth/register`,
    grant_types_supported: ['authorization_code', 'client_credentials'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256'],
    service_documentation: `https://financemcps.agenticledger.ai/${SLUG}/`,
  });
});

// --- OAuth 2.0 Dynamic Client Registration ---
app.post('/oauth/register', (req, res) => {
  res.status(201).json({
    client_id: SLUG,
    client_name: req.body?.client_name || 'MCP Client',
    redirect_uris: req.body?.redirect_uris || [],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  });
});

// --- OAuth 2.0 Authorization Endpoint ---
app.get('/authorize', (req, res) => {
  const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state, scope } = req.query;
  if (response_type !== 'code') {
    res.status(400).json({ error: 'unsupported_response_type' });
    return;
  }
  res.send(AUTHORIZE_HTML(client_id as string || '', redirect_uri as string || '', code_challenge as string || '', code_challenge_method as string || 'S256', state as string || '', scope as string || ''));
});

app.post('/authorize', (req, res) => {
  const { api_key, client_id, redirect_uri, code_challenge, code_challenge_method, state } = req.body;
  if (!api_key) { res.status(400).send('API key is required'); return; }
  if (!redirect_uri) { res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri is required' }); return; }
  const code = `authcode_${randomUUID().replace(/-/g, '')}`;
  authCodes.set(code, {
    apiKey: api_key,
    codeChallenge: code_challenge || '',
    codeChallengeMethod: code_challenge_method || 'S256',
    redirectUri: redirect_uri,
    expiresAt: Date.now() + AUTH_CODE_TTL_MS,
  });
  const url = new URL(redirect_uri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);
  res.redirect(302, url.toString());
});

// --- OAuth 2.0 Token Exchange ---
app.post('/oauth/token', (req, res) => {
  const { grant_type } = req.body;
  if (grant_type === 'authorization_code') {
    const { code, code_verifier, redirect_uri } = req.body;
    if (!code) { res.status(400).json({ error: 'invalid_request', error_description: 'code is required' }); return; }
    const entry = authCodes.get(code);
    if (!entry) { res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code not found or expired' }); return; }
    authCodes.delete(code);
    if (Date.now() > entry.expiresAt) { res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code expired' }); return; }
    if (redirect_uri && redirect_uri !== entry.redirectUri) { res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' }); return; }
    if (entry.codeChallenge) {
      if (!code_verifier) { res.status(400).json({ error: 'invalid_request', error_description: 'code_verifier is required for PKCE' }); return; }
      if (!verifyPKCE(code_verifier, entry.codeChallenge, entry.codeChallengeMethod)) { res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' }); return; }
    }
    const accessToken = `mcp_${randomUUID().replace(/-/g, '')}`;
    oauthTokens.set(accessToken, { apiKey: entry.apiKey, expiresAt: Date.now() + TOKEN_TTL_MS });
    res.json({ access_token: accessToken, token_type: 'bearer', expires_in: TOKEN_TTL_MS / 1000 });
    return;
  }
  if (grant_type === 'client_credentials') {
    const { client_id, client_secret } = req.body;
    if (client_id !== SLUG) { res.status(400).json({ error: 'invalid_client', error_description: `client_id must be "${SLUG}"` }); return; }
    if (!client_secret) { res.status(400).json({ error: 'invalid_request', error_description: 'client_secret is required (your API key)' }); return; }
    const accessToken = `mcp_${randomUUID().replace(/-/g, '')}`;
    oauthTokens.set(accessToken, { apiKey: client_secret, expiresAt: Date.now() + TOKEN_TTL_MS });
    res.json({ access_token: accessToken, token_type: 'bearer', expires_in: TOKEN_TTL_MS / 1000 });
    return;
  }
  res.status(400).json({ error: 'unsupported_grant_type', error_description: 'Supported: authorization_code, client_credentials' });
});

// --- OAuth 2.0 Token Revocation ---
app.post('/oauth/revoke', (req, res) => {
  const { token } = req.body;
  if (token) oauthTokens.delete(token);
  res.status(200).json({ status: 'revoked' });
});

// --- Root route with content negotiation ---
app.get('/', (_req, res) => {
  const accept = _req.headers.accept || '';

  if (accept.includes('text/html')) {
    res.type('html').send(renderHtmlPage());
    return;
  }

  // Default: JSON
  res.json({
    name: 'Expensify MCP Server',
    provider: 'AgenticLedger',
    version: '1.0.0',
    description:
      'Access Expensify expense reports, policies, categories, tags, and reconciliation through MCP tools.',
    mcpEndpoint: '/mcp',
    transport: 'streamable-http',
    tools: tools.length,
    auth: {
      type: 'dual-mode',
      description:
        'Pass your Expensify partner credentials as the Bearer token in the format partnerUserID:partnerUserSecret. No credentials are stored on this server.',
      header: 'Authorization: Bearer <partnerUserID>:<partnerUserSecret>',
      howToGetKey:
        'Generate partner credentials at https://www.expensify.com/tools/integrations/',
    },
    configTemplate: {
      mcpServers: {
        expensify: {
          url: `${SERVER_BASE_URL}/mcp`,
          headers: {
            Authorization: 'Bearer <partnerUserID>:<partnerUserSecret>',
          },
        },
      },
    },
    links: {
      health: '/health',
      documentation: 'https://financemcps.agenticledger.ai/expensify/',
    },
  });
});

function renderHtmlPage(): string {
  const configTemplate = JSON.stringify(
    {
      mcpServers: {
        expensify: {
          url: `${SERVER_BASE_URL}/mcp`,
          headers: {
            Authorization: 'Bearer YOUR_PARTNER_USER_ID:YOUR_PARTNER_USER_SECRET',
          },
        },
      },
    },
    null,
    2,
  );

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Expensify MCP Server — AgenticLedger</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap" rel="stylesheet" />
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'DM Sans',sans-serif;background:#f8fafc;color:#1e293b;line-height:1.6}
    .header{background:#fff;border-bottom:1px solid #e2e8f0;padding:1rem 2rem;display:flex;align-items:center;gap:0.75rem}
    .header img{height:36px}
    .header span{font-weight:700;font-size:1.1rem;color:#2563EB}
    .container{max-width:720px;margin:2rem auto;padding:0 1.5rem}
    h1{font-size:1.75rem;font-weight:700;color:#0f172a;margin-bottom:0.25rem}
    .subtitle{color:#64748b;margin-bottom:2rem}
    .card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:1.5rem;margin-bottom:1.5rem}
    .card h2{font-size:1.1rem;font-weight:600;margin-bottom:0.75rem;color:#0f172a}
    .steps{padding-left:1.25rem}
    .steps li{margin-bottom:0.5rem}
    a{color:#2563EB;text-decoration:none}
    a:hover{text-decoration:underline}
    label{display:block;font-weight:500;margin-bottom:0.4rem}
    input[type="text"]{width:100%;padding:0.6rem 0.75rem;font-size:0.95rem;font-family:inherit;border:1px solid #cbd5e1;border-radius:8px;outline:none;transition:border-color .15s;margin-bottom:0.5rem}
    input[type="text"]:focus{border-color:#2563EB;box-shadow:0 0 0 3px rgba(37,99,235,.12)}
    .code-block{position:relative;background:#0f172a;color:#e2e8f0;border-radius:8px;padding:1rem;font-family:'Fira Mono','Consolas',monospace;font-size:0.85rem;white-space:pre;overflow-x:auto;line-height:1.5;margin-top:0.75rem}
    .copy-btn{position:absolute;top:0.5rem;right:0.5rem;background:#2563EB;color:#fff;border:none;border-radius:6px;padding:0.35rem 0.75rem;font-size:0.8rem;font-family:inherit;cursor:pointer;transition:background .15s}
    .copy-btn:hover{background:#1d4ed8}
    .copy-btn.copied{background:#16a34a}
    .badges{display:flex;flex-wrap:wrap;gap:0.75rem;margin-top:0.5rem}
    .badge{display:flex;align-items:center;gap:0.4rem;background:#f0f9ff;border:1px solid #bae6fd;color:#0369a1;border-radius:999px;padding:0.3rem 0.85rem;font-size:0.82rem;font-weight:500}
    .badge svg{width:14px;height:14px;flex-shrink:0}
    .footer{text-align:center;color:#94a3b8;font-size:0.82rem;padding:2rem 0}
  </style>
</head>
<body>
  <div class="header">
    <img src="/static/logo.png" alt="AgenticLedger" onerror="this.style.display='none'" />
    <span>AgenticLedger</span>
  </div>

  <div class="container">
    <h1>Expensify MCP Server</h1>
    <p class="subtitle">Access Expensify expense reports, policies, categories, tags, and reconciliation through MCP tools.</p>

    <div class="card">
      <h2>How to get your Expensify credentials</h2>
      <ol class="steps">
        <li>Log in to <a href="https://www.expensify.com" target="_blank" rel="noopener">Expensify</a>.</li>
        <li>Go to <strong>Settings &rarr; Workspaces &rarr; [Your Workspace]</strong>.</li>
        <li>Navigate to <a href="https://www.expensify.com/tools/integrations/" target="_blank" rel="noopener"><strong>Integrations</strong></a>.</li>
        <li>Copy your <strong>partnerUserID</strong> and <strong>partnerUserSecret</strong>.</li>
        <li>Paste them below, separated by a colon.</li>
      </ol>
    </div>

    <div class="card">
      <h2>Generate your MCP config</h2>
      <label for="userId">Partner User ID</label>
      <input type="text" id="userId" placeholder="aa_your_partner_id..." autocomplete="off" spellcheck="false" />
      <label for="userSecret">Partner User Secret</label>
      <input type="text" id="userSecret" placeholder="your_partner_secret..." autocomplete="off" spellcheck="false" />
      <div class="code-block" id="configBlock">${escapeHtml(configTemplate)}</div>
      <button class="copy-btn" id="copyBtn" onclick="copyConfig()">Copy</button>
    </div>

    <div class="card">
      <h2>Trust &amp; Security</h2>
      <div class="badges">
        <span class="badge">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          No credentials stored
        </span>
        <span class="badge">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
          Stateless &amp; per-session
        </span>
        <span class="badge">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
          Bearer passthrough
        </span>
      </div>
    </div>

    <div class="footer">Powered by AgenticLedger &middot; ${tools.length} tools available &middot; <a href="https://financemcps.agenticledger.ai/" style="color:#2563EB;text-decoration:none">Explore Other MCPs</a></div>
  </div>

  <script>
    const userIdInput = document.getElementById('userId');
    const userSecretInput = document.getElementById('userSecret');
    const configBlock = document.getElementById('configBlock');
    const baseUrl = ${JSON.stringify(SERVER_BASE_URL)};

    function buildConfig() {
      const uid = userIdInput.value.trim();
      const secret = userSecretInput.value.trim();
      const token = (uid && secret) ? uid + ':' + secret : 'YOUR_PARTNER_USER_ID:YOUR_PARTNER_USER_SECRET';
      return JSON.stringify({
        mcpServers: {
          expensify: {
            url: baseUrl + '/mcp',
            headers: {
              Authorization: 'Bearer ' + token
            }
          }
        }
      }, null, 2);
    }

    userIdInput.addEventListener('input', function () {
      configBlock.textContent = buildConfig();
    });
    userSecretInput.addEventListener('input', function () {
      configBlock.textContent = buildConfig();
    });

    function copyConfig() {
      const btn = document.getElementById('copyBtn');
      navigator.clipboard.writeText(configBlock.textContent).then(function () {
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(function () { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
      });
    }
  </script>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Health check (no auth required)
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    server: 'expensify-mcp-http',
    version: '1.0.0',
    tools: tools.length,
    transport: 'streamable-http',
    auth: 'dual-mode',
    auth_modes: ['bearer-passthrough', 'oauth-authorization-code', 'oauth-client-credentials'],
  });
});

// --- Extract Bearer token and parse credentials ---
function extractCredentials(req: express.Request): { partnerUserID: string; partnerUserSecret: string } | null {
  const auth = req.headers.authorization;
  if (!auth) return null;
  const token = auth.replace(/^Bearer\s+/i, '');
  const colonIndex = token.indexOf(':');
  if (colonIndex === -1) return null;
  const partnerUserID = token.substring(0, colonIndex);
  const partnerUserSecret = token.substring(colonIndex + 1);
  if (!partnerUserID || !partnerUserSecret) return null;
  return { partnerUserID, partnerUserSecret };
}

// --- Per-session state ---
interface SessionState {
  server: Server;
  transport: StreamableHTTPServerTransport;
  client: ExpensifyClient;
}

const sessions = new Map<string, SessionState>();

function createMCPServer(client: ExpensifyClient): Server {
  const server = new Server(
    { name: 'expensify-mcp-server', version: '1.0.0' },
    { capabilities: { tools: {} } }
  );

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

    if (!tool) {
      throw new Error(`Unknown tool: ${name}`);
    }

    try {
      const result = await tool.handler(client, args as any);
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [{ type: 'text' as const, text: `Error: ${message}` }],
        isError: true,
      };
    }
  });

  return server;
}

// --- Streamable HTTP endpoint ---
app.post('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;

  // Existing session
  if (sessionId && sessions.has(sessionId)) {
    const { transport } = sessions.get(sessionId)!;
    await transport.handleRequest(req, res, req.body);
    return;
  }

  // New session — requires Bearer token
  const creds = extractCredentials(req);
  if (!creds) {
    res.status(401).json({
      error: 'Missing or invalid Authorization header. Use: Bearer <partnerUserID>:<partnerUserSecret>',
    });
    return;
  }

  // Create per-session API client with the user's credentials
  const client = new ExpensifyClient(creds.partnerUserID, creds.partnerUserSecret);

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
  });

  const server = createMCPServer(client);

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
    sessions.set(newSessionId, { server, transport, client });
    console.log(`[mcp] New session: ${newSessionId}`);
  }
});

// GET /mcp — SSE stream for server notifications
app.get('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (!sessionId || !sessions.has(sessionId)) {
    res.status(400).json({ error: 'Invalid or missing session. Send initialization POST first.' });
    return;
  }
  const { transport } = sessions.get(sessionId)!;
  await transport.handleRequest(req, res);
});

// DELETE /mcp — close session
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

// ==================== OAUTH AUTHORIZE CONSENT PAGE ====================
function AUTHORIZE_HTML(clientId: string, redirectUri: string, codeChallenge: string, codeChallengeMethod: string, state: string, scope: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize \u2014 Expensify MCP</title>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root{--primary:#2563EB;--primary-dark:#1D4ED8;--primary-50:#EFF6FF;--fg:#0F172A;--muted:#64748B;--surface:#F8FAFC;--border:#E2E8F0;--success:#10B981;}
    *{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:"DM Sans",sans-serif;color:var(--fg);min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--surface);background-image:linear-gradient(135deg,var(--primary-50) 0%,var(--surface) 50%,#F0F9FF 100%);}
    .card{background:#fff;border:1px solid var(--border);border-radius:16px;padding:40px;max-width:480px;width:100%;margin:20px;box-shadow:0 1px 3px rgba(0,0,0,.04),0 8px 24px rgba(0,0,0,.06);}
    .header{display:flex;align-items:center;gap:14px;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid var(--border);}
    .header img{height:36px;}.header span{font-size:18px;font-weight:700;}
    .consent-msg{font-size:14px;color:var(--muted);margin-bottom:20px;line-height:1.6;}.consent-msg strong{color:var(--fg);}
    .key-label{font-size:13px;font-weight:600;margin-bottom:8px;display:block;}
    .key-input{width:100%;padding:12px 16px;border:2px solid var(--border);border-radius:10px;font-family:"JetBrains Mono",monospace;font-size:13px;margin-bottom:6px;}.key-input:focus{outline:none;border-color:var(--primary);}
    .key-hint{font-size:11px;color:var(--muted);margin-bottom:24px;}
    .btn-authorize{width:100%;padding:14px;background:var(--primary);color:#fff;border:none;border-radius:10px;font-family:"DM Sans",sans-serif;font-size:15px;font-weight:600;cursor:pointer;}.btn-authorize:hover{background:var(--primary-dark);}.btn-authorize:disabled{background:var(--border);cursor:not-allowed;}
    .trust-row{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--muted);margin-top:16px;}.trust-row svg{width:14px;height:14px;color:var(--success);}
    .footer{margin-top:20px;padding-top:16px;border-top:1px solid var(--border);text-align:center;font-size:11px;color:var(--muted);}
  </style>
</head>
<body>
  <div class="card">
    <div class="header"><img src="/static/logo.png" alt="AgenticLedger"><span>Expensify MCP</span></div>
    <div class="consent-msg">An application wants to connect to <strong>Expensify MCP Server</strong> on your behalf. Enter your API key to authorize access.</div>
    <form method="POST" action="/authorize">
      <input type="hidden" name="client_id" value="${clientId}">
      <input type="hidden" name="redirect_uri" value="${redirectUri}">
      <input type="hidden" name="code_challenge" value="${codeChallenge}">
      <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}">
      <input type="hidden" name="state" value="${state}">
      <input type="hidden" name="scope" value="${scope}">
      <label class="key-label">Your API Key</label>
      <input type="password" class="key-input" name="api_key" id="apiKey" placeholder="Enter your API key" required autofocus oninput="document.getElementById('authBtn').disabled=!this.value">
      <div class="key-hint">Your key creates a temporary token. It is not stored permanently.</div>
      <button type="submit" class="btn-authorize" id="authBtn" disabled>Authorize</button>
    </form>
    <div class="trust-row"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>No credentials stored permanently</div>
    <div class="footer">Powered by AgenticLedger</div>
  </div>
</body>
</html>`;
}


app.listen(PORT, () => {
  console.log(`Expensify MCP HTTP Server running on port ${PORT}`);
  console.log(`  MCP endpoint:   http://localhost:${PORT}/mcp`);
  console.log(`  Health check:   http://localhost:${PORT}/health`);
  console.log(`  Tools:          ${tools.length}`);
  console.log(`  Transport:      Streamable HTTP`);
  console.log(`  Auth:           Bearer passthrough (client provides partnerUserID:partnerUserSecret)`);
});
// OAuth upgrade 2026-03-19T00:52:18Z
