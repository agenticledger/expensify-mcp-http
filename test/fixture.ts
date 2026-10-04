import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createApp } from '../src/app.js';

export const hmacKey = 'fixture-hmac';
export const raw = (user = 'A') => ({ Authorization: `Bearer ${user}:secret-${user}` });
export const signed = (principal = 'A') => ({ 'x-broker-principal': principal, 'x-broker-principal-sig': createHmac('sha256', hmacKey).update(principal).digest('base64url') });
export async function fixture(t: any, options: { configured?: boolean; hmacKey?: string } = {}) {
  const calls: { kind: string; identity: string; payload: any }[] = [];
  const state = { brokerStatus: 200, providerStatus: 200, reject: false, badToken: false };
  const outbound: typeof fetch = async (url, init) => {
    if (state.reject) throw new Error('PRIVATE-CANARY');
    if (String(url) === 'https://fixture.invalid/token') {
      const headers = new Headers(init?.headers);
      assert.equal(headers.get('authorization'), 'Bearer fixture-install');
      const payload = jwt.verify(headers.get('x-broker-token')!, 'fixture-jwt', { algorithms: ['HS256'] }) as any;
      assert.equal(payload.clientNamespace, 'fixture-namespace');
      calls.push({ kind: 'broker', identity: payload.principal, payload: JSON.parse(String(init?.body)) });
      return new Response(state.brokerStatus === 200 ? JSON.stringify({ accessToken: state.badToken ? 'PRIVATE-CANARY' : `${payload.principal}:secret-${payload.principal}` }) : 'PRIVATE-CANARY', { status: state.brokerStatus });
    }
    assert.equal(String(url), 'https://integrations.expensify.com/Integration-Server/ExpensifyIntegrations');
    const payload = JSON.parse(new URLSearchParams(String(init?.body)).get('requestJobDescription')!);
    calls.push({ kind: 'provider', identity: payload.credentials.partnerUserID, payload });
    await new Promise(resolve => setTimeout(resolve, payload.credentials.partnerUserID === 'A' ? 15 : 1));
    return new Response(state.providerStatus === 200 ? JSON.stringify({ policies: [payload.credentials.partnerUserID] }) : 'PRIVATE-CANARY', { status: state.providerStatus });
  };
  const runtime = createApp({ broker: { baseUrl: 'https://fixture.invalid', installBearer: options.configured === false ? '' : 'fixture-install', jwtKey: 'fixture-jwt', clientNamespace: 'fixture-namespace' }, hmacKey: options.hmacKey ?? hmacKey, outboundFetch: outbound });
  const http = runtime.app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => http.once('listening', resolve));
  const url = new URL(`http://127.0.0.1:${(http.address() as any).port}/mcp`);
  t.after(async () => { await runtime.close(); http.closeAllConnections(); await new Promise<void>(resolve => http.close(() => resolve())); });
  async function connect(headers: Record<string, string>) {
    const client = new Client({ name: 'fixture', version: '1' });
    const transport = new StreamableHTTPClientTransport(url, { requestInit: { headers } });
    await client.connect(transport);
    t.after(() => client.close());
    return { client, transport };
  }
  async function request(method: string, headers: Record<string, string>, sessionId?: string, body?: unknown) {
    return fetch(url, { method, headers: { accept: 'application/json, text/event-stream', 'content-type': 'application/json', 'mcp-protocol-version': '2025-11-25', ...headers, ...(sessionId ? { 'mcp-session-id': sessionId } : {}) }, ...(body !== undefined ? { body: typeof body === 'string' ? body : JSON.stringify(body) } : {}), signal: AbortSignal.timeout(3000) });
  }
  return { url, calls, state, connect, request };
}

export const initialize = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'fixture', version: '1' } } };
