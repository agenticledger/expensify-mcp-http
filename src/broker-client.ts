/**
 * Connections-Broker client (auth model "B" — broker-first).
 *
 * This MCP holds ZERO provider secrets. The only secret it carries is a broker
 * *install identity* (installBearer + JWT signing key from the broker's /register),
 * which merely grants "ask MY broker for a credential scoped to this caller". It
 * cannot touch any provider OAuth app or any other account's vault.
 *
 * Per request the MCP:
 *   1. derives a `principal` (see index.ts — gateway header or install fallback),
 *   2. signs a short-lived HS256 JWT { clientNamespace, principal },
 *   3. calls the broker (POST /token) to resolve a ready-to-use credential,
 *   4. calls the provider API directly with it.
 *
 * Works identically for OAuth and `kind:"static"` (API-key) providers — the broker
 * returns the right credential shape in `accessToken` either way (for multi-field
 * static providers it is a JSON string the caller parses).
 *
 * Contract: ~/Desktop/APPs/connections-broker/INTEGRATION.md
 */

import jwt from 'jsonwebtoken';

const BROKER_BASE_URL = (process.env.BROKER_BASE_URL || 'https://connectionsbroker.agenticledger.ai').replace(/\/$/, '');
const INSTALL_BEARER = process.env.BROKER_INSTALL_BEARER || '';
const JWT_KEY = process.env.BROKER_JWT_KEY || '';
const CLIENT_NAMESPACE = process.env.BROKER_CLIENT_NAMESPACE || '';

/** The provider name as seeded in the broker (PROVIDER_SEED). */
const PROVIDER = 'expensify';
/** 'oauth' -> /connect returns an authorizeUrl; 'static' -> user pastes a key via /credential. */
const PROVIDER_KIND: 'oauth' | 'static' = 'static';

/** True only when all three install-identity secrets are present. */
export const brokerConfigured = Boolean(INSTALL_BEARER && JWT_KEY && CLIENT_NAMESPACE);
export const brokerBaseUrl = BROKER_BASE_URL;
export const brokerClientNamespace = CLIENT_NAMESPACE;
export const brokerProvider = PROVIDER;
export const brokerProviderKind = PROVIDER_KIND;

function signBrokerToken(principal: string): string {
  return jwt.sign(
    { clientNamespace: CLIENT_NAMESPACE, principal },
    JWT_KEY,
    { algorithm: 'HS256', expiresIn: '60s' }
  );
}

async function brokerFetch(path: string, principal: string, body: unknown): Promise<Response> {
  return fetch(`${BROKER_BASE_URL}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${INSTALL_BEARER}`,
      'X-Broker-Token': signBrokerToken(principal),
    },
    body: JSON.stringify(body),
  });
}

export type TokenResult =
  | { status: 'connected'; accessToken: string; expiresAt: string | null }
  | { status: 'not_connected' }
  | { status: 'error'; message: string };

/**
 * Resolve the caller's provider credential from the broker.
 * 404 -> the caller hasn't connected yet (connect-on-first-call).
 * For static providers `accessToken` is the stored API key (verbatim, or a JSON
 * string for multi-field providers).
 */
export async function resolveToken(principal: string, account = ''): Promise<TokenResult> {
  try {
    const res = await brokerFetch('/token', principal, { provider: PROVIDER, ...(account ? { account } : {}) });
    if (res.status === 404) return { status: 'not_connected' };
    if (!res.ok) return { status: 'error', message: `broker /token -> ${res.status} ${await res.text()}` };
    const data = (await res.json()) as { accessToken?: string; expiresAt?: string | null };
    if (!data.accessToken) return { status: 'error', message: 'broker /token returned no credential' };
    return { status: 'connected', accessToken: data.accessToken, expiresAt: data.expiresAt ?? null };
  } catch (err) {
    return { status: 'error', message: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Build the connect-on-first-call payload. OAuth providers get a one-time
 * authorizeUrl from /connect; static (API-key) providers are connected by pasting
 * a key through the platform's broker /credential flow, so we surface the broker
 * connect entry point rather than an OAuth URL.
 */
export async function startConnect(
  principal: string,
  account = ''
): Promise<{ authorizeUrl: string } | { error: string }> {
  if (PROVIDER_KIND === 'static') {
    return { authorizeUrl: `${BROKER_BASE_URL}/connect?provider=${encodeURIComponent(PROVIDER)}` };
  }
  try {
    const res = await brokerFetch('/connect', principal, { provider: PROVIDER, ...(account ? { account } : {}) });
    if (!res.ok) return { error: `broker /connect -> ${res.status} ${await res.text()}` };
    const data = (await res.json()) as { authorizeUrl?: string };
    if (!data.authorizeUrl) return { error: 'broker /connect returned no authorizeUrl' };
    return { authorizeUrl: data.authorizeUrl };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}
