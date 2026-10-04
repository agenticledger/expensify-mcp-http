import jwt from 'jsonwebtoken';

export type BrokerConfig = { baseUrl: string; installBearer: string; jwtKey: string; clientNamespace: string };
export type TokenResult =
  | { status: 'connected'; accessToken: string }
  | { status: 'not_connected' }
  | { status: 'error' };

export function brokerConfigFromEnv(env = process.env): BrokerConfig {
  return {
    baseUrl: (env.BROKER_BASE_URL || 'https://connectionsbroker.agenticledger.ai').replace(/\/$/, ''),
    installBearer: env.BROKER_INSTALL_BEARER || '', jwtKey: env.BROKER_JWT_KEY || '',
    clientNamespace: env.BROKER_CLIENT_NAMESPACE || '',
  };
}

/** Broker authenticates this install; the HTTP boundary must authenticate its principal. */
export function createBrokerClient(config: BrokerConfig, request: typeof fetch = fetch) {
  const configured = Boolean(config.installBearer && config.jwtKey && config.clientNamespace);
  return {
    configured,
    connectUrl: `${config.baseUrl}/connect?provider=expensify`,
    async resolveToken(principal: string): Promise<TokenResult> {
      try {
        const token = jwt.sign({ clientNamespace: config.clientNamespace, principal }, config.jwtKey, { algorithm: 'HS256', expiresIn: '60s' });
        const res = await request(`${config.baseUrl}/token`, {
          method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${config.installBearer}`, 'X-Broker-Token': token },
          body: JSON.stringify({ provider: 'expensify' }),
        });
        if (res.status === 404) { await res.body?.cancel(); return { status: 'not_connected' }; }
        if (!res.ok) { await res.body?.cancel(); return { status: 'error' }; }
        const data = await res.json() as { accessToken?: unknown };
        return typeof data.accessToken === 'string' && data.accessToken ? { status: 'connected', accessToken: data.accessToken } : { status: 'error' };
      } catch { return { status: 'error' }; }
    },
  };
}
