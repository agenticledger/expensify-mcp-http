import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';

export class AdmissionError extends Error {
  constructor(public readonly status: number, message: string) { super(message); }
}
export type PartnerCredential = { partnerUserID: string; partnerUserSecret: string };
export type Caller = { binding: string } & (
  | { mode: 'raw'; credential: PartnerCredential }
  | { mode: 'broker'; principal: string }
);
export type AuthConfig = { brokerConfigured: boolean; principalHeader: string; hmacKey: string };

export function parseCredential(value: string): PartnerCredential {
  const invalid = () => new AdmissionError(400, 'Invalid partner credential.');
  if (value.length > 8192) throw invalid();
  const raw = value.trim();
  let id: unknown, secret: unknown;
  if (raw.startsWith('{')) {
    let parsed;
    try { parsed = JSON.parse(raw); } catch { throw invalid(); }
    id = parsed.partnerUserID ?? parsed.id;
    secret = parsed.partnerUserSecret ?? parsed.secret;
  } else {
    const colon = raw.indexOf(':');
    if (colon < 0) throw invalid();
    id = raw.slice(0, colon); secret = raw.slice(colon + 1);
  }
  if (typeof id !== 'string' || !id.trim() || typeof secret !== 'string' || !secret.trim()) throw invalid();
  return { partnerUserID: id, partnerUserSecret: secret };
}

/** Each app owns a random key: credential fingerprints never leave process memory. */
export function createAuthenticator(config: AuthConfig) {
  const bindingKey = randomBytes(32);
  const fingerprint = (parts: string[]) => createHmac('sha256', bindingKey).update(JSON.stringify(parts)).digest('hex');
  return (headers: IncomingHttpHeaders): Caller => {
    if (headers.authorization !== undefined) {
      const match = /^Bearer[ \t]+(.+)$/i.exec(headers.authorization);
      if (!match) throw new AdmissionError(401, 'Bearer authentication required.');
      const credential = parseCredential(match[1]);
      return { mode: 'raw', credential, binding: fingerprint(['raw', credential.partnerUserID, credential.partnerUserSecret]) };
    }
    if (!config.brokerConfigured || !config.hmacKey.trim()) throw new AdmissionError(503, 'Signed broker authentication unavailable.');
    const raw = headers[config.principalHeader.toLowerCase()];
    const sig = headers['x-broker-principal-sig'];
    if (typeof raw !== 'string' || !raw.trim() || raw.length > 512 || typeof sig !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(sig)) {
      throw new AdmissionError(401, 'Invalid broker authentication.');
    }
    const principal = raw.trim();
    const expected = createHmac('sha256', config.hmacKey).update(principal).digest();
    const supplied = Buffer.from(sig, 'base64url');
    if (supplied.toString('base64url') !== sig || !timingSafeEqual(expected, supplied)) throw new AdmissionError(401, 'Invalid broker authentication.');
    return { mode: 'broker', principal, binding: fingerprint(['broker', principal]) };
  };
}
