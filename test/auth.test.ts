import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createAuthenticator, parseCredential, AdmissionError } from '../src/auth.js';

const config = { brokerConfigured: true, principalHeader: 'x-broker-principal', hmacKey: 'fixture-hmac' };
const signed = (principal: string) => ({ 'x-broker-principal': principal, 'x-broker-principal-sig': createHmac('sha256', config.hmacKey).update(principal).digest('base64url') });
for (const credential of ['id:secret:more', '{"partnerUserID":"id","partnerUserSecret":"secret:more"}', '{"id":"id","secret":"secret:more"}']) {
  test(`parses supported credential format ${credential.startsWith('{') ? 'JSON' : 'colon'}`, () => assert.deepEqual(parseCredential(credential), { partnerUserID: 'id', partnerUserSecret: 'secret:more' }));
}
for (const value of ['malformed', '{"id":', '{}', '{"id":3,"secret":"s"}', '{"id":"i","secret":null}', ':secret', 'id:', 'id: ', 'x'.repeat(8193)]) {
  test(`rejects malformed credential #${value.length}`, () => assert.throws(() => parseCredential(value), e => e instanceof AdmissionError && e.status === 400));
}
test('bindings separate modes, identities and app instances; canonical raw encodings agree', () => {
  const authenticate = createAuthenticator(config);
  const a = authenticate({ authorization: 'Bearer id:secret' });
  const b = authenticate({ authorization: 'Bearer {"id":"id","secret":"secret"}' });
  assert.equal(a.binding, b.binding);
  assert.notEqual(a.binding, authenticate({ authorization: 'Bearer id:changed' }).binding);
  assert.notEqual(a.binding, authenticate(signed('id:secret')).binding);
  assert.notEqual(a.binding, createAuthenticator(config)({ authorization: 'Bearer id:secret' }).binding);
});
for (const headers of [{}, { 'x-broker-principal': ' ' }, { 'x-broker-principal': 'a' }, { 'x-broker-principal-sig': signed('a')['x-broker-principal-sig'] }, { ...signed('a'), 'x-broker-principal': 'b' }, { ...signed('a'), 'x-broker-principal-sig': 'not-base64' }, { authorization: 'Basic id:secret', ...signed('a') }, { authorization: 'Bearer', ...signed('a') }]) {
  test('rejects missing/forged broker proof or invalid explicit scheme', () => assert.throws(() => createAuthenticator(config)(headers), e => e instanceof AdmissionError && e.status === 401));
}
test('missing broker config/key closes only broker mode; custom principal header works', () => {
  for (const cfg of [{ ...config, hmacKey: '' }, { ...config, brokerConfigured: false }]) {
    const authenticate = createAuthenticator(cfg);
    assert.throws(() => authenticate(signed('a')), e => e instanceof AdmissionError && e.status === 503);
    assert.equal(authenticate({ authorization: 'Bearer id:secret' }).mode, 'raw');
  }
  assert.equal(createAuthenticator({ ...config, principalHeader: 'X-Custom' })({ 'x-custom': 'a', 'x-broker-principal-sig': signed('a')['x-broker-principal-sig'] }).mode, 'broker');
});
