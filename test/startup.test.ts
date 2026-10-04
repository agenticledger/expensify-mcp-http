import test from 'node:test';
import assert from 'node:assert/strict';
import { startProcess } from './process-fixture.js';
import { initialize } from './fixture.js';

test('compiled production entrypoint survives malformed secrets and remains usable without broker', async t => {
  const f = await startProcess(t, false);
  const health = await (await fetch(`${f.url}/health`)).json() as any;
  assert.equal(health.brokerConfigured, false); assert.equal(health.brokerReady, false); assert.equal(health.rawBearerAvailable, true);
  assert.doesNotMatch(JSON.stringify(health), /secret|namespace|principal/i);
  const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
  for (const credential of ['PRIVATE-CANARY', '{"id":3,"secret":"PRIVATE-CANARY"}', '{"id":']) {
    const res = await fetch(`${f.url}/mcp`, { method: 'POST', headers: { ...headers, Authorization: `Bearer ${credential}` }, body: JSON.stringify(initialize) });
    assert.equal(res.status, 400); assert.doesNotMatch(await res.text(), /PRIVATE-CANARY/);
    assert.equal((await fetch(`${f.url}/health`)).status, 200);
  }
  const initialized = await fetch(`${f.url}/mcp`, { method: 'POST', headers: { ...headers, Authorization: 'Bearer fixture:PRIVATE-CANARY' }, body: JSON.stringify(initialize) });
  assert.equal(initialized.status, 200);
  const id = initialized.headers.get('mcp-session-id')!; assert.ok(id); await initialized.text();
  const listing = await fetch(`${f.url}/mcp`, { method: 'POST', headers: { ...headers, Authorization: 'Bearer fixture:PRIVATE-CANARY', 'mcp-session-id': id }, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }) });
  assert.equal(listing.status, 200); assert.match(await listing.text(), /policies_list/);
  assert.doesNotMatch(f.output(), /PRIVATE-CANARY/); assert.ok(!f.output().includes(id));
});
