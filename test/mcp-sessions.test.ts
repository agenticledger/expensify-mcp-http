import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, raw, signed, initialize } from './fixture.js';
const call = { jsonrpc: '2.0', id: 50, method: 'tools/call', params: { name: 'policies_list', arguments: {} } };
const resultText = (r: any) => r.content[0].text;
for (const mode of ['raw', 'broker'] as const) {
  test(`${mode}: real MCP lifecycle and cross-caller denials on every method`, async t => {
    const f = await fixture(t);
    const headers = mode === 'raw' ? raw : signed;
    const a = await f.connect(headers('A'));
    const b = await f.connect(headers('B'));
    assert.equal((await a.client.listTools()).tools.length, 13);
    assert.equal(resultText(await a.client.callTool({ name: 'policies_list', arguments: {} })), '{\n  "policies": [\n    "A"\n  ]\n}');
    for (const method of ['POST', 'GET', 'DELETE']) {
      for (const other of [{}, headers('B'), raw('changed'), mode === 'raw' ? signed('A') : raw('A')]) {
        const before = f.calls.length;
        const response = await f.request(method, other, a.transport.sessionId, method === 'POST' ? call : undefined);
        assert.ok([401, 403].includes(response.status), `${mode}/${method}: ${response.status}`);
        assert.equal(f.calls.length, before);
        assert.doesNotMatch(await response.text(), /secret-|PRIVATE-CANARY/);
      }
    }
    const simultaneous = await Promise.all([a.client.callTool({ name: 'policies_list', arguments: {} }), b.client.callTool({ name: 'policies_list', arguments: {} })]);
    assert.deepEqual(simultaneous.map(r => JSON.parse(resultText(r)).policies), [['A'], ['B']]);
    for (const record of f.calls.filter(c => c.kind === 'provider')) {
      assert.equal(record.payload.credentials.partnerUserSecret, `secret-${record.identity}`);
      assert.equal(record.payload.type, 'get'); assert.equal(record.payload.inputSettings.type, 'policyList');
    }
    const aId = a.transport.sessionId;
    await a.transport.terminateSession();
    assert.equal((await f.request('POST', headers('A'), aId, call)).status, 404);
    assert.equal((await b.client.listTools()).tools.length, 13);
    const replacement = await f.connect(headers('A'));
    assert.notEqual(replacement.transport.sessionId, aId);
  });
}
test('GET requires same headers and streams only to owning session', async t => {
  const f = await fixture(t);
  const initialized = await f.request('POST', raw(), undefined, initialize);
  const id = initialized.headers.get('mcp-session-id')!;
  assert.ok(id); await initialized.text();
  const controller = new AbortController();
  const response = await fetch(f.url, { headers: { ...raw(), accept: 'text/event-stream', 'mcp-session-id': id }, signal: controller.signal });
  assert.equal(response.status, 200); assert.match(response.headers.get('content-type')!, /event-stream/);
  controller.abort();
  assert.equal((await f.request('DELETE', raw(), id)).status, 200);
});
test('raw encodings, precedence and broker-disabled compatibility reach exact mock credential', async t => {
  const f = await fixture(t, { configured: false, hmacKey: '' });
  for (const value of ['A:secret:A', '{"partnerUserID":"A","partnerUserSecret":"secret:A"}', '{"id":"A","secret":"secret:A"}']) {
    const a = await f.connect({ Authorization: `Bearer ${value}`, ...signed('unrelated') });
    await a.client.callTool({ name: 'policies_list', arguments: {} });
    assert.equal(f.calls.at(-1)!.payload.credentials.partnerUserSecret, 'secret:A');
    await a.transport.terminateSession();
  }
  assert.equal(f.calls.filter(c => c.kind === 'broker').length, 0);
});
test('signed broker resolves on each call and preserves disconnected response; failures are private', async t => {
  const f = await fixture(t); const a = await f.connect(signed());
  await a.client.callTool({ name: 'policies_list', arguments: {} });
  f.state.brokerStatus = 404;
  const disconnected = await a.client.callTool({ name: 'policies_list', arguments: {} });
  assert.equal(JSON.parse(resultText(disconnected)).status, 'connection_required');
  assert.equal(f.calls.filter(c => c.kind === 'broker').length, 2);
  assert.equal(f.calls.filter(c => c.kind === 'provider').length, 1);
  f.state.brokerStatus = 500;
  assert.equal((await a.client.callTool({ name: 'policies_list', arguments: {} })).isError, true);
  f.state.brokerStatus = 200; f.state.badToken = true;
  assert.doesNotMatch(resultText(await a.client.callTool({ name: 'policies_list', arguments: {} })), /PRIVATE-CANARY/);
  f.state.badToken = false; f.state.providerStatus = 500;
  assert.doesNotMatch(resultText(await a.client.callTool({ name: 'policies_list', arguments: {} })), /PRIVATE-CANARY/);
  f.state.reject = true;
  assert.doesNotMatch(resultText(await a.client.callTool({ name: 'policies_list', arguments: {} })), /PRIVATE-CANARY/);
  f.state.reject = false; f.state.providerStatus = 200;
  assert.ok(!((await a.client.callTool({ name: 'policies_list', arguments: {} })).isError));
});
test('bad admissions/JSON and unknown sessions have no external effects and no session header', async t => {
  const f = await fixture(t);
  for (const headers of [{}, { 'x-broker-principal': 'A' }, { ...signed(), 'x-broker-principal-sig': 'bad' }, { Authorization: 'Bearer PRIVATE-CANARY', ...signed() }, { Authorization: 'Basic PRIVATE-CANARY' }, { Authorization: 'Bearer {"id":3,"secret":"PRIVATE-CANARY"}' }]) {
    const response = await f.request('POST', headers, undefined, call);
    assert.ok([400, 401].includes(response.status)); assert.equal(response.headers.get('mcp-session-id'), null);
    assert.doesNotMatch(await response.text(), /PRIVATE-CANARY/);
  }
  const invalidJson = await f.request('POST', raw(), undefined, '{"PRIVATE-CANARY":');
  assert.equal(invalidJson.status, 400); assert.doesNotMatch(await invalidJson.text(), /PRIVATE-CANARY/);
  const unknown = await f.request('POST', raw(), 'does-not-exist', call);
  assert.equal(unknown.status, 404); assert.equal(unknown.headers.get('mcp-session-id'), null);
  const noInit = await f.request('POST', raw(), undefined, call);
  assert.equal(noInit.status, 400); assert.equal(noInit.headers.get('mcp-session-id'), null);
  assert.equal(f.calls.length, 0);
  assert.equal((await (await f.connect(raw())).client.listTools()).tools.length, 13);
});

test('broker misconfiguration refuses HTTP admission without token or provider calls', async t => {
  for (const options of [{ configured: false }, { hmacKey: '' }]) {
    const f = await fixture(t, options);
    const response = await f.request('POST', signed(), undefined, initialize);
    assert.equal(response.status, 503); assert.equal(response.headers.get('mcp-session-id'), null);
    assert.equal(f.calls.length, 0);
    const a = await f.connect(raw());
    await a.client.callTool({ name: 'policies_list', arguments: {} });
    assert.equal(f.calls[0].kind, 'provider');
  }
});
test('private malformed protocol values and failed initialize are normalized before transport', async t => {
  const f = await fixture(t);
  const a = await f.connect(raw());
  for (const body of [{ ...initialize, params: { clientInfo: { name: 'PRIVATE-CANARY' } } }, { ...call, params: { name: { private: 'PRIVATE-CANARY' } } }, { jsonrpc: 'PRIVATE-CANARY', id: 10, method: 'tools/list' }]) {
    const response = await f.request('POST', raw(), undefined, body);
    assert.equal(response.status, 400); assert.equal(response.headers.get('mcp-session-id'), null);
    assert.doesNotMatch(await response.text(), /PRIVATE-CANARY/);
  }
  const version = await f.request('POST', { ...raw(), 'mcp-protocol-version': 'PRIVATE-CANARY' }, a.transport.sessionId, call);
  assert.equal(version.status, 400); assert.doesNotMatch(await version.text(), /PRIVATE-CANARY/);
  assert.equal(f.calls.length, 0);
  assert.equal((await a.client.listTools()).tools.length, 13);
});

for (const protocol of ['2025-03-26', '2024-11-05']) {
  for (const mode of ['raw', 'broker'] as const) {
    test(`${protocol} ${mode}: authenticated batches preserve results and refuse mixed-invalid or foreign callers`, async t => {
      const f = await fixture(t);
      const headers = mode === 'raw' ? raw : signed;
      const versionHeaders = { ...headers('A'), 'mcp-protocol-version': protocol };
      const opened = await f.request('POST', versionHeaders, undefined, { ...initialize, params: { ...initialize.params, protocolVersion: protocol } });
      assert.equal(opened.status, 200);
      const sessionId = opened.headers.get('mcp-session-id')!;
      assert.ok(sessionId); await opened.text();
      const batch = [
        { jsonrpc: '2.0', id: 81, method: 'tools/list', params: {} },
        { ...call, id: 82 },
      ];
      const result = await f.request('POST', versionHeaders, sessionId, batch);
      assert.equal(result.status, 200);
      const messages = (await result.text()).split('\n').filter(line => line.startsWith('data: ')).map(line => JSON.parse(line.slice(6)));
      assert.equal(messages.find(m => m.id === 81).result.tools.length, 13);
      assert.deepEqual(JSON.parse(messages.find(m => m.id === 82).result.content[0].text).policies, ['A']);
      const before = f.calls.length;
      for (const badHeaders of [{}, { ...headers('B'), 'mcp-protocol-version': protocol }]) {
        const denied = await f.request('POST', badHeaders, sessionId, batch);
        assert.ok([401, 403].includes(denied.status)); assert.equal(f.calls.length, before);
      }
      for (const invalid of [
        [...batch, { ...call, id: 83, params: { name: { private: 'PRIVATE-CANARY' } } }],
        [...batch, { jsonrpc: 'PRIVATE-CANARY', id: 83, method: 'tools/list' }],
        [...batch, { ...initialize, id: 83, params: { clientInfo: { name: 'PRIVATE-CANARY' } } }],
        [],
      ]) {
        const denied = await f.request('POST', versionHeaders, sessionId, invalid);
        assert.equal(denied.status, 400); assert.doesNotMatch(await denied.text(), /PRIVATE-CANARY/);
        assert.equal(f.calls.length, before, 'validate the entire batch before invoking any member');
      }
      const mixedInitialize = await f.request('POST', versionHeaders, undefined, [initialize, { ...initialize, id: 2 }]);
      assert.equal(mixedInitialize.status, 400); assert.equal(mixedInitialize.headers.get('mcp-session-id'), null);
      assert.equal((await f.request('DELETE', versionHeaders, sessionId)).status, 200);
    });
  }
}
