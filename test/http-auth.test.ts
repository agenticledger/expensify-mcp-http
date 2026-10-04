import test from 'node:test';
import assert from 'node:assert/strict';
import { startProcess } from './process-fixture.js';
import { initialize } from './fixture.js';

test('compiled HTTP boundary refuses anonymous broker initialization', async t => {
  const { url } = await startProcess(t);
  const response = await fetch(`${url}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body: JSON.stringify(initialize) });
  assert.equal(response.status, 401);
  assert.equal(response.headers.get('mcp-session-id'), null);
});
