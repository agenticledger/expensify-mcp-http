import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
export async function startProcess(t: any, broker = true) {
  const reserve = createServer();
  await new Promise<void>(resolve => reserve.listen(0, '127.0.0.1', resolve));
  const port = (reserve.address() as any).port;
  await new Promise<void>(resolve => reserve.close(() => resolve()));
  const child = spawn(process.execPath, ['dist/index.js'], { env: {
    PATH: process.env.PATH, PORT: String(port), BROKER_BASE_URL: 'http://127.0.0.1:1',
    BROKER_INSTALL_BEARER: broker ? 'fixture-install' : '', BROKER_JWT_KEY: broker ? 'fixture-jwt' : '',
    BROKER_CLIENT_NAMESPACE: broker ? 'fixture-namespace' : '', BROKER_PRINCIPAL_HMAC_KEY: broker ? 'fixture-hmac' : '',
  }, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = ''; child.stdout.on('data', d => output += d); child.stderr.on('data', d => output += d);
  t.after(async () => { child.kill(); await new Promise<void>(resolve => child.exitCode !== null ? resolve() : child.once('exit', () => resolve())); });
  const url = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 150; i++) {
    try { if ((await fetch(`${url}/health`)).ok) return { url, child, output: () => output }; } catch {}
    if (child.exitCode !== null) throw new Error('Fixture startup failed');
    await delay(20);
  }
  throw new Error('Fixture startup timeout');
}
