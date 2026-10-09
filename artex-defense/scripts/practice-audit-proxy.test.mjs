import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { createPracticeProxy } from './practice-audit-proxy.mjs';

const UUID = '11111111-2222-4333-8444-555555555555';
const rows = (dir, name) => readFileSync(join(dir, name), 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);

async function fixture(t, handler = (_req, res) => res.end('origin'), options = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'artex-practice-proxy-'));
  const origin = http.createServer(handler);
  await new Promise((done) => origin.listen(0, '127.0.0.1', done));
  const proxy = createPracticeProxy({ logDir: dir, upstream: `http://127.0.0.1:${origin.address().port}`, ...options });
  const address = await proxy.listen(0, '127.0.0.1');
  t.after(async () => {
    await proxy.close();
    origin.closeAllConnections();
    await new Promise((done) => origin.close(done));
    rmSync(dir, { recursive: true, force: true });
  });
  return { dir, origin, proxy, port: address.port };
}

function request(port, path, { headers = {}, method = 'GET', chunks = [] } = {}) {
  return new Promise((accept, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.once('end', () => accept({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.once('error', reject);
    });
    req.once('error', reject);
    for (const chunk of chunks) req.write(chunk);
    req.end();
  });
}

test('real /ftp paths create independently identified audit and alert; lookalikes do not', async (t) => {
  const f = await fixture(t);
  for (const path of ['/ftp', '/ftp/readme.txt?token=do-not-log', '/f%74p', '/ftp%2Ffile']) {
    assert.equal((await request(f.port, path, { headers: { 'X-ARTEX-Verification-ID': UUID } })).status, 200);
  }
  for (const path of ['/api/ftp', '/ftproxy', '/FTP', '//other.invalid/ftp', '/']) await request(f.port, path);
  const audit = rows(f.dir, 'audit.jsonl');
  const alerts = rows(f.dir, 'alerts.jsonl');
  assert.equal(audit.length, 9);
  assert.equal(alerts.length, 4);
  for (let i = 0; i < 4; i++) {
    assert.equal(audit[i].action, 'allowed');
    assert.equal(audit[i].artex_verification_id, UUID);
    assert.equal(alerts[i].artex_verification_id, UUID);
    assert.equal(alerts[i].audit_event_id, audit[i].id);
    assert.notEqual(alerts[i].id, audit[i].id);
    assert.equal(alerts[i].rule_id, 'ftp-access-v1');
    assert.equal(alerts[i].event_kind, 'alert');
    assert.equal(alerts[i].control_scope, 'practice-forwarding-proxy');
  }
  assert.equal(readFileSync(join(f.dir, 'audit.jsonl'), 'utf8').includes('do-not-log'), false);
});

test('health is not audit evidence; invalid and duplicate UUID headers cannot acquire correlation', async (t) => {
  const seen = [];
  const f = await fixture(t, (req, res) => { seen.push(req.headers['x-artex-verification-id']); res.end(); });
  const health = await request(f.port, '/__artex_health');
  assert.equal(health.status, 200);
  assert.equal(JSON.parse(health.body).healthy, true);
  assert.equal(rows(f.dir, 'audit.jsonl').length, 0);
  await request(f.port, '/ftp', { headers: { 'X-ARTEX-Verification-ID': UUID } });
  await request(f.port, '/ftp', { headers: { 'X-ARTEX-Verification-ID': 'not-a-uuid' } });
  await request(f.port, '/ftp', { headers: { 'X-ARTEX-Verification-ID': [UUID, UUID] } });
  await request(f.port, '/ftp');
  assert.equal(seen[0], UUID);
  const audit = rows(f.dir, 'audit.jsonl');
  assert.deepEqual(audit.map((r) => r.correlation_status), ['valid', 'invalid', 'invalid', 'missing']);
  for (const row of audit.slice(1)) assert.equal(Object.hasOwn(row, 'artex_verification_id'), false);
  assert.equal(rows(f.dir, 'alerts.jsonl').length, 4);
});

test('forwards binary request and response streams without recording bodies or credentials', async (t) => {
  const payload = Buffer.from([0, 1, 255, 128, 42]);
  let originHeaders;
  let originBody;
  const f = await fixture(t, (req, res) => {
    originHeaders = req.headers;
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      originBody = Buffer.concat(chunks);
      res.writeHead(201, { 'content-type': 'application/octet-stream', 'connection': 'x-local', 'x-local': 'remove', 'x-origin': 'keep' });
      res.end(originBody);
    });
  });
  const response = await request(f.port, '/api/item', { method: 'POST', chunks: [payload.subarray(0, 2), payload.subarray(2)], headers: {
    cookie: 'secret-cookie', authorization: 'Bearer secret-token', connection: 'x-remove', 'x-remove': 'remove', 'x-keep': 'keep',
  } });
  assert.equal(response.status, 201);
  assert.deepEqual(response.body, payload);
  assert.deepEqual(originBody, payload);
  assert.equal(originHeaders['x-remove'], undefined);
  assert.equal(originHeaders['x-keep'], 'keep');
  assert.equal(originHeaders.cookie, 'secret-cookie');
  assert.equal(response.headers['x-local'], undefined);
  assert.equal(response.headers['x-origin'], 'keep');
  assert.equal(/secret-cookie|secret-token|authorization|cookie/.test(readFileSync(join(f.dir, 'audit.jsonl'), 'utf8')), false);
});

test('an upstream 403 means this proxy forwarded, never proves a security block', async (t) => {
  const f = await fixture(t, (_req, res) => { res.writeHead(403); res.end('origin refused'); });
  assert.equal((await request(f.port, '/ftp')).status, 403);
  const audit = rows(f.dir, 'audit.jsonl')[0];
  assert.equal(audit.status, 403);
  assert.equal(audit.action, 'allowed');
  assert.equal(audit.control_scope, 'practice-forwarding-proxy');
});

test('upstream disconnect is unknown while actual matching request still triggers rule', async (t) => {
  const f = await fixture(t, (req) => req.socket.destroy());
  assert.equal((await request(f.port, '/ftp')).status, 502);
  const audit = rows(f.dir, 'audit.jsonl')[0];
  assert.equal(audit.action, 'unknown');
  assert.equal(audit.status, null);
  assert.equal(audit.observed_from, 'proxy_error');
  assert.equal(audit.transport_error, 'upstream_connection_error');
  assert.equal(rows(f.dir, 'alerts.jsonl')[0].action, 'unknown');
});

test('incomplete upstream response cannot be recorded as allowed', async (t) => {
  const f = await fixture(t, (_req, res) => {
    res.writeHead(200, { 'content-length': '100' });
    res.write('short');
    setTimeout(() => res.destroy(), 10);
  });
  await assert.rejects(request(f.port, '/ftp'));
  await delay(10);
  const audit = rows(f.dir, 'audit.jsonl');
  assert.equal(audit.length, 1);
  assert.equal(audit[0].action, 'unknown');
  assert.equal(audit[0].status, 200);
});

test('upstream timeout produces unknown audit and preserves real rule detection', async (t) => {
  const f = await fixture(t, () => {}, { upstreamTimeoutMs: 15 });
  assert.equal((await request(f.port, '/ftp')).status, 502);
  const audit = rows(f.dir, 'audit.jsonl');
  assert.equal(audit.length, 1);
  assert.equal(audit[0].action, 'unknown');
  assert.equal(audit[0].transport_error, 'upstream_timeout');
  assert.equal(rows(f.dir, 'alerts.jsonl').length, 1);
});

test('client abort records unknown once and closes the upstream request', async (t) => {
  const f = await fixture(t, (_req, res) => { res.writeHead(200); res.write('first chunk'); });
  await new Promise((accept, reject) => {
    const req = http.get({ hostname: '127.0.0.1', port: f.port, path: '/ftp' }, (res) => {
      res.on('error', () => {});
      res.once('data', () => { res.destroy(); accept(); });
    });
    req.once('error', reject);
  });
  await delay(20);
  const audit = rows(f.dir, 'audit.jsonl');
  assert.equal(audit.length, 1);
  assert.equal(audit[0].action, 'unknown');
  assert.equal(audit[0].transport_error, 'client_aborted');
  assert.equal(rows(f.dir, 'alerts.jsonl').length, 1);
});

test('malformed path is rejected and absolute request targets cannot change the upstream', async (t) => {
  let calls = 0;
  const f = await fixture(t, (_req, res) => { calls++; res.end(); });
  assert.equal((await request(f.port, '/ftp/%ZZ')).status, 400);
  assert.equal((await request(f.port, 'http://unreachable.invalid/ftp')).status, 400);
  assert.equal(calls, 0);
  assert.equal(rows(f.dir, 'alerts.jsonl').length, 0);
  for (const row of rows(f.dir, 'audit.jsonl')) assert.equal(row.action, 'unknown');
});

test('evidence write failure stops healthy coverage and refuses further forwarding', async (t) => {
  let calls = 0;
  const f = await fixture(t, (_req, res) => { calls++; res.end(); }, { maxLogBytes: 1200, heartbeatMs: 10000 });
  for (let i = 0; i < 5 && f.proxy.health().healthy; i++) await request(f.port, `/ftp/${'a'.repeat(400)}`);
  assert.equal(f.proxy.health().healthy, false);
  assert.equal(f.proxy.health().failure_code, 'LOG_SIZE_LIMIT');
  assert.equal((await request(f.port, '/__artex_health')).status, 503);
  const before = calls;
  assert.equal((await request(f.port, '/ftp')).status, 503);
  assert.equal(calls, before);
  const journal = rows(f.dir, 'metadata.jsonl');
  assert.equal(journal.at(-1).event, 'evidence_write_failed');
  assert.equal(journal.at(-1).healthy, false);
});

test('journal records continuous healthy heartbeats and graceful shutdown', async (t) => {
  const f = await fixture(t, undefined, { heartbeatMs: 10 });
  await delay(35);
  await f.proxy.close();
  const journal = rows(f.dir, 'metadata.jsonl');
  assert.equal(journal[0].event, 'started');
  assert.equal(journal.at(-1).event, 'stopped');
  assert.ok(journal.some((r) => r.event === 'heartbeat'));
  for (const row of journal) {
    assert.equal(row.instance_id, journal[0].instance_id);
    assert.equal(row.healthy, true);
    assert.equal(row.scope, 'local-practice-detector');
  }
});
