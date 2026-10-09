#!/usr/bin/env node
// Local practice detector: records real forwarded requests, not a production WAF.
import { randomUUID } from 'node:crypto';
import { appendFileSync, mkdirSync, statSync } from 'node:fs';
import http from 'node:http';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const RULE_ID = 'ftp-access-v1';
const CONTROL_SCOPE = 'practice-forwarding-proxy';
const HEALTH_PATH = '/__artex_health';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HOP_HEADERS = ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'proxy-connection'];

function endToEndHeaders(headers) {
  const result = { ...headers };
  const connection = headers.connection;
  const nominated = typeof connection === 'string' ? connection.split(',') : [];
  for (const name of [...HOP_HEADERS, ...nominated]) delete result[name.trim().toLowerCase()];
  return result;
}

function correlation(req) {
  const values = [];
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i].toLowerCase() === 'x-artex-verification-id') values.push(req.rawHeaders[i + 1]);
  }
  if (values.length === 0) return { correlation_status: 'missing' };
  if (values.length !== 1 || !UUID.test(values[0])) return { correlation_status: 'invalid' };
  return { correlation_status: 'valid', artex_verification_id: values[0].toLowerCase() };
}

function requestPath(target) {
  if (!target?.startsWith('/')) return { path: '', invalid_path: true, matches: false };
  try {
    // Concatenation preserves a leading // as a path, never as a new upstream host.
    const encoded = new URL(`http://practice.invalid${target}`).pathname;
    const decoded = decodeURIComponent(encoded);
    return {
      path: decoded.slice(0, 2048),
      ...(decoded.length > 2048 ? { path_truncated: true } : {}),
      matches: decoded === '/ftp' || decoded.startsWith('/ftp/'),
    };
  } catch {
    return { path: target.split('?')[0].slice(0, 2048), invalid_path: true, matches: false };
  }
}

export function createPracticeProxy({
  logDir,
  upstream = 'http://juice-shop-origin:3000',
  heartbeatMs = 5000,
  maxLogBytes = 32 * 1024 * 1024,
  upstreamTimeoutMs = 30000,
} = {}) {
  if (!logDir) throw new Error('logDir is required');
  const target = new URL(upstream);
  if (target.protocol !== 'http:' || target.username || target.password || target.pathname !== '/') {
    throw new Error('upstream must be an HTTP origin');
  }
  if (!Number.isSafeInteger(maxLogBytes) || maxLogBytes < 1) throw new Error('invalid maxLogBytes');
  const directory = resolve(logDir);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const files = { audit: 'audit.jsonl', alert: 'alerts.jsonl', metadata: 'metadata.jsonl' };
  for (const name of Object.values(files)) appendFileSync(resolve(directory, name), '', { mode: 0o600 });
  const instanceId = randomUUID();
  let startedAt = null;
  let healthy = true;
  let failureCode = null;
  let heartbeat;
  let closing = false;
  let closePromise;

  function append(kind, record) {
    const path = resolve(directory, files[kind]);
    const line = `${JSON.stringify(record)}\n`;
    const limit = kind === 'metadata' ? Math.min(maxLogBytes, 8 * 1024 * 1024) : maxLogBytes;
    if (statSync(path).size + Buffer.byteLength(line) > limit) {
      const error = new Error('evidence log size limit reached');
      error.code = 'LOG_SIZE_LIMIT';
      throw error;
    }
    appendFileSync(path, line, { mode: 0o600 });
  }

  function metadata(event) {
    append('metadata', {
      timestamp: new Date().toISOString(), event, instance_id: instanceId,
      scope: 'local-practice-detector', rule_id: RULE_ID, healthy,
      ...(failureCode ? { failure_code: failureCode } : {}),
    });
  }

  function failEvidence(error) {
    if (!healthy) return;
    healthy = false;
    failureCode = /^[A-Z0-9_]{1,40}$/.test(error?.code ?? '') ? error.code : 'EVIDENCE_WRITE_ERROR';
    clearInterval(heartbeat);
    try { metadata('evidence_write_failed'); } catch { /* Missing heartbeats also invalidate coverage. */ }
    process.stderr.write(`practice detector evidence failure: ${failureCode}\n`);
  }

  function health() {
    return {
      service: 'artex-practice-audit-proxy', healthy, instance_id: instanceId,
      started_at: startedAt, observed_at: new Date().toISOString(), rule_id: RULE_ID,
      control_scope: CONTROL_SCOPE,
      ...(failureCode ? { failure_code: failureCode } : {}),
    };
  }

  const server = http.createServer({ maxHeaderSize: 16 * 1024 }, (req, res) => {
    if (req.url?.split('?')[0] === HEALTH_PATH) {
      res.writeHead(healthy && !closing ? 200 : 503, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(health()));
      return;
    }
    if (!healthy || closing) {
      res.writeHead(503, { 'content-type': 'text/plain', 'connection': 'close' });
      res.end('Practice evidence collection is unavailable.\n');
      return;
    }

    const receivedAt = new Date().toISOString();
    const path = requestPath(req.url);
    const match = path.matches;
    delete path.matches;
    const fields = { ...correlation(req), method: req.method, ...path };
    let recorded = false;
    let upstreamComplete = false;
    let upstreamStatus = null;
    let transportError = null;
    let outgoing;

    function record() {
      if (recorded) return;
      recorded = true;
      const forwarded = upstreamComplete && res.writableFinished && transportError === null;
      const audit = {
        id: randomUUID(), timestamp: new Date().toISOString(), received_at: receivedAt,
        instance_id: instanceId, event_kind: 'audit', control_scope: CONTROL_SCOPE,
        observed_from: forwarded ? 'proxy_response' : 'proxy_error',
        ...fields, status: upstreamStatus, action: forwarded ? 'allowed' : 'unknown',
        ...(transportError ? { transport_error: transportError } : {}),
      };
      try {
        append('audit', audit);
        if (match) append('alert', {
          ...audit, id: randomUUID(), event_kind: 'alert', audit_event_id: audit.id,
          rule_id: RULE_ID, severity: 'low',
          message: 'Real request matched the local practice /ftp path rule.',
        });
      } catch (error) { failEvidence(error); }
    }

    res.once('finish', record);
    res.once('close', () => {
      if (!res.writableFinished) {
        transportError ??= 'client_aborted';
        outgoing?.destroy();
      }
      record();
    });
    req.once('aborted', () => {
      transportError ??= 'client_aborted';
      outgoing?.destroy();
      res.destroy();
      record();
    });

    if (path.invalid_path) {
      transportError = 'invalid_request_path';
      req.resume();
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('Invalid request path.\n');
      return;
    }

    const headers = endToEndHeaders(req.headers);
    headers.host = target.host;
    // Explicit origin fields keep all traffic on the configured local upstream.
    outgoing = http.request({
      hostname: target.hostname, port: target.port || 80, method: req.method,
      path: req.url, headers,
    }, (response) => {
      upstreamStatus = response.statusCode;
      response.once('end', () => { upstreamComplete = response.complete; });
      response.once('error', () => {
        transportError = 'upstream_response_error';
        res.destroy();
        record();
      });
      res.writeHead(response.statusCode, endToEndHeaders(response.headers));
      response.pipe(res);
    });
    outgoing.setTimeout(upstreamTimeoutMs, () => {
      transportError = 'upstream_timeout';
      outgoing.destroy();
    });
    outgoing.once('error', () => {
      transportError ??= 'upstream_connection_error';
      if (res.destroyed) { record(); return; }
      if (res.headersSent) { res.destroy(); record(); return; }
      req.resume();
      res.writeHead(502, { 'content-type': 'text/plain' });
      res.end('Local practice upstream unavailable.\n');
    });
    req.pipe(outgoing);
  });
  server.requestTimeout = 60000;
  server.headersTimeout = 15000;

  return {
    server, health,
    async listen(port = 3000, host = '0.0.0.0') {
      await new Promise((accept, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => { server.off('error', reject); accept(); });
      });
      startedAt = new Date().toISOString();
      try { metadata('started'); } catch (error) { failEvidence(error); }
      if (healthy) {
        heartbeat = setInterval(() => {
          try { metadata('heartbeat'); } catch (error) { failEvidence(error); }
        }, heartbeatMs);
        heartbeat.unref();
      }
      return server.address();
    },
    close() {
      closePromise ??= (async () => {
        closing = true;
        await new Promise((accept) => {
          const deadline = setTimeout(() => server.closeAllConnections(), 5000);
          deadline.unref();
          server.close(() => { clearTimeout(deadline); accept(); });
        });
        clearInterval(heartbeat);
        try { metadata('stopped'); } catch (error) { failEvidence(error); }
      })();
      return closePromise;
    },
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const proxy = createPracticeProxy({ logDir: process.env.LOG_DIR || '/logs' });
  await proxy.listen();
  process.stdout.write(`Local practice detector listening on 3000; rule ${RULE_ID}.\n`);
  for (const signal of ['SIGTERM', 'SIGINT']) {
    process.once(signal, async () => { await proxy.close(); process.exit(proxy.health().healthy ? 0 : 1); });
  }
}
