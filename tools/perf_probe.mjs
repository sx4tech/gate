// Measure actual payload bytes. No synthetic speed estimate from VPN Gate metadata.
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import { Duplex } from 'node:stream';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { sstpConnect, withTimeout } from './vendor/sstp.mjs';

export function measureDownload(socket, {host, path, bytes, timeoutMs = 20000}) {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const agent = new http.Agent({keepAlive: false});
    agent.createConnection = () => socket;
    let received = 0, firstByte = null;
    const request = http.request({hostname: host, port: 443, path, agent,
      headers: {Host: host, 'Accept-Encoding': 'identity', Connection: 'close',
        'User-Agent': 'gate-performance-check/1.0', 'Cache-Control': 'no-cache'}}, response => {
      if (response.statusCode !== 200) {
        response.destroy();
        finish(new Error(`HTTP ${response.statusCode}`));
        return;
      }
      response.on('data', chunk => {
        if (firstByte === null) firstByte = performance.now();
        received += chunk.length;
        if (received > bytes) request.destroy(new Error('Unexpected oversized response'));
      });
      response.on('aborted', () => finish(new Error('Truncated download')));
      response.on('error', finish);
      response.on('end', () => {
        if (received !== bytes) return finish(new Error(`Short download: ${received}/${bytes}`));
        const elapsed = Math.max(performance.now() - started, 1);
        finish(null, {download_bytes: received, download_ms: Math.round(elapsed),
          download_mbps: +(received * 8 / (elapsed * 1000)).toFixed(3),
          ttfb_ms: Math.round((firstByte ?? performance.now()) - started)});
      });
    });
    let settled = false;
    const timer = setTimeout(() => request.destroy(new Error('Download deadline exceeded')), timeoutMs);
    function finish(error, data) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      agent.destroy();
      error ? reject(error) : resolve(data);
    }
    request.on('error', finish);
    request.end();
  });
}

async function secure(socket, host, timeoutMs) {
  const secureSocket = tls.connect({socket, servername: host, rejectUnauthorized: true,
    minVersion: 'TLSv1.2', ALPNProtocols: ['http/1.1']});
  try {
    await withTimeout(new Promise((resolve, reject) => {
      secureSocket.once('secureConnect', resolve);
      secureSocket.once('error', reject);
    }), timeoutMs, 'TLS handshake deadline exceeded');
    return secureSocket;
  } catch (error) { secureSocket.destroy(); throw error; }
}

async function direct(host, port, servername, timeoutMs) {
  const raw = net.connect({host, port});
  raw.setNoDelay(true);
  return secure(raw, servername, timeoutMs);
}

async function validateEntry(input) {
  const started = performance.now();
  const socket = await direct(input.host, input.port, input.servername, input.timeout_ms);
  return new Promise((resolve, reject) => {
    const agent = new http.Agent();
    agent.createConnection = () => socket;
    const req = http.request({hostname: input.servername, port: input.port,
      path: '/cdn-cgi/trace', agent,
      headers: {Host: input.servername, Connection: 'close'}}, res => {
      let body = '';
      res.on('data', c => {body += c; if (body.length > 8192) req.destroy(new Error('Invalid trace response'));});
      res.on('error', finish);
      res.on('end', () => {
        if (res.statusCode !== 200 || !/^colo=[A-Z]{3}$/m.test(body))
          return finish(new Error('Entry failed HTTPS/Cloudflare trace validation'));
        finish(null, {latency_ms: Math.round(performance.now() - started),
          colo: body.match(/^colo=([A-Z]{3})$/m)[1]});
      });
    });
    const timer = setTimeout(() => req.destroy(new Error('Entry deadline exceeded')), input.timeout_ms);
    function finish(error, result) {clearTimeout(timer); agent.destroy(); error ? reject(error) : resolve(result);}
    req.on('error', finish); req.end();
  });
}

export async function runProbe(input) {
  input = {timeout_ms: 25000, bytes: 2097152, ...input};
  if (!Number.isInteger(input.bytes) || input.bytes < 65536 || input.bytes > 4194304)
    throw new Error('Probe payload must be 64 KiB to 4 MiB');
  const target = 'speed.cloudflare.com';
  if (input.mode === 'entry-latency') return validateEntry(input);
  let tunnel, socket;
  const started = performance.now();
  try {
    if (input.mode === 'sstp') {
      if (!/^[a-zA-Z0-9.-]+\.opengw\.net$/.test(input.host)) throw new Error('Expected public VPN Gate hostname');
      tunnel = await sstpConnect({hostname: input.host, port: input.port, username: 'vpn', password: 'vpn'}, target, 443);
      tunnel.closed.catch(() => {});
      socket = await secure(Duplex.fromWeb(tunnel), target, input.timeout_ms);
    } else if (input.mode === 'entry-speed') {
      if (!net.isIP(input.host)) throw new Error('Entry speed probe requires a resolved IP');
      socket = await direct(input.host, input.port, target, input.timeout_ms);
    } else throw new Error('Unknown probe mode');
    const setup_ms = Math.round(performance.now() - started);
    const result = await measureDownload(socket, {host: target,
      path: `/__down?bytes=${input.bytes}&nonce=${Date.now()}`, bytes: input.bytes,
      timeoutMs: input.timeout_ms});
    return {...result, setup_ms, measurement_scope: input.mode === 'sstp'
      ? 'runner-to-sstp-exit-to-cloudflare-speed' : 'runner-to-cloudflare-entry'};
  } finally { socket?.destroy(); tunnel?.close(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let raw = '';
  for await (const chunk of process.stdin) raw += chunk;
  try { console.log(JSON.stringify({ok: true, ...await runProbe(JSON.parse(raw))})); }
  catch (error) { console.log(JSON.stringify({ok: false, error: error.message})); }
  // Close any unfinished PPP receive timers; every CLI invocation is one isolated sample.
  process.exit(0);
}
