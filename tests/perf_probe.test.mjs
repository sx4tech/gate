import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import {measureDownload} from '../tools/perf_probe.mjs';

async function fixture(handler, check) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const socket = net.connect({host: '127.0.0.1', port: server.address().port});
  try { await check(socket); }
  finally { socket.destroy(); await new Promise(resolve => server.close(resolve)); }
}

test('counts decoded body bytes and rejects error pages', async () => {
  await fixture((req, res) => {res.writeHead(503); res.end('unavailable');}, async socket => {
    await assert.rejects(measureDownload(socket, {host:'fixture', path:'/', bytes:65536}), /HTTP 503/);
  });
});

test('rejects a truncated success response', async () => {
  await fixture((req, res) => {res.writeHead(200, {'Content-Length':65536}); res.end('short');}, async socket => {
    await assert.rejects(measureDownload(socket, {host:'fixture', path:'/', bytes:65536}), /Truncated|aborted/);
  });
});

test('measures chunked payload without counting HTTP framing', async () => {
  await fixture((req, res) => {
    res.writeHead(200, {'Content-Type':'application/octet-stream'});
    res.write(Buffer.alloc(32768));
    setTimeout(() => res.end(Buffer.alloc(32768)), 30);
  }, async socket => {
    const result = await measureDownload(socket, {host:'fixture', path:'/', bytes:65536});
    assert.equal(result.download_bytes, 65536);
    assert.ok(result.download_ms >= 25);
    assert.ok(result.download_mbps > 0);
  });
});
