import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { NativeBrowserHost, normalBrowserEndpoint } from '../lib/native-browser-host.js';
import { normalBrowserRequest } from '../lib/normal-browser.js';

test('normal browser endpoint accepts only loopback DevToolsActivePort data', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-normal-endpoint-'));
  try {
    await assert.rejects(normalBrowserEndpoint(root), error => error.code === 'setup_required');
    await writeFile(path.join(root, 'DevToolsActivePort'), '9222\n/devtools/browser/session-1\n');
    const endpoint = await normalBrowserEndpoint(root);
    assert.equal(endpoint.wsUrl, 'ws://127.0.0.1:9222/devtools/browser/session-1');
    assert.equal(endpoint.browserSession.length, 32);
    await writeFile(path.join(root, 'DevToolsActivePort'), '9222\nws://evil.test/devtools/browser/x\n');
    await assert.rejects(normalBrowserEndpoint(root), error => error.code === 'unavailable');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('native browser host reuses one CDP connection across adapter requests', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-normal-host-'));
  const chromeRoot = path.join(root, 'chrome'), socketPath = path.join(root, 'host.sock');
  await mkdir(chromeRoot);
  await writeFile(path.join(chromeRoot, 'DevToolsActivePort'), '9333\n/devtools/browser/stable\n');
  let connects = 0;
  let closes = 0;
  const cdp = { close() { closes++; } };
  let factories = 0;
  const host = await new NativeBrowserHost({ chromeRoot, socketPath, connect: async () => { connects++; return cdp; }, operationsFactory: async (_cdp, context) => {
    factories++;
    return { inventory: async () => ({ label: 'Chrome', items: [], session: context.browserSession }) };
  } }).start();
  try {
    const approved = await normalBrowserRequest('connect', {}, { socketPath });
    assert.equal(approved.connected, true);
    const first = await normalBrowserRequest('inventory', {}, { socketPath });
    const second = await normalBrowserRequest('inventory', {}, { socketPath });
    assert.equal(first.session, second.session);
    assert.equal(connects, 1);
    assert.equal(factories, 1);
    await writeFile(path.join(chromeRoot, 'DevToolsActivePort'), '9444\n/devtools/browser/restarted\n');
    await assert.rejects(normalBrowserRequest('inventory', {}, { socketPath }), error => error.code === 'setup_required');
    const afterRestart = await normalBrowserRequest('connect', {}, { socketPath });
    assert.notEqual(afterRestart.browser_session, first.session);
    assert.equal(connects, 2);
    assert.equal(closes, 1);
  } finally { await host.close(); await rm(root, { recursive: true, force: true }); }
});

test('only explicit connect starts a detached host and retries a missing socket', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-normal-autostart-'));
  const socketPath = path.join(root, 'host.sock');
  let server, spawns = 0, detached;
  const spawnFn = (_node, _args, options) => {
    spawns++; detached = options.detached;
    server = net.createServer(socket => socket.once('data', () => socket.end('{"result":{"connected":true,"browser_session":"mock"}}\n')));
    server.listen(socketPath);
    return { unref() {}, once() {} };
  };
  try {
    await assert.rejects(normalBrowserRequest('inventory', {}, { socketPath, autoStart: true, spawnFn,
      endpointFn: async () => ({ wsUrl: 'ws://127.0.0.1:1/devtools/browser/mock' }), logDir: path.join(root, 'logs') }), error => error.code === 'setup_required');
    assert.equal(spawns, 0);
    const result = await normalBrowserRequest('connect', {}, { socketPath, autoStart: true, spawnFn,
      endpointFn: async () => ({ wsUrl: 'ws://127.0.0.1:1/devtools/browser/mock' }), logDir: path.join(root, 'logs') });
    assert.equal(result.connected, true);
    assert.equal(spawns, 1);
    assert.equal(detached, true);
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  }
});

test('native host rejects unknown operations before connecting and reconnects a closed websocket', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-normal-reconnect-'));
  const chromeRoot = path.join(root, 'chrome'), socketPath = path.join(root, 'host.sock');
  await mkdir(chromeRoot);
  await writeFile(path.join(chromeRoot, 'DevToolsActivePort'), '9555\n/devtools/browser/reconnect\n');
  let connects = 0;
  const connections = [];
  const host = await new NativeBrowserHost({ chromeRoot, socketPath, connect: async () => {
    connects++;
    const cdp = { ws: { readyState: 1 }, close() { this.ws.readyState = 3; } };
    connections.push(cdp);
    return cdp;
  }, operations: { inventory: async () => ({ label: 'Chrome', items: [] }) } }).start();
  try {
    await assert.rejects(normalBrowserRequest('toString', {}, { socketPath }), error => error.code === 'invalid_request');
    assert.equal(connects, 0);
    await normalBrowserRequest('connect', {}, { socketPath });
    await normalBrowserRequest('inventory', {}, { socketPath });
    connections[0].ws.readyState = 3;
    await assert.rejects(normalBrowserRequest('inventory', {}, { socketPath }), error => error.code === 'setup_required');
    await normalBrowserRequest('connect', {}, { socketPath });
    assert.equal(connects, 2);
  } finally { await host.close(); await rm(root, { recursive: true, force: true }); }
});

test('native host serializes browser operations', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-normal-queue-'));
  const chromeRoot = path.join(root, 'chrome'), socketPath = path.join(root, 'host.sock');
  await mkdir(chromeRoot);
  await writeFile(path.join(chromeRoot, 'DevToolsActivePort'), '9666\n/devtools/browser/queue\n');
  let active = 0, maxActive = 0;
  const operation = async () => { active++; maxActive = Math.max(maxActive, active); await new Promise(resolve => setTimeout(resolve, 15)); active--; return {}; };
  const host = await new NativeBrowserHost({ chromeRoot, socketPath, connect: async () => ({ close() {} }), operations: { inventory: operation, export: operation, import: operation } }).start();
  try {
    await normalBrowserRequest('connect', {}, { socketPath });
    await Promise.all([normalBrowserRequest('inventory', {}, { socketPath }), normalBrowserRequest('export', {}, { socketPath }), normalBrowserRequest('import', {}, { socketPath })]);
    assert.equal(maxActive, 1);
  } finally { await host.close(); await rm(root, { recursive: true, force: true }); }
});
