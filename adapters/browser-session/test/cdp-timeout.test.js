import test from 'node:test';
import assert from 'node:assert/strict';
import { CDP } from '../lib/cdp.js';

class FakeWebSocket {
  static instances = [];
  constructor() { FakeWebSocket.instances.push(this); queueMicrotask(() => this.onopen?.()); }
  send(message) { this.sent = JSON.parse(message); }
  close() { this.onclose?.(); }
  reply(result = {}) { this.onmessage?.({ data: JSON.stringify({ id: this.sent.id, result }) }); }
}

test('CDP commands time out, clear pending state, and ignore late replies', async () => {
  const previous = globalThis.WebSocket;
  globalThis.WebSocket = FakeWebSocket;
  try {
    const cdp = await new CDP('ws://127.0.0.1/mock', { commandTimeout: 15 }).connect();
    const socket = FakeWebSocket.instances.at(-1);
    await assert.rejects(cdp.send('Page.getFrameTree'), error => error.code === 'timeout' && error.method === 'Page.getFrameTree');
    assert.equal(cdp.pending.size, 0);
    assert.doesNotThrow(() => socket.reply({ frameTree: {} }));
    cdp.close();
  } finally { globalThis.WebSocket = previous; }
});

test('CDP replies cancel command timeouts', async () => {
  const previous = globalThis.WebSocket;
  globalThis.WebSocket = FakeWebSocket;
  try {
    const cdp = await new CDP('ws://127.0.0.1/mock', { commandTimeout: 15 }).connect();
    const socket = FakeWebSocket.instances.at(-1);
    const result = cdp.send('Target.getTargets');
    socket.reply({ targetInfos: [] });
    assert.deepEqual(await result, { targetInfos: [] });
    assert.equal(cdp.pending.size, 0);
    cdp.close();
  } finally { globalThis.WebSocket = previous; }
});
