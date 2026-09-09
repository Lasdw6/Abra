import { setTimeout as delay } from 'node:timers/promises';

export class CDP {
  constructor(url) { this.url = url; this.id = 0; this.pending = new Map(); this.listeners = new Map(); }
  async connect() {
    this.ws = new WebSocket(this.url);
    await new Promise((resolve, reject) => { this.ws.onopen = resolve; this.ws.onerror = () => reject(new Error('cannot connect to CDP destination')); });
    this.ws.onmessage = event => {
      const msg = JSON.parse(String(event.data));
      if (msg.id) {
        const pending = this.pending.get(msg.id); this.pending.delete(msg.id);
        if (msg.error) pending?.reject(new Error(msg.error.message || 'CDP command failed')); else pending?.resolve(msg.result);
      } else {
        for (const fn of this.listeners.get(msg.method) || []) fn(msg.params || {}, msg.sessionId);
      }
    };
    this.ws.onclose = () => { for (const p of this.pending.values()) p.reject(new Error('CDP connection closed')); this.pending.clear(); };
    return this;
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }
  on(method, fn) { if (!this.listeners.has(method)) this.listeners.set(method, new Set()); this.listeners.get(method).add(fn); return () => this.listeners.get(method).delete(fn); }
  close() { this.ws?.close(); }
}

export async function waitForLoad(cdp, sessionId, timeout = 10000) {
  await cdp.send('Page.enable', {}, sessionId);
  const ready = async () => (await cdp.send('Runtime.evaluate', { expression: 'document.readyState', returnByValue: true }, sessionId)).result.value;
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (['interactive', 'complete'].includes(await ready())) return; await delay(50); }
  throw new Error('page load timed out');
}

export async function attachPage(cdp, targetId) {
  return (await cdp.send('Target.attachToTarget', { targetId, flatten: true })).sessionId;
}

export async function evalValue(cdp, sessionId, expression, awaitPromise = true) {
  const result = await cdp.send('Runtime.evaluate', { expression, awaitPromise, returnByValue: true, userGesture: true }, sessionId);
  if (result.exceptionDetails) throw new Error('browser evaluation failed');
  return result.result.value;
}

export async function browserWebSocketFromUrl(baseUrl) {
  const response = await fetch(`${String(baseUrl).replace(/\/$/, '')}/json/version`);
  if (!response.ok) throw new Error(`Chrome debugging endpoint returned ${response.status}`);
  const url = (await response.json()).webSocketDebuggerUrl;
  if (typeof url !== 'string' || !url) throw new Error('Chrome debugging endpoint omitted webSocketDebuggerUrl');
  return url;
}

export async function browserWebSocketFromPort(port) {
  return browserWebSocketFromUrl(`http://127.0.0.1:${port}`);
}

export async function resolveCdpEndpoint(value) {
  if (typeof value !== 'string' || !value) throw new Error('CDP endpoint is required');
  const raw = value.startsWith('cdp:') ? value.slice(4) : value;
  if (/^wss?:\/\//.test(raw)) return raw;
  if (/^https?:\/\//.test(raw)) return browserWebSocketFromUrl(raw);
  throw new Error('CDP endpoint must be a ws(s) or http(s) URL');
}
