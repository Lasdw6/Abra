import test from 'node:test';
import assert from 'node:assert/strict';
import { createNativeBrowserOperations } from '../lib/native-browser-operations.js';

function fixture() {
  let url = 'https://example.test/notes';
  let closes = 0;
  const calls = [];
  const cdp = {
    close() { closes++; },
    async send(method, params = {}) {
      calls.push([method, params]);
      if (method === 'Target.getBrowserContexts') return { browserContextIds: ['private-context'] };
      if (method === 'Target.getTargets') return { targetInfos: [
        { targetId: 'page-1', type: 'page', title: 'Notes', url },
        { targetId: 'private-page', type: 'page', title: 'Private', url: 'https://private.test/', browserContextId: 'private-context' },
      ] };
      if (method === 'Target.getTargetInfo') return { targetInfo: { targetId: 'page-1', type: 'page', title: 'Notes', url } };
      if (method === 'Target.attachToTarget') return { sessionId: 'attached-1' };
      if (method === 'Target.detachFromTarget' || method === 'Page.enable') return {};
      if (method === 'Network.getCookies') return { cookies: [] };
      if (method === 'Runtime.evaluate') {
        const expression = params.expression;
        if (expression === 'document.readyState') return { result: { value: 'complete' } };
        if (expression === 'document.title') return { result: { value: 'Notes' } };
        if (expression === 'location.href') return { result: { value: url } };
        if (expression.includes('historyLength')) return { result: { value: { x: 0, y: 0, historyLength: 1 } } };
        if (expression.includes("querySelectorAll('video,audio')")) return { result: { value: null } };
        if (expression.includes('localStorage:entries')) return { result: { value: { origin: 'https://example.test', localStorage: [], sessionStorage: [] } } };
        if (expression.includes('indexedDB.databases')) return { result: { value: { databases: [] } } };
      }
      throw new Error(`unexpected CDP call: ${method}`);
    },
  };
  return { cdp, calls, closes: () => closes, navigate: next => { url = next; } };
}

test('native inventory uses stable session and target identity without exposing private contexts', async () => {
  const f = fixture();
  const operations = createNativeBrowserOperations(f.cdp, { browserSession: 'session-hash' });
  const report = await operations.inventory();
  assert.deepEqual(report.items.map(item => item.id), ['chrome:session-hash:page-1']);
  assert.deepEqual(report.items[0].source, {
    type: 'normal', target_id: 'page-1', expected_url: 'https://example.test/notes', browser_session: 'session-hash',
  });
  assert.equal(JSON.stringify(report).includes('private.test'), false);
  assert.deepEqual(f.calls.map(([method]) => method), ['Target.getBrowserContexts', 'Target.getTargets']);
});

test('native export rejects stale identity and captures through the supplied shared CDP connection', async () => {
  const f = fixture();
  const operations = createNativeBrowserOperations(f.cdp, { browserSession: 'session-hash' });
  const source = (await operations.inventory()).items[0].source;
  await assert.rejects(operations.export({ source: { ...source, browser_session: 'old-session' } }), error => error.code === 'not_found');
  f.navigate('https://example.test/changed');
  await assert.rejects(operations.export({ source }), error => error.code === 'not_found');
  f.navigate(source.expected_url);
  const state = await operations.export({ source });
  assert.equal(state.tabs[0].url, source.expected_url);
  assert.equal(f.closes(), 0, 'capture must not close the daemon-owned CDP connection');
  assert.equal(f.calls.some(([method]) => method === 'Target.createTarget'), false);
  assert.equal(f.calls.some(([method]) => method === 'Page.navigate' || method === 'Page.reload'), false);
});
