import test from 'node:test';
import assert from 'node:assert/strict';
import { importIntoNormalBrowser } from '../lib/native-import.js';

function connection({ url = 'https://existing.test/', frameUrl, context } = {}) {
  const calls = [];
  const cdp = {
    calls,
    async send(method, params = {}, session) {
      calls.push({ method, params, session });
      if (method === 'Target.getBrowserContexts') return { browserContextIds: ['private'] };
      if (method === 'Target.getTargets') return { targetInfos: [{ targetId: 'existing', type: 'page', url, browserContextId: context }] };
      if (method === 'Target.attachToTarget') return { sessionId: `session-${params.targetId}` };
      if (method === 'Page.getFrameTree') return { frameTree: { frame: { url }, childFrames: frameUrl ? [{ frame: { url: frameUrl } }] : [] } };
      if (method === 'Target.createTarget') return { targetId: 'new-tab' };
      if (method === 'Runtime.evaluate') return { result: { value: 'complete' } };
      return {};
    },
  };
  return cdp;
}
const state = (patch = {}) => ({ tabs: [{ url: 'https://incoming.test/', title: 'Incoming' }], cookies: [], origins: [], ...patch });
const cookie = { name: 'session', value: 'incoming-sign-in', domain: '.incoming.test', path: '/', httpOnly: true, secure: true };

test('an import without shared state does not inspect existing tabs', async () => {
  const cdp = connection();
  await importIntoNormalBrowser(cdp, state());
  assert.equal(cdp.calls.some(call => call.method === 'Page.getFrameTree'), false);
  assert.equal(cdp.calls.some(call => call.params.targetId === 'existing'), false);
});

test('normal import opens a new default-profile tab and never changes existing tab navigation', async () => {
  const cdp = connection();
  const receipt = await importIntoNormalBrowser(cdp, state({ cookies: [cookie] }));
  assert.deepEqual(receipt.target_ids, ['new-tab']);
  const writes = cdp.calls.filter(call => ['Page.navigate', 'Page.reload', 'Target.closeTarget', 'Browser.close', 'Runtime.evaluate'].includes(call.method));
  assert.ok(writes.length);
  assert.ok(writes.every(call => call.session === 'session-new-tab'));
  assert.equal(cdp.calls.some(call => call.method === 'Target.createBrowserContext'), false);
  assert.deepEqual(cdp.calls.find(call => call.method === 'Target.createTarget').params, { url: 'about:blank', newWindow: false, background: true });
});

test('cookie conflict with an existing tab stops before any mutation', async () => {
  const cdp = connection({ url: 'https://account.incoming.test/profile' });
  await assert.rejects(importIntoNormalBrowser(cdp, state({ cookies: [cookie] })), error => error.code === 'conflict');
  assert.equal(cdp.calls.some(call => ['Storage.setCookies', 'Target.createTarget', 'Page.navigate', 'Runtime.evaluate'].includes(call.method)), false);
});

test('shared local storage in an existing embedded frame blocks restoration', async () => {
  const cdp = connection({ frameUrl: 'https://incoming.test/frame' });
  await assert.rejects(importIntoNormalBrowser(cdp, state({ origins: [{ origin: 'https://incoming.test', localStorage: [{ name: 'account', value: 'other' }] }] })), /shared sign-in or site data/);
  assert.equal(cdp.calls.some(call => call.method === 'Target.createTarget'), false);
});

test('private contexts do not share the normal-profile storage being restored', async () => {
  const cdp = connection({ url: 'https://incoming.test/', context: 'private' });
  await importIntoNormalBrowser(cdp, state({ cookies: [cookie] }));
  assert.equal(cdp.calls.some(call => call.params.targetId === 'existing'), false);
});

test('unrelated cookie state is rejected before accessing the browser', async () => {
  const cdp = connection();
  await assert.rejects(importIntoNormalBrowser(cdp, state({ cookies: [{ ...cookie, domain: 'unrelated.test' }] })), /does not belong/);
  assert.equal(cdp.calls.length, 0);
});
