import test from 'node:test';
import assert from 'node:assert/strict';
import { applyTransferPolicy, resolveNamedDestination, userOwnedDestination } from '../lib/transfer-policy.js';
import { filterState, loadBundle, saveBundle, supportsManualCookieOverride } from '../lib/util.js';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const github = { name: 'user_session', value: 'gh', domain: 'github.com', path: '/', secure: true, httpOnly: true };
const google = { name: '__Host-session', value: 'secret', domain: 'accounts.google.com', path: '/', secure: true, httpOnly: true };
const bound = { name: 'device_bound_session', value: 'fixture', domain: 'example.com', path: '/', secure: true, httpOnly: true };
const tab = { url: 'https://github.com/Lasdw6/morse', title: 'morse' };
const origin = { origin: 'https://github.com', localStorage: [{ name: 'k', value: 'v' }] };

test('user devices open tabs only; sandboxes keep portable cookies', () => {
  const state = { cookies: [github, google], origins: [origin], tabs: [tab] };
  const user = applyTransferPolicy(state, { type: 'normal' });
  assert.deepEqual(user.cookies, []);
  assert.deepEqual(user.origins, []);
  assert.equal(user.tabs[0].url, tab.url);

  const sandbox = applyTransferPolicy(state, { type: 'managed' });
  assert.deepEqual(sandbox.cookies.map(cookie => cookie.name), ['user_session']);
  assert.equal(sandbox.origins[0].origin, origin.origin);
  assert.equal(applyTransferPolicy(state, { type: 'cdp' }).cookies.length, 1);
});

test('local and omitted destinations follow whether this is a user browser', () => {
  assert.deepEqual(resolveNamedDestination(undefined, { userBrowser: true }), { type: 'normal' });
  assert.deepEqual(resolveNamedDestination('', { userBrowser: false }), { type: 'managed' });
  assert.deepEqual(resolveNamedDestination('local', { userBrowser: true }), { type: 'normal' });
  assert.deepEqual(resolveNamedDestination('local', { userBrowser: false }), { type: 'managed' });
  assert.deepEqual(resolveNamedDestination({ type: 'local' }, { userBrowser: true }), { type: 'normal' });
  assert.deepEqual(resolveNamedDestination('managed', { userBrowser: true }), { type: 'managed' });
  assert.deepEqual(resolveNamedDestination('normal', { userBrowser: false }), { type: 'normal' });
  assert.equal(resolveNamedDestination('cdp:ws://127.0.0.1:1', { userBrowser: true }), null);
  assert.equal(userOwnedDestination({ type: 'normal' }), true);
  assert.equal(userOwnedDestination({ type: 'managed' }), false);
});

test('device-bound cookies cannot be forced into a bundle', async () => {
  assert.equal(supportsManualCookieOverride, false);
  const dir = await mkdtemp(path.join(os.tmpdir(), 'abra-refuse-dbsc-'));
  try {
    const manifest = await saveBundle(dir, { cookies: [google, bound, github], origins: [], tabs: [tab] }, { allowNonPortable: true });
    assert.deepEqual((await loadBundle(dir)).state.cookies.map(cookie => cookie.name), ['user_session']);
    assert.ok(manifest.non_teleportable.some(item => item.action === 'omitted'));
    assert.equal(filterState({ cookies: [google, bound], origins: [], tabs: [] }).cookies.length, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
