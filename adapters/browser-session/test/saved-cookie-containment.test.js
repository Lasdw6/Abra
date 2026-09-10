import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { captureFrom } from '../lib/browser.js';
import { installBundle } from '../lib/import.js';
import { saveBundle } from '../lib/util.js';

test('saved-cookie capture is blocked before profile or cookie access', async () => {
  await assert.rejects(captureFrom({type:'saved-cookie-tab'}), error => error.code === 'unavailable' && /second reported source sign-out/.test(error.message));
});

test('saved-cookie bundles cannot be replayed into any browser', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-containment-'));
  const previous = process.env.ABRA_BROWSER_DATA_DIR;
  process.env.ABRA_BROWSER_DATA_DIR = path.join(root, 'identity');
  try {
    const bundle = path.join(root, 'bundle');
    await saveBundle(bundle, {cookies:[], origins:[], tabs:[]}, {source:'saved-cookie-db-read-only'});
    await assert.rejects(installBundle(bundle, {type:'cdp', cdpUrl:'ws://127.0.0.1:1'}), error => error.code === 'unavailable' && /source sign-out/.test(error.message));
  } finally {
    if (previous === undefined) delete process.env.ABRA_BROWSER_DATA_DIR;
    else process.env.ABRA_BROWSER_DATA_DIR = previous;
    await rm(root, {recursive:true, force:true});
  }
});
