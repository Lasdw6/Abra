import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { CDP, browserWebSocketFromPort } from '../lib/cdp.js';
import { chromeBinary } from '../lib/managed.js';
import { install, stopLocalChrome } from '../lib/browser.js';

test('import preserves cookies rotated by the destination website', async t => {
  if (process.env.ABRA_BROWSER_TEST_NO_CHROME === '1') return t.skip('Chrome tests disabled');
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-rotation-test-'));
  const server = createServer((req, res) => {
    res.setHeader('Set-Cookie', 'session=rotated-by-server; Path=/; HttpOnly; SameSite=Lax');
    res.end('<!doctype html><title>Cookie rotation fixture</title>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const child = spawn(await chromeBinary(), ['--headless=new', '--no-sandbox', `--user-data-dir=${root}`, '--remote-debugging-port=0', '--no-first-run', 'about:blank'], { stdio: 'ignore' });
  let cdp;
  try {
    let port;
    for (let i = 0; i < 200 && !port; i++) {
      try { port = Number((await readFile(path.join(root, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); }
      catch { await delay(50); }
    }
    assert.ok(port, 'disposable Chrome starts');
    const ws = await browserWebSocketFromPort(port);
    const receipt = await install(ws, {
      cookies: [{ name: 'session', value: 'old-snapshot', domain: '127.0.0.1', path: '/', httpOnly: true }],
      origins: [], tabs: [{ url: `http://127.0.0.1:${server.address().port}/` }]
    }, {}, { watchMs: 150 });
    cdp = await new CDP(ws).connect();
    const { cookies } = await cdp.send('Storage.getCookies', { browserContextId: receipt.browser_context_id });
    assert.equal(cookies.find(cookie => cookie.name === 'session')?.value, 'rotated-by-server');
  } finally {
    cdp?.close();
    await stopLocalChrome({ child, tempRoot: root });
    await new Promise(resolve => server.close(resolve));
  }
});
