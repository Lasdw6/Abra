import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import vm from 'node:vm';
import { setTimeout as delay } from 'node:timers/promises';
import { CDP, attachPage, browserWebSocketFromPort, browserWebSocketFromUrl, evalValue, resolveCdpEndpoint, waitForLoad } from '../lib/cdp.js';
import { browserInventory, capture, captureLocalTab, captureTarget, chromeTabsUnavailable, CHROME_TABS_SCRIPT, install, revoke, stopLocalChrome } from '../lib/browser.js';
import { chromeBinary, ensureManagedBrowser, stopChrome, stopManagedBrowser } from '../lib/managed.js';
import { run, summary } from '../lib/cli.js';
import { cleanupLocalProfile } from '../lib/import.js';
import { allowedDomain, assertPrivateFile, canonical, filterState, loadBundle, nonPortableCookieReasons, saveBundle, signingIdentity, signObject, toStorageState, verifyObject, writeJson } from '../lib/util.js';
import { createFacade } from '../facade/server.js';

const NO_CHROME_MESSAGE = 'Chrome tests disabled by ABRA_BROWSER_TEST_NO_CHROME=1';
process.env.ABRA_BROWSER_DATA_DIR = await mkdtemp(path.join(os.tmpdir(), 'abra-browser-data-test-'));
process.env.ABRA_BROWSER_CHROME_ROOT = path.join(process.env.ABRA_BROWSER_DATA_DIR, 'missing-chrome-root');
test.after(() => rm(process.env.ABRA_BROWSER_DATA_DIR, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 }));

async function adapterRequest(request, env = process.env) {
  const child = spawn(process.execPath, [path.resolve('bin/adapter.js')], { stdio: ['pipe', 'pipe', 'pipe'], env });
  const stdout = [], stderr = [];
  child.stdout.on('data', chunk => stdout.push(chunk));
  child.stderr.on('data', chunk => stderr.push(chunk));
  child.stdin.end(`${JSON.stringify(request)}\n`);
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
  assert.equal(code, 0, Buffer.concat(stderr).toString());
  return JSON.parse(Buffer.concat(stdout).toString().trim());
}

test('domain policy is label-boundary based at both ends', () => {
  assert.equal(allowedDomain('a.example.com', ['example.com'], []), true);
  assert.equal(allowedDomain('badexample.com', ['example.com'], []), false);
  const state = { cookies: [{ domain: '.example.com' }, { domain: 'blocked.test' }], origins: [{ origin: 'https://a.example.com' }, { origin: 'https://blocked.test' }, { origin: 'ftp://a.example.com/file' }], tabs: [{ url: 'file:///tmp/secret' }] };
  const filtered = filterState(state, ['example.com', 'blocked.test'], ['blocked.test']);
  assert.equal(filtered.cookies.length, 1); assert.equal(filtered.origins.length, 1); assert.equal(filtered.tabs.length, 0);
});

test('receiver policy closes URL, parent-domain, case, mismatch, IDN, and public-suffix bypasses', () => {
  const cookies = [
    { name:'url',value:'x',url:'https://ADMIN.Example.com/' },
    { name:'parent',value:'x',domain:'.EXAMPLE.com' },
    { name:'mismatch',value:'x',domain:'safe.test',url:'https://blocked.test/' },
    { name:'suffix',value:'x',domain:'.co.uk' },
    { name:'unicode',value:'x',domain:'.bücher.example' },
    { name:'safe',value:'x',domain:'.safe.test' }
  ];
  const result=filterState({cookies,origins:[{origin:'https://ADMIN.Example.com'},{origin:'https://co.uk'}],tabs:[{url:'https://admin.example.com/path'}]},[],['admin.example.com']);
  assert.deepEqual(result.cookies.map(c=>c.name),['unicode','safe']);assert.equal(result.origins.length,0);assert.equal(result.tabs.length,0);
  assert.equal(filterState({cookies:[cookies[4]],origins:[],tabs:[]},[],['xn--bcher-kva.example']).cookies.length,0);
});

test('persistent signatures pin domains, versions, and receipt keys', async () => {
  const id=await signingIdentity(), object={kind:'x'};object.signature=signObject(object,id,'browser-session-install-receipt');
  assert.equal(verifyObject(object,{domain:'browser-session-install-receipt',publicKey:id.publicDer,fingerprint:id.fingerprint}),true);
  assert.equal(verifyObject(object,{domain:'browser-session-manifest'}),false);
  const dir=await mkdtemp(path.join(os.tmpdir(),'abra-version-'));await saveBundle(dir,{cookies:[],origins:[],tabs:[]});const manifest=JSON.parse(await readFile(path.join(dir,'manifest.json')));manifest.version=99;manifest.signature=signObject(manifest,id,'browser-session-manifest');await writeJson(path.join(dir,'manifest.json'),manifest);await assert.rejects(loadBundle(dir),/unsupported/);
});

test('canonical signatures survive undefined object fields and reject top-level undefined', async () => {
  const identity = await signingIdentity();
  const object = { kind: 'x', optional: undefined, nested: { kept: true, omitted: undefined } };
  object.signature = signObject(object, identity, 'browser-session-install-receipt');
  const roundTripped = JSON.parse(JSON.stringify(object));
  assert.equal(verifyObject(roundTripped, { domain: 'browser-session-install-receipt', publicKey: identity.publicDer, fingerprint: identity.fingerprint }), true);
  assert.throws(() => canonical(undefined), /canonical: undefined/);
});

test('legacy hyphenated bundle kind remains verifiable', async () => {
  const dir=await mkdtemp(path.join(os.tmpdir(),'abra-legacy-kind-')),id=await signingIdentity();
  await saveBundle(dir,{cookies:[],origins:[],tabs:[]});
  const manifest=JSON.parse(await readFile(path.join(dir,'manifest.json')));manifest.kind='dev.abra.browser-session.v1';manifest.signature=signObject(manifest,id,'browser-session-manifest');await writeJson(path.join(dir,'manifest.json'),manifest);
  assert.equal((await loadBundle(dir)).manifest.kind,'dev.abra.browser-session.v1');
});

test('revoke rejects forged receipts before using paths, pids, or CDP capabilities', async () => {
  const dir=await mkdtemp(path.join(os.tmpdir(),'abra-forged-receipt-')),file=path.join(dir,'receipt.json');
  await writeFile(file,JSON.stringify({kind:'dev.abra.browser-session.receipt.v1',install_id:'evil',browser_context_id:'evil',cdp_url:'ws://127.0.0.1:1',local_chrome:{pid:-1,profile_copy:path.join(dir,'..')}}));
  await assert.rejects(run(['revoke',file],{log(){}}),/not signed/);await assert.rejects(stat(`${file}.revoked.json`));
});

test('bundle payloads and exports are private and inspect never emits values', async () => {
  const root=await mkdtemp(path.join(os.tmpdir(),'abra-modes-')),bundle=path.join(root,'bundle'),out=path.join(root,'out.json');
  const manifest=await saveBundle(bundle,{cookies:[{name:'sid',value:'alpha',domain:'example.com'}],origins:[],tabs:[{url:'https://example.com/callback?code=SUPER_SECRET',title:'x'}]});
  for(const name of ['state.json','storage_state.json','manifest.json'])assert.equal((await stat(path.join(bundle,name))).mode&0o777,0o600);
  assert.equal((await stat(bundle)).mode&0o777,0o700);let inspected='';await run(['inspect',bundle],{log(value){inspected+=value;}});assert.doesNotMatch(inspected,/alpha|SUPER_SECRET/);
  assert.doesNotMatch(JSON.stringify({payload:{manifest}}),/alpha|SUPER_SECRET/,'adapter export shape contains metadata only');
  await run(['storage-state','export',bundle,'--out',out],{log(){}});assert.equal((await stat(out)).mode&0o777,0o600);
});

test('storage projection preserves partitioning and does not invent SameSite', () => {
  const projected=toStorageState({cookies:[{name:'sid',value:'x',domain:'example.com',expires:123,httpOnly:true,secure:true,sameSite:'None',partitionKey:'https://top.test'},{name:'plain',value:'y',domain:'example.com'}],origins:[]});
  assert.equal(projected.cookies[0].partitionKey,'https://top.test');assert.equal(projected.cookies[0].sameSite,'None');assert.equal('sameSite' in projected.cookies[1],false);
});

test('device-bound cookies are omitted from bundles and rejected during import filtering', async () => {
  const dir=await mkdtemp(path.join(os.tmpdir(),'abra-dbsc-')),state={cookies:[{name:'__Host-session',value:'secret',domain:'accounts.google.com',secure:true,httpOnly:true}],origins:[],tabs:[]},manifest=await saveBundle(dir,state);
  assert.equal(manifest.non_teleportable[0].heuristic,true);assert.equal(manifest.non_teleportable[0].action,'omitted');assert.equal((await loadBundle(dir)).state.cookies.length,0);assert.doesNotMatch(await readFile(path.join(dir,'storage_state.json'),'utf8'),/secret/);assert.match(summary(manifest),/heuristic/);
  assert.equal(filterState(state).cookies.length,0);
  assert.deepEqual(nonPortableCookieReasons({name:'device_bound_session',domain:'example.com',secure:true,httpOnly:true}),['device-bound cookie name and security attributes']);
  assert.equal(nonPortableCookieReasons({name:'user_session',domain:'example.com',secure:true,httpOnly:true}).length,0);
});

test('adapter dispatches string and object export sources over NDJSON', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-adapter-dispatch-'));
  const base = { protocol: 'abra-adapter/1', kind: 'dev.abra.browser.session.v1', verb: 'export', options: {} };
  const stringResponse = await adapterRequest({ ...base, request_id: 'a1', source: 'ws://127.0.0.1:1', staging_dir: path.join(root, 'string') });
  const objectResponse = await adapterRequest({ ...base, kind: 'dev.abra.browser-session.v1', request_id: 'a2', source: { type: 'cdp', cdp_url: 'ws://127.0.0.1:1' }, staging_dir: path.join(root, 'object') });
  assert.equal(stringResponse.request_id, 'a1');
  assert.equal(objectResponse.request_id, 'a2');
  assert.equal(stringResponse.error.code, 'internal');
  assert.equal(objectResponse.error.code, 'internal');
});

test('inventory reports normal Chrome tabs once using the canonical kind', async () => {
  const previousTabs = process.env.ABRA_BROWSER_TABS_JSON;
  await mkdir(path.join(process.env.ABRA_BROWSER_CHROME_ROOT, 'Default'), { recursive: true });
  process.env.ABRA_BROWSER_TABS_JSON = JSON.stringify([{ id: '91', title: 'Alpha', url: 'https://example.com/a' }, { id: '92', title: 'Beta', url: 'https://example.org/b' }]);
  try {
    const items = await browserInventory();
    assert.deepEqual(items.map(item => item.id), ['chrome:91', 'chrome:92']);
    assert.deepEqual(new Set(items.map(item => item.kind)), new Set(['dev.abra.browser.session.v1']));
    assert.deepEqual(items[0].source, { type: 'local-tab', tab_id: '91', expected_url: 'https://example.com/a', profile: 'Default' });
    assert.ok(items.every(item => item.transferable === false));
  } finally {
    if (previousTabs === undefined) delete process.env.ABRA_BROWSER_TABS_JSON; else process.env.ABRA_BROWSER_TABS_JSON = previousTabs;
    await rm(process.env.ABRA_BROWSER_CHROME_ROOT, { recursive: true, force: true });
  }
});

test('macOS Chrome inventory script excludes private windows', () => {
  const tab = (id, title) => ({ id: () => id, title: () => title, url: () => `https://${title}.example/` });
  const window = (mode, id, tabs) => ({ mode: () => mode, id: () => id, tabs: () => tabs, activeTabIndex: () => 1 });
  const windows = [window('normal', 1, [tab(11, 'normal')]), window('incognito', 2, [tab(22, 'private')])];
  const output = vm.runInNewContext(CHROME_TABS_SCRIPT, { Application: () => ({ running: () => true, windows: () => windows }), JSON });
  const listed = JSON.parse(output);
  assert.deepEqual(listed.map(item => item.id), ['11']);
  assert.doesNotMatch(output, /private/);
});

test('macOS Chrome inventory reports AppleScript permission and timeout failures', () => {
  const denied = chromeTabsUnavailable({ stderr: 'Not authorized to send Apple events. (-1743)', code: 1 });
  assert.equal(denied.code, 'unavailable');
  assert.match(denied.message, /Not authorized.*-1743/);
  const timedOut = chromeTabsUnavailable({ killed: true, signal: 'SIGKILL' });
  assert.equal(timedOut.code, 'unavailable');
  assert.match(timedOut.message, /timed out.*Apple Events/i);
});

test('selected normal Chrome export fails when the tab closed or changed', async () => {
  const previousTabs = process.env.ABRA_BROWSER_TABS_JSON;
  await mkdir(path.join(process.env.ABRA_BROWSER_CHROME_ROOT, 'Default'), { recursive: true });
  process.env.ABRA_BROWSER_TABS_JSON = JSON.stringify([{ id: '91', title: 'Moved', url: 'https://example.com/new' }]);
  try {
    await assert.rejects(captureLocalTab({ tab_id: '91', expected_url: 'https://example.com/old', profile: 'Default' }), error => error.code === 'not_found');
    await assert.rejects(captureLocalTab({ tab_id: 'closed', expected_url: 'https://example.com/old', profile: 'Default' }), error => error.code === 'not_found');
    await assert.rejects(captureLocalTab({ tab_id: '91', expected_url: 'https://example.com/new', profile: 'Default' }), error => error.code === 'unavailable' && /temporarily disabled/.test(error.message));
  } finally {
    if (previousTabs === undefined) delete process.env.ABRA_BROWSER_TABS_JSON; else process.env.ABRA_BROWSER_TABS_JSON = previousTabs;
    await rm(process.env.ABRA_BROWSER_CHROME_ROOT, { recursive: true, force: true });
  }
});

test('failed import cleanup reports a retained profile containing sender cookies', async () => {
  const profile = path.join(process.env.ABRA_BROWSER_DATA_DIR, 'profiles', 'leftover-profile');
  let stopped = false;
  await assert.rejects(
    cleanupLocalProfile(
      { child: { pid: 123 }, tempRoot: profile },
      {
        stop: async () => { stopped = true; },
        remove: async () => { throw new Error('stubbed delete failure'); }
      }
    ),
    error => {
      assert.equal(stopped, true);
      assert.match(error.message, /sender cookies remain on disk/);
      assert.match(error.message, new RegExp(profile.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
      return true;
    }
  );
});

test('http debugging endpoints resolve through /json/version', async () => {
  const ws = 'ws://127.0.0.1:9/devtools/browser/fake';
  const hits = [];
  const server = createServer((req, res) => {
    hits.push(req.url);
    if (req.url === '/json/version') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ webSocketDebuggerUrl: ws }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const httpUrl = `http://127.0.0.1:${port}`;
  try {
    assert.equal(await browserWebSocketFromUrl(httpUrl), ws);
    assert.equal(await browserWebSocketFromUrl(`${httpUrl}/`), ws);
    assert.equal(await browserWebSocketFromPort(port), ws);
    assert.equal(await resolveCdpEndpoint(httpUrl), ws);
    assert.equal(await resolveCdpEndpoint(`cdp:${httpUrl}`), ws);
    assert.equal(await resolveCdpEndpoint(ws), ws);
    assert.equal(await resolveCdpEndpoint(`cdp:${ws}`), ws);
    assert.equal(hits.filter(url => url === '/json/version').length >= 4, true);

    const root = await mkdtemp(path.join(os.tmpdir(), 'abra-http-cdp-'));
    const exportBase = { protocol: 'abra-adapter/1', kind: 'dev.abra.browser.session.v1', verb: 'export', options: {}, staging_dir: path.join(root, 'out') };
    for (const [index, source] of [`cdp:${httpUrl}`, { type: 'cdp', cdp_url: httpUrl }].entries()) {
      const before = hits.length;
      const response = await adapterRequest({ ...exportBase, request_id: `a${index}`, source });
      assert.notEqual(response.error?.code, 'invalid_request');
      assert.equal(hits.slice(before).includes('/json/version'), true);
    }
    const beforeWs = hits.length;
    const wsResponse = await adapterRequest({ ...exportBase, request_id: 'ab', source: `cdp:${ws}` });
    assert.notEqual(wsResponse.error?.code, 'invalid_request');
    assert.equal(hits.length, beforeWs);
    const httpsResponse = await adapterRequest({ ...exportBase, request_id: 'ac', source: 'cdp:https://127.0.0.1:1' });
    assert.notEqual(httpsResponse.error?.code, 'invalid_request');

    const bundle = path.join(root, 'bundle');
    await saveBundle(bundle, { cookies: [], origins: [], tabs: [] });
    const importBase = { protocol: 'abra-adapter/1', kind: 'dev.abra.browser.session.v1', verb: 'import', payload: {}, materialized_files: bundle, options: {} };
    for (const [index, destination] of [`cdp:${httpUrl}`, { type: 'cdp', cdp_url: httpUrl }].entries()) {
      const before = hits.length;
      const response = await adapterRequest({ ...importBase, request_id: `b${index}`, destination });
      assert.notEqual(response.error?.code, 'invalid_request');
      assert.equal(hits.slice(before).includes('/json/version'), true);
    }
  } finally {
    await new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
  }
});

test('adapter rejects invalid source and destination forms', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-adapter-validation-'));
  const exportBase = { protocol: 'abra-adapter/1', kind: 'dev.abra.browser.session.v1', verb: 'export', options: {}, staging_dir: path.join(root, 'out') };
  for (const [index, source] of ['local:', 'cdp:not-a-websocket', '/tmp/profile', 'bundle:', { type: 'cdp', cdp_url: 'ftp://127.0.0.1' }, { type: 'other' }, { type: 'bundle' }].entries()) {
    const response = await adapterRequest({ ...exportBase, request_id: `c${index}`, source });
    assert.equal(response.error.code, 'invalid_request');
  }
  const selected = await adapterRequest({ ...exportBase, request_id: 'f1', source: { type: 'cdp', cdp_url: 'ws://127.0.0.1:1', target_id: 'tab', expected_url: 'https://example.com/' }, options: { selected_cookie_keys: 'bad' } });
  assert.equal(selected.error.code, 'invalid_request');
  assert.match(selected.error.message, /selected_cookie_keys/);

  const bundle = path.join(root, 'bundle');
  await saveBundle(bundle, { cookies: [], origins: [], tabs: [] });
  const importBase = { protocol: 'abra-adapter/1', kind: 'dev.abra.browser.session.v1', verb: 'import', payload: {}, materialized_files: bundle, options: {} };
  for (const [index, destination] of ['/tmp/materialized', 'cdp:ftp://127.0.0.1', { cdp_url: 'ws://127.0.0.1:1' }, { type: 'cdp', cdp_url: 'ftp://127.0.0.1' }].entries()) {
    const response = await adapterRequest({ ...importBase, request_id: `d${index}`, destination });
    assert.equal(response.error.code, 'invalid_request');
    assert.match(response.error.message, /requires --destination local, normal, managed, or cdp/);
  }
  const missing = await adapterRequest({ ...exportBase, request_id: 'c9', source: 'managed' });
  assert.equal(missing.error.code, 'not_found');
  assert.match(missing.error.message, /no managed browser is running/);
  const previewStopped = await adapterRequest({
    protocol: 'abra-adapter/1', kind: 'dev.abra.browser.session.v1', verb: 'preview',
    request_id: 'd0', source: 'managed', options: {}
  }, { ...process.env, ABRA_BROWSER_DATA_DIR: path.join(root, 'empty-managed') });
  assert.equal(previewStopped.error.code, 'not_found');
  assert.match(previewStopped.error.message, /no managed browser is running/);
});

test('adapter ignores sender payload paths and does not chmod them', async () => {
  const hostile = await mkdtemp(path.join(os.tmpdir(), 'abra-hostile-payload-'));
  const marker = path.join(hostile, 'marker');
  await writeFile(marker, 'safe');
  await chmod(hostile, 0o755);
  await chmod(marker, 0o644);
  const response = await adapterRequest({ protocol: 'abra-adapter/1', request_id: 'e1', verb: 'import', kind: 'dev.abra.browser.session.v1', payload: { bundle_path: hostile }, destination: 'local', options: {} });
  assert.equal(response.error.code, 'invalid_request');
  assert.match(response.error.message, /materialized_files is required/);
  assert.equal((await stat(hostile)).mode & 0o777, 0o755);
  assert.equal((await stat(marker)).mode & 0o777, 0o644);
});

function skipChromeTest(t) {
  if (process.env.ABRA_BROWSER_TEST_NO_CHROME !== '1') return false;
  t.skip(NO_CHROME_MESSAGE);
  return true;
}

async function chrome() {
  if (process.env.ABRA_BROWSER_TEST_NO_CHROME === '1') throw new Error(NO_CHROME_MESSAGE);
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-browser-test-'));
  const child = spawn(await chromeBinary(), ['--headless=new', '--no-sandbox', `--user-data-dir=${root}`, '--remote-debugging-port=0', '--no-first-run', 'about:blank'], { stdio: 'ignore' });
  try {
    let port;
    for (let i = 0; i < 200; i++) { try { port = Number((await readFile(path.join(root, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); break; } catch { await delay(50); } }
    if (!port) throw new Error('Chrome failed to start');
    return { ws: await browserWebSocketFromPort(port), close: () => stopLocalChrome({ child, tempRoot: root }) };
  } catch (error) {
    await stopLocalChrome({ child, tempRoot: root });
    throw error;
  }
}

async function page(ws, url, context) {
  const cdp = await new CDP(ws).connect();
  const targetId = (await cdp.send('Target.createTarget', { url, ...(context ? { browserContextId: context } : {}) })).targetId;
  const session = await attachPage(cdp, targetId); await waitForLoad(cdp, session);
  return { cdp, session, targetId, close: () => cdp.close() };
}

async function fixtureServer() {
  const server = createServer((req, res) => {
    res.setHeader('content-type', 'text/html');
    res.setHeader('set-cookie', `server_cookie=${req.headers.host.startsWith('localhost') ? 'alpha' : 'beta'}; Path=/; HttpOnly; SameSite=Lax`);
    res.end(`<!doctype html><title>${req.headers.host}</title><script>
      localStorage.setItem('local-secret', location.hostname + '-local');
      sessionStorage.setItem('session-secret', location.hostname + '-session');
      const r=indexedDB.open('abra-db',1);r.onupgradeneeded=()=>r.result.createObjectStore('things');r.onsuccess=()=>{const tx=r.result.transaction('things','readwrite');tx.objectStore('things').put({secret:location.hostname+'-idb'},'record')};
    </script>`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { port: server.address().port, close: () => new Promise(resolve => server.close(resolve)) };
}

async function conflictingDatabaseServer() {
  const server = createServer((req, res) => {
    if (req.url === '/hold') {
      setTimeout(() => { res.end('ok'); }, 300);
      return;
    }
    res.setHeader('content-type', 'text/html');
    res.end(`<!doctype html><title>conflict</title><script>indexedDB.open('abra-db',1)</script><img src="/hold">`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { port: server.address().port, close: () => new Promise(resolve => server.close(resolve)) };
}

test('CDP import restores storage before origin scripts can create a conflicting database', { timeout: 30000 }, async t => {
  if (skipChromeTest(t)) return;
  const fixture = await conflictingDatabaseServer();
  let browser;
  try { browser = await chrome(); }
  catch (error) { await fixture.close(); t.skip(`headless Chrome unavailable: ${error.message}`); return; }
  t.after(async () => { await browser.close(); await fixture.close(); });
  const origin = `http://127.0.0.1:${fixture.port}`;
  const state = { cookies: [], origins: [{ origin, localStorage: [], sessionStorage: [], indexedDB: { databases: [{ name: 'abra-db', version: 1, stores: [{ name: 'things', keyPath: null, autoIncrement: false, records: [{ key: 'record', value: { restored: true } }] }] }] } }], tabs: [] };
  const receipt = await install(browser.ws, state);
  const cdp = await new CDP(browser.ws).connect();
  const target = (await cdp.send('Target.getTargets')).targetInfos.find(x => x.browserContextId === receipt.browser_context_id && x.url.startsWith(origin));
  const session = await attachPage(cdp, target.targetId); await waitForLoad(cdp, session);
  assert.deepEqual(await evalValue(cdp, session, `new Promise((ok,bad)=>{const r=indexedDB.open('abra-db');r.onsuccess=()=>{const q=r.result.transaction('things').objectStore('things').get('record');q.onsuccess=()=>ok(q.result);q.onerror=()=>bad(q.error)}})`), { restored: true });
  cdp.close();
  await revoke(browser.ws, receipt.browser_context_id, receipt.origins);
});

test('CDP export/import, receiver deny, inspect secrecy, and revoke', { timeout: 60000 }, async t => {
  if (skipChromeTest(t)) return;
  const fixture = await fixtureServer();
  let a, b;
  try { a = await chrome(); b = await chrome(); }
  catch (error) { if (a) await a.close(); await fixture.close(); t.skip(`headless Chrome unavailable: ${error.message}`); return; }
  t.after(async () => { await Promise.all([a.close(), b.close()]); await fixture.close(); });
  const originA = `http://localhost:${fixture.port}`, originB = `http://127.0.0.1:${fixture.port}`;
  const pa = await page(a.ws, originA), pb = await page(a.ws, originB);
  await delay(300); pa.close(); pb.close();

  const selected = await captureTarget(a.ws, pa.targetId, originA);
  assert.deepEqual(selected.tabs.map(tab => tab.url), [originA + '/']);
  assert.equal(selected.cookies.some(cookie => cookie.value === 'alpha'), true);
  assert.equal(selected.cookies.some(cookie => cookie.value === 'beta'), false);
  assert.deepEqual(selected.origins.map(origin => origin.origin), [originA]);
  const alphaKey = Buffer.from(JSON.stringify(['localhost', '/', 'server_cookie', null])).toString('base64url');
  assert.deepEqual((await captureTarget(a.ws, pa.targetId, originA, { selectedCookieKeys: [alphaKey] })).cookies.map(cookie => cookie.value), ['alpha']);
  assert.equal((await captureTarget(a.ws, pa.targetId, originA, { selectedCookieKeys: [] })).cookies.length, 0);
  const selectedDir = await mkdtemp(path.join(os.tmpdir(), 'abra-selected-export-'));
  const selectedExport = await adapterRequest({ protocol: 'abra-adapter/1', request_id: 'e1', verb: 'export', kind: 'dev.abra.browser.session.v1',
    source: { type: 'cdp', cdp_url: a.ws, target_id: pa.targetId, expected_url: originA }, staging_dir: selectedDir,
    options: { exclude_domains: 'localhost' } });
  assert.equal(selectedExport.ok, true);
  assert.deepEqual((await loadBundle(selectedDir)).state, { cookies: [], origins: [], tabs: [] });
  const state = await capture(a.ws);
  const closer = await new CDP(a.ws).connect();
  await closer.send('Target.closeTarget', { targetId: pa.targetId });
  closer.close();
  const staleExport = await adapterRequest({ protocol: 'abra-adapter/1', request_id: 'e2', verb: 'export', kind: 'dev.abra.browser.session.v1',
    source: { type: 'cdp', cdp_url: a.ws, target_id: pa.targetId, expected_url: originA }, staging_dir: await mkdtemp(path.join(os.tmpdir(), 'abra-stale-export-')), options: {} });
  assert.equal(staleExport.error.code, 'not_found');

  const dir = await mkdtemp(path.join(os.tmpdir(), 'abra-bundle-'));
  const manifest = await saveBundle(dir, state, { sourceBrowser: 'test Chrome' });
  assert.equal(manifest.domains.find(d => d.domain === 'localhost').cookie_count, 1);
  assert.equal(manifest.domains.find(d => d.domain === '127.0.0.1').cookie_count, 1);
  assert.equal(manifest.origins.length, 2);
  const printed = summary(manifest);
  assert.doesNotMatch(printed, /alpha|beta|local-secret|session-secret/);

  const receipt = await install(b.ws, state, { denies: ['127.0.0.1'] });
  assert.deepEqual(receipt.origins, [originA]);
  const cdp = await new CDP(b.ws).connect();
  const contextCookies = (await cdp.send('Storage.getCookies', { browserContextId: receipt.browser_context_id })).cookies;
  assert.equal(contextCookies.some(c => c.domain === 'localhost' && c.value === 'alpha'), true);
  assert.equal(contextCookies.some(c => c.domain === '127.0.0.1'), false);
  assert.equal((await cdp.send('Storage.getCookies')).cookies.some(c => ['alpha','beta'].includes(c.value)), false, 'default context remains untouched');
  const targets = (await cdp.send('Target.getTargets')).targetInfos.filter(x => x.browserContextId === receipt.browser_context_id && x.url.startsWith(originA));
  const session = await attachPage(cdp, targets[0].targetId); await waitForLoad(cdp, session);
  assert.equal(await evalValue(cdp, session, `localStorage.getItem('local-secret')`), 'localhost-local');
  assert.equal(await evalValue(cdp, session, `sessionStorage.getItem('session-secret')`), 'localhost-session');
  assert.deepEqual(await evalValue(cdp, session, `new Promise((ok,bad)=>{const r=indexedDB.open('abra-db');r.onsuccess=()=>{const q=r.result.transaction('things').objectStore('things').get('record');q.onsuccess=()=>ok(q.result);q.onerror=()=>bad(q.error)}})`), { secret: 'localhost-idb' });
  cdp.close();

  await revoke(b.ws, receipt.browser_context_id, receipt.origins);
  const verify = await new CDP(b.ws).connect();
  await assert.rejects(verify.send('Storage.getCookies', { browserContextId: receipt.browser_context_id }));
  verify.close();
});

test('adapter rejects the daemon filesystem destination without changing bundle modes', async () => {
  const bundle = await mkdtemp(path.join(os.tmpdir(), 'abra-adapter-bundle-'));
  await saveBundle(bundle, { cookies: [], origins: [], tabs: [] });
  await chmod(bundle, 0o755);
  for (const name of ['state.json', 'storage_state.json', 'manifest.json']) await chmod(path.join(bundle, name), 0o644);
  const destinationPath = path.join(bundle, 'daemon-default-destination');
  const imported = await adapterRequest({ protocol: 'abra-adapter/1', request_id: 'b2', verb: 'import', kind: 'dev.abra.browser.session.v1', payload: {}, materialized_files: bundle, destination: destinationPath, options: {} });
  assert.equal(imported.error.code, 'invalid_request');
  assert.match(imported.error.message, /requires --destination local, normal, managed, or cdp/);
  assert.equal((await stat(bundle)).mode & 0o777, 0o755);
  for (const name of ['state.json', 'storage_state.json', 'manifest.json']) assert.equal((await stat(path.join(bundle, name))).mode & 0o777, 0o644);
});

test('storage_state import/export is byte-stable', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'abra-storage-state-'));
  const input = path.join(dir, 'input.json'), bundle = path.join(dir, 'bundle'), output = path.join(dir, 'output.json');
  const bytes = '{\n  "cookies": [],\n  "origins": []\n}\n';
  await writeFile(input, bytes);
  await run(['storage-state', 'import', input, '--out', bundle], { log() {} });
  await run(['storage-state', 'export', bundle, '--out', output], { log() {} });
  assert.equal(await readFile(output, 'utf8'), bytes);
});

test('Browser Use façade CRUD never returns cookie values', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-facade-'));
  const server = createFacade({ root, userId: 'user-1', secret:'test-secret' });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/api/v4/profiles`;
  const headers={ 'content-type':'application/json',authorization:'Bearer test-secret' };
  let response = await fetch(base, { method: 'POST', headers, body: JSON.stringify({ name: 'Migrated', cookies: [{ domain: '.example.com', name: 'sid', value: 'SUPER_SECRET' }] }) });
  assert.equal(response.status, 201); const created = await response.json();
  assert.deepEqual(created.cookieDomains, ['example.com']); assert.doesNotMatch(JSON.stringify(created), /SUPER_SECRET|"cookies"/);
  response = await fetch(`${base}/${created.id}`,{headers}); assert.doesNotMatch(await response.text(), /SUPER_SECRET|"cookies"/);
  response = await fetch(`${base}/${created.id}`, { method: 'PATCH', headers, body: JSON.stringify({ name: 'Updated' }) });
  assert.equal((await response.json()).name, 'Updated');
  response = await fetch(base,{headers}); assert.equal((await response.json()).length, 1);
  response = await fetch(`${base}/${created.id}`, { method: 'DELETE',headers }); assert.equal(response.status, 204);
  response = await fetch(`${base}/${created.id}`,{headers}); assert.equal(response.status, 404);
  response=await fetch(base,{method:'POST',headers,body:JSON.stringify({bundlePath:os.homedir()})});assert.equal(response.status,400);assert.equal(await response.text(),'{"error":"bad request"}');
});

async function runNode(script, args, env = process.env) {
  const child = spawn(process.execPath, [path.resolve(script), ...args], { stdio: ['ignore', 'pipe', 'pipe'], env });
  const stdout = [], stderr = [];
  child.stdout.on('data', chunk => stdout.push(chunk));
  child.stderr.on('data', chunk => stderr.push(chunk));
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
  return { code, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() };
}
async function fixture(args) { const result = await runNode('bin/cdp-fixture.mjs', args); assert.equal(result.code, 0, result.stderr); return JSON.parse(result.stdout); }

const SANDBOX_ORIGIN = 'http://127.0.0.1:8123';
const SANDBOX_STATE = { cookies: [{ name: 'sid', value: 'alpha', domain: '127.0.0.1', path: '/' }], origins: [{ origin: SANDBOX_ORIGIN, localStorage: [{ name: 'k', value: 'v' }], sessionStorage: [], indexedDB: { databases: [] } }], tabs: [{ url: `${SANDBOX_ORIGIN}/marker.txt`, title: 'marker' }] };

// Enough of a CDP browser (Target, Storage, Network, Page, Fetch, Runtime) to run
// import and the fixture without Chrome. It speaks WebSocket by hand so the tests
// stay dependency-free. Runtime.evaluate runs expressions in-process against fake
// storage objects.
class FakeStorage { setItem(name, value) { this[name] = String(value); } getItem(name) { return Object.hasOwn(this, name) ? this[name] : null; } removeItem(name) { delete this[name]; } clear() { for (const key of Object.keys(this)) delete this[key]; } }
async function fakeCdp() {
  const state = { cookies: [], contexts: new Set(), targets: new Map(), sessions: new Map(), intercepting: new Set(), stores: new Map(), calls: [] };
  let seq = 0; const next = prefix => `${prefix}-${++seq}`;
  const target = sessionId => { const t = state.targets.get(state.sessions.get(sessionId)); if (!t) throw new Error('No session'); return t; };
  const storeFor = t => { const key = `${t.browserContextId}|${new URL(t.url).origin}`; if (!state.stores.has(key)) state.stores.set(key, { local: new FakeStorage(), session: new FakeStorage() }); return state.stores.get(key); };
  const putCookie = (c, ctx) => {
    const domain = c.domain || new URL(c.url).hostname, cookiePath = c.path || '/';
    state.cookies = state.cookies.filter(x => !(x.ctx === ctx && x.name === c.name && x.domain === domain && x.path === cookiePath));
    state.cookies.push({ ctx, name: c.name, value: c.value, domain, path: cookiePath, secure: Boolean(c.secure), httpOnly: Boolean(c.httpOnly), ...(c.sameSite ? { sameSite: c.sameSite } : {}), expires: c.expires ?? -1 });
  };
  const handlers = {
    'Target.createBrowserContext': () => { const id = next('ctx'); state.contexts.add(id); return { browserContextId: id }; },
    'Target.disposeBrowserContext': ({ browserContextId }) => { if (!state.contexts.delete(browserContextId)) throw new Error('Failed to find context'); for (const [id, t] of state.targets) if (t.browserContextId === browserContextId) state.targets.delete(id); state.cookies = state.cookies.filter(c => c.ctx !== browserContextId); return {}; },
    'Target.getBrowserContexts': () => ({ browserContextIds: [...state.contexts] }),
    'Target.createTarget': ({ url, browserContextId }) => { const id = next('target'); state.targets.set(id, { targetId: id, url, browserContextId: browserContextId || 'default' }); return { targetId: id }; },
    'Target.getTargets': () => ({ targetInfos: [...state.targets.values()].map(t => ({ ...t, type: 'page', title: '', attached: false })) }),
    'Target.attachToTarget': ({ targetId }) => { if (!state.targets.has(targetId)) throw new Error('No target'); const id = next('session'); state.sessions.set(id, targetId); return { sessionId: id }; },
    'Target.detachFromTarget': ({ sessionId }) => { state.sessions.delete(sessionId); return {}; },
    'Target.setAutoAttach': () => ({}), 'Page.enable': () => ({}), 'Page.reload': () => ({}), 'Network.enable': () => ({}), 'Fetch.fulfillRequest': () => ({}),
    'Storage.getCookies': ({ browserContextId }) => ({ cookies: state.cookies.filter(c => c.ctx === (browserContextId || 'default')).map(({ ctx, ...c }) => c) }),
    'Storage.setCookies': ({ cookies, browserContextId }) => { for (const c of cookies) putCookie(c, browserContextId || 'default'); return {}; },
    'Network.setCookie': (params, sessionId) => { putCookie(params, target(sessionId).browserContextId); return { success: true }; },
    'Fetch.enable': (_, sessionId) => { state.intercepting.add(sessionId); return {}; },
    'Fetch.disable': (_, sessionId) => { state.intercepting.delete(sessionId); return {}; },
    'Page.navigate': ({ url }, sessionId, emit) => { const t = target(sessionId); t.url = url; if (state.intercepting.has(sessionId)) setImmediate(() => emit('Fetch.requestPaused', { requestId: next('req'), request: { url } }, sessionId)); return { frameId: 'frame' }; },
    'Runtime.evaluate': async ({ expression }, sessionId) => {
      const t = target(sessionId), store = storeFor(t), url = new URL(t.url);
      const scope = { localStorage: store.local, sessionStorage: store.session, location: { href: t.url, origin: url.origin, hostname: url.hostname }, document: { readyState: 'complete', title: '', querySelectorAll: () => [], querySelector: () => null }, indexedDB: { databases: async () => [], open() { throw new Error('no indexedDB in fake'); } }, history: { length: 1 }, scrollX: 0, scrollY: 0 };
      try { const value = await new Function(...Object.keys(scope), `return (${expression});`)(...Object.values(scope)); return { result: { type: typeof value, value } }; }
      catch (error) { return { result: { type: 'object' }, exceptionDetails: { text: error.message } }; }
    }
  };
  const server = createServer((_, res) => { res.statusCode = 404; res.end(); });
  server.on('upgrade', (req, socket) => {
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${createHash('sha1').update(`${req.headers['sec-websocket-key']}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64')}\r\n\r\n`);
    const send = value => {
      const body = Buffer.from(JSON.stringify(value)), len = body.length;
      const head = len < 126 ? Buffer.from([0x81, len]) : len < 65536 ? Buffer.from([0x81, 126, len >> 8, len & 255]) : Buffer.concat([Buffer.from([0x81, 127]), (b => { b.writeBigUInt64BE(BigInt(len)); return b; })(Buffer.alloc(8))]);
      if (!socket.destroyed) socket.write(Buffer.concat([head, body]));
    };
    const emit = (method, params, sessionId) => send({ method, params, ...(sessionId ? { sessionId } : {}) });
    const handle = async msg => {
      state.calls.push(msg.method);
      try { const handler = handlers[msg.method]; if (!handler) throw new Error(`'${msg.method}' wasn't found`); send({ id: msg.id, result: await handler(msg.params || {}, msg.sessionId, emit) }); }
      catch (error) { send({ id: msg.id, error: { message: error.message } }); }
    };
    let buffered = Buffer.alloc(0);
    socket.on('data', chunk => {
      buffered = Buffer.concat([buffered, chunk]);
      while (buffered.length >= 2) {
        const opcode = buffered[0] & 0x0f; let len = buffered[1] & 0x7f, offset = 2;
        if (len === 126) { if (buffered.length < 4) return; len = buffered.readUInt16BE(2); offset = 4; }
        else if (len === 127) { if (buffered.length < 10) return; len = Number(buffered.readBigUInt64BE(2)); offset = 10; }
        if (buffered.length < offset + 4 + len) return;
        const mask = buffered.subarray(offset, offset + 4), payload = Buffer.from(buffered.subarray(offset + 4, offset + 4 + len));
        for (let i = 0; i < len; i++) payload[i] ^= mask[i & 3];
        buffered = buffered.subarray(offset + 4 + len);
        if (opcode === 8) { socket.end(); return; }
        if (opcode === 1) handle(JSON.parse(payload.toString()));
      }
    });
    socket.on('error', () => {});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { ws: `ws://127.0.0.1:${server.address().port}/devtools/browser/fake`, state, close: () => { server.closeAllConnections?.(); return new Promise(resolve => server.close(resolve)); } };
}

test('adapter re-exports a foreign bundle unchanged and refuses non-re-exportable or tampered ones', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-bundle-source-')), other = await signingIdentity(path.join(root, 'other-install'));
  const bundle = path.join(root, 'bundle'), manifest = await saveBundle(bundle, SANDBOX_STATE, { identity: other });
  assert.notEqual(manifest.signature.fingerprint, (await signingIdentity()).fingerprint);
  const base = { protocol: 'abra-adapter/1', kind: 'dev.abra.browser.session.v1', verb: 'export', options: {} };
  for (const [index, source] of [`bundle:${bundle}`, { type: 'bundle', path: bundle }].entries()) {
    const staging = path.join(root, `staging-${index}`);
    const response = await adapterRequest({ ...base, request_id: `f${index}`, source, staging_dir: staging });
    assert.equal(response.ok, true, JSON.stringify(response));
    assert.equal(response.files_path, staging);
    assert.equal(response.payload.bundle_path, '.');
    assert.equal(response.payload.manifest.signature.fingerprint, other.fingerprint);
    assert.equal(response.floor.summary, '1 domains, 1 tabs');
    assert.doesNotMatch(JSON.stringify(response), /alpha/);
    for (const name of ['state.json', 'storage_state.json', 'manifest.json']) {
      assert.deepEqual(await readFile(path.join(staging, name)), await readFile(path.join(bundle, name)));
      assert.equal((await stat(path.join(staging, name))).mode & 0o777, 0o600);
    }
    assert.equal((await loadBundle(staging, { trustSender: other.fingerprint })).state.cookies[0].value, 'alpha');
  }
  const received = path.join(root, 'received');
  await saveBundle(received, { cookies: [], origins: [], tabs: [] }, { provenance: { capture: 'direct-cdp', reexportable: false } });
  const refused = await adapterRequest({ ...base, request_id: 'f2', source: `bundle:${received}`, staging_dir: path.join(root, 'staging-refused') });
  assert.equal(refused.error.code, 'invalid_request'); assert.match(refused.error.message, /not re-exportable/);
  await writeFile(path.join(bundle, 'state.json'), '{"cookies":[],"origins":[],"tabs":[]}\n');
  const tampered = await adapterRequest({ ...base, request_id: 'f3', source: `bundle:${bundle}`, staging_dir: path.join(root, 'staging-tampered') });
  assert.equal(tampered.error.code, 'internal');
  await assert.rejects(stat(path.join(root, 'staging-tampered', 'manifest.json')));
});

test('cdp-fixture set then get round-trips a cookie, localStorage and tab', async t => {
  const fake = await fakeCdp(); t.after(fake.close);
  const url = `${SANDBOX_ORIGIN}/marker.txt`;
  const seeded = await fixture(['set', '--cdp', fake.ws, '--url', url, '--cookie', 'sid=alpha', '--local', 'k=v']);
  assert.deepEqual([seeded.cookies, seeded.local_storage], [['sid'], ['k']]);
  const got = await fixture(['get', '--cdp', fake.ws, '--url', SANDBOX_ORIGIN]);
  assert.equal(got.origin, SANDBOX_ORIGIN);
  assert.deepEqual(got.cookies.map(c => [c.name, c.value, c.domain]), [['sid', 'alpha', '127.0.0.1']]);
  assert.deepEqual(got.local_storage, [{ name: 'k', value: 'v' }]);
  assert.deepEqual(got.tabs, [url]);
  assert.deepEqual((await fixture(['get', '--cdp', fake.ws, '--url', 'http://other.test/'])).cookies, []);
  assert.equal((await runNode('bin/cdp-fixture.mjs', ['set', '--cdp', fake.ws, '--url', url, '--cookie', 'novalue'])).code, 1);
});

test('CLI import into a CDP browser from a fresh data dir trusts only the named sender', async t => {
  const fake = await fakeCdp(); t.after(fake.close);
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-fresh-import-')), other = await signingIdentity(path.join(root, 'sandbox-install'));
  const bundle = path.join(root, 'bundle'); await saveBundle(bundle, SANDBOX_STATE, { identity: other });
  const fresh = path.join(root, 'fresh-data'), env = { ...process.env, ABRA_BROWSER_DATA_DIR: fresh };
  const untrusted = await runNode('bin/abra-browser.js', ['import', bundle, '--to', 'cdp', fake.ws], env);
  assert.equal(untrusted.code, 1); assert.match(untrusted.stderr, /untrusted sender/);
  assert.equal(fake.state.calls.length, 0, 'nothing reaches the browser before trust is settled');
  const imported = await runNode('bin/abra-browser.js', ['import', bundle, '--to', 'cdp', fake.ws, '--trust-sender', other.fingerprint], env);
  assert.equal(imported.code, 0, imported.stderr);
  const receiptPath = imported.stdout.trim();
  assert.ok(receiptPath.startsWith(path.join(fresh, 'receipts')), receiptPath);
  const receipt = JSON.parse(await readFile(receiptPath, 'utf8'));
  assert.deepEqual(receipt.cookies, [{ name: 'sid', domain: '127.0.0.1', path: '/' }]);
  assert.equal(receipt.reexportable, false);
  assert.equal(await assertPrivateFile(path.join(fresh, 'keys', 'ed25519-private.pem')), true, 'a key was created on first use');
  const got = await fixture(['get', '--cdp', fake.ws, '--url', SANDBOX_ORIGIN]);
  assert.deepEqual(got.cookies.map(c => [c.name, c.value]), [['sid', 'alpha']]);
  assert.equal(fake.state.cookies[0].ctx, receipt.browser_context_id, 'cookie lands in the import context, not the default one');
  assert.deepEqual(got.local_storage, [{ name: 'k', value: 'v' }]);
  assert.equal(got.tabs.length, 1);
});

async function markerServer() {
  const server = createServer((_, res) => { res.setHeader('content-type', 'text/plain'); res.end('marker'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { port: server.address().port, close: () => new Promise(resolve => server.close(resolve)) };
}

test('cdp-fixture seeds Chrome A and the CLI import from a fresh data dir lands in Chrome B', { timeout: 60000 }, async t => {
  if (skipChromeTest(t)) return;
  const server = await markerServer();
  let a, b;
  try { a = await chrome(); b = await chrome(); }
  catch (error) { await a?.close(); await server.close(); t.skip(`headless Chrome unavailable: ${error.message}`); return; }
  t.after(async () => { await a.close(); await b.close(); await server.close(); });
  const origin = `http://127.0.0.1:${server.port}`, url = `${origin}/marker.txt`;
  await fixture(['set', '--cdp', a.ws, '--url', url, '--cookie', 'sid=alpha', '--local', 'k=v']);
  const seeded = await fixture(['get', '--cdp', a.ws, '--url', origin]);
  assert.deepEqual(seeded.cookies.map(c => [c.name, c.value]), [['sid', 'alpha']]);
  assert.deepEqual(seeded.local_storage, [{ name: 'k', value: 'v' }]);
  assert.deepEqual(seeded.tabs, [url]);
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-chrome-transfer-')), sandbox = await signingIdentity(path.join(root, 'sandbox-install'));
  const bundle = path.join(root, 'bundle'); await saveBundle(bundle, await capture(a.ws), { identity: sandbox });
  const imported = await runNode('bin/abra-browser.js', ['import', bundle, '--to', 'cdp', b.ws, '--trust-sender', sandbox.fingerprint], { ...process.env, ABRA_BROWSER_DATA_DIR: path.join(root, 'fresh-data') });
  assert.equal(imported.code, 0, imported.stderr);
  const got = await fixture(['get', '--cdp', b.ws, '--url', origin]);
  assert.deepEqual(got.cookies.map(c => [c.name, c.value]), [['sid', 'alpha']]);
  assert.deepEqual(got.local_storage, [{ name: 'k', value: 'v' }]);
  assert.ok(got.tabs.some(tab => tab.startsWith(origin)), JSON.stringify(got.tabs));
  assert.deepEqual((await fixture(['get', '--cdp', b.ws, '--url', 'http://other.test/'])).cookies, []);
});

test('device-bound cookies stay omitted even if a caller asks to override', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'abra-override-'));
  const state = { cookies: [{ name: 'device_bound_session', value: 'fixture', domain: 'example.com', secure: true, httpOnly: true }], origins: [], tabs: [] };
  try {
    const manifest = await saveBundle(dir, state, { allowNonPortable: true });
    assert.equal((await loadBundle(dir)).state.cookies.length, 0);
    assert.equal(manifest.non_teleportable[0].action, 'omitted');
    assert.equal(filterState(state, [], ['example.com'], { allowNonPortable: true }).cookies.length, 0);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('a user Chrome root makes local import ask for the normal-browser connection instead of launching isolated Chrome', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-user-dest-'));
  await mkdir(path.join(root, 'Default'), { recursive: true });
  const bundle = path.join(root, 'bundle');
  await saveBundle(bundle, {
    cookies: [{ name: 'user_session', value: 'gh', domain: 'github.com', path: '/' }],
    origins: [{ origin: 'https://github.com', localStorage: [{ name: 'k', value: 'v' }] }],
    tabs: [{ url: 'https://github.com/Lasdw6/morse', title: 'morse' }]
  });
  const response = await adapterRequest({
    protocol: 'abra-adapter/1', kind: 'dev.abra.browser.session.v1', verb: 'import',
    request_id: 'ae', payload: {}, materialized_files: bundle, destination: 'local', options: {}
  }, { ...process.env, ABRA_BROWSER_CHROME_ROOT: root });
  assert.equal(response.ok, false);
  assert.equal(response.error.code, 'setup_required');
  assert.match(response.error.message, /native-browser-host --connect/);
});

test('local and omitted imports reuse isolated Chrome and inventory includes it beside desktop tabs', { timeout: 60000 }, async t => {
  if (skipChromeTest(t)) return;
  let started;
  try { started = await ensureManagedBrowser({ headless: true }); }
  catch (error) { t.skip(`headless Chrome unavailable: ${error.message}`); return; }
  t.after(async () => { await stopManagedBrowser().catch(() => {}); });
  const fixture = await fixtureServer();
  t.after(fixture.close);
  const origin = `http://127.0.0.1:${fixture.port}`;
  const bundle = await mkdtemp(path.join(os.tmpdir(), 'abra-managed-bundle-'));
  await saveBundle(bundle, {
    cookies: [{ name: 'sid', value: 'alpha', domain: '127.0.0.1', path: '/' }],
    origins: [{ origin, localStorage: [{ name: 'k', value: 'v' }], sessionStorage: [], indexedDB: { databases: [] } }],
    tabs: [{ url: `${origin}/`, title: 'marker' }]
  });
  const importBase = { protocol: 'abra-adapter/1', kind: 'dev.abra.browser.session.v1', verb: 'import', payload: {}, materialized_files: bundle, options: {} };
  const first = await adapterRequest({ ...importBase, request_id: '11', destination: 'local' });
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.equal(first.result.receipt.managed, true);
  assert.equal(first.result.receipt.auth_applied, true);
  const reused = await ensureManagedBrowser({ headless: true });
  assert.equal(reused.pid, started.pid);
  const second = await adapterRequest({ ...importBase, request_id: '12' });
  assert.equal(second.ok, true, JSON.stringify(second));
  assert.equal((await ensureManagedBrowser({ headless: true })).pid, started.pid);
  const staging = await mkdtemp(path.join(os.tmpdir(), 'abra-managed-export-'));
  const exported = await adapterRequest({
    protocol: 'abra-adapter/1', kind: 'dev.abra.browser.session.v1', verb: 'export',
    request_id: '13', source: 'managed', staging_dir: staging, options: {}
  });
  assert.equal(exported.ok, true, JSON.stringify(exported));
  const state = (await loadBundle(staging)).state;
  assert.equal(state.cookies.some(cookie => cookie.name === 'sid' && cookie.value === 'alpha' && cookie.domain === '127.0.0.1'), true);
  assert.equal(state.tabs.some(tab => tab.url.startsWith(origin)), true);
  const previousTabs = process.env.ABRA_BROWSER_TABS_JSON;
  await mkdir(path.join(process.env.ABRA_BROWSER_CHROME_ROOT, 'Default'), { recursive: true });
  process.env.ABRA_BROWSER_TABS_JSON = JSON.stringify([{ id: 'desktop-1', title: 'Desktop', url: 'https://example.com/desktop' }]);
  try {
    const items = await browserInventory();
    assert.equal(items.some(item => item.id === 'chrome:desktop-1'), true);
    assert.equal(items.some(item => item.id.startsWith('managed:') && item.detail.startsWith(origin)), true);
  } finally {
    if (previousTabs === undefined) delete process.env.ABRA_BROWSER_TABS_JSON; else process.env.ABRA_BROWSER_TABS_JSON = previousTabs;
    await rm(process.env.ABRA_BROWSER_CHROME_ROOT, { recursive: true, force: true });
  }
});

test('adapter preview of a managed browser returns a jpeg and tab items', { timeout: 60000 }, async t => {
  if (skipChromeTest(t)) return;
  const data = await mkdtemp(path.join(os.tmpdir(), 'abra-preview-managed-'));
  const previous = process.env.ABRA_BROWSER_DATA_DIR;
  process.env.ABRA_BROWSER_DATA_DIR = data;
  t.after(async () => {
    await stopManagedBrowser().catch(() => {});
    process.env.ABRA_BROWSER_DATA_DIR = previous;
    await rm(data, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  });
  let started;
  try { started = await ensureManagedBrowser({ headless: true }); }
  catch (error) { t.skip(`headless Chrome unavailable: ${error.message}`); return; }
  const fixture = await fixtureServer();
  t.after(fixture.close);
  const origin = `http://127.0.0.1:${fixture.port}`;
  const opened = await page(started.wsUrl, origin);
  t.after(() => opened.close());
  await delay(300);
  const response = await adapterRequest({
    protocol: 'abra-adapter/1', kind: 'dev.abra.browser.session.v1', verb: 'preview',
    request_id: 'd1', source: 'managed', options: {}
  }, { ...process.env, ABRA_BROWSER_DATA_DIR: data });
  assert.equal(response.ok, true, JSON.stringify({ ...response, data: response.data?.slice?.(0, 24) }));
  assert.equal(response.media_type, 'image/jpeg');
  assert.equal(typeof response.width, 'number');
  assert.equal(typeof response.height, 'number');
  assert.ok(response.width > 0 && response.height > 0);
  const bytes = Buffer.from(response.data, 'base64');
  assert.equal(bytes[0], 0xff);
  assert.equal(bytes[1], 0xd8);
  assert.ok(bytes.length <= 512 * 1024);
  assert.ok(response.items.some(item => item.detail?.startsWith(origin) && item.active === true), JSON.stringify(response.items));
});

test('adapter export from a cdp source includes a png thumbnail', { timeout: 60000 }, async t => {
  if (skipChromeTest(t)) return;
  const fixture = await fixtureServer();
  let browser;
  try { browser = await chrome(); }
  catch (error) { await fixture.close(); t.skip(`headless Chrome unavailable: ${error.message}`); return; }
  t.after(async () => { await browser.close(); await fixture.close(); });
  const origin = `http://127.0.0.1:${fixture.port}`;
  const opened = await page(browser.ws, origin);
  t.after(() => opened.close());
  await delay(300);
  const staging = await mkdtemp(path.join(os.tmpdir(), 'abra-cdp-thumb-'));
  const exported = await adapterRequest({
    protocol: 'abra-adapter/1', kind: 'dev.abra.browser.session.v1', verb: 'export',
    request_id: 'd2', source: { type: 'cdp', cdp_url: browser.ws }, staging_dir: staging, options: {}
  });
  assert.equal(exported.ok, true, JSON.stringify(exported.floor));
  const thumb = exported.floor.thumbnail_path;
  assert.ok(thumb);
  assert.equal(path.resolve(thumb).startsWith(os.tmpdir()), true);
  assert.equal(path.resolve(thumb).startsWith(path.resolve(staging)), false);
  const bytes = await readFile(thumb);
  assert.equal(bytes[0], 0x89);
  assert.equal(bytes[1], 0x50);
  assert.equal(bytes[2], 0x4e);
  assert.equal(bytes[3], 0x47);
  assert.ok(bytes.length <= 512 * 1024);
});

test('legacy local profile export stays disabled even with a valid saved session', { timeout: 60000 }, async t => {
  if (process.platform !== 'darwin') { t.skip('local Chrome profile capture is macOS-only'); return; }
  if (skipChromeTest(t)) return;
  let binary;
  try { binary = await chromeBinary(); }
  catch (error) { t.skip(`headless Chrome unavailable: ${error.message}`); return; }
  const fixture = await fixtureServer();
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-chrome-root-'));
  t.after(async () => { await fixture.close(); await rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 }); });
  const origin = `http://127.0.0.1:${fixture.port}`;
  const child = spawn(binary, ['--headless=new', '--no-sandbox', `--user-data-dir=${root}`, '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', '--no-first-run', '--no-default-browser-check', 'about:blank'], { stdio: 'ignore' });
  try {
    let port;
    for (let i = 0; i < 300; i++) {
      try {
        port = Number((await readFile(path.join(root, 'DevToolsActivePort'), 'utf8')).split('\n')[0]);
        if (Number.isInteger(port) && port > 0) break;
      } catch { /* still starting */ }
      await delay(50);
    }
    if (!port) throw new Error('Chrome failed to start');
    const ws = await browserWebSocketFromPort(port);
    const opened = await page(ws, origin);
    await delay(300);
    opened.close();
    const cdp = await new CDP(ws).connect();
    await cdp.send('Browser.close').catch(() => {});
    cdp.close();
    await stopChrome(child.pid, root);
  } catch (error) {
    await stopChrome(child.pid, root).catch(() => {});
    t.skip(`headless Chrome unavailable: ${error.message}`);
    return;
  }
  const staging = await mkdtemp(path.join(os.tmpdir(), 'abra-local-export-'));
  const tab = { url: `${origin}/`, title: 'fixture' };
  const exported = await adapterRequest({
    protocol: 'abra-adapter/1', kind: 'dev.abra.browser.session.v1', verb: 'export',
    request_id: '21', source: 'local', staging_dir: staging, options: {}
  }, { ...process.env, ABRA_BROWSER_CHROME_ROOT: root, ABRA_BROWSER_TABS_JSON: JSON.stringify([tab]) });
  assert.equal(exported.error.code, 'unavailable');
  assert.match(exported.error.message, /temporarily disabled/);
  await assert.rejects(stat(path.join(staging, 'state.json')));
});
