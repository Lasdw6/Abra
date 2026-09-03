import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { CDP, attachPage, browserWebSocketFromPort, evalValue, waitForLoad } from '../lib/cdp.js';
import { capture, install, revoke, stopLocalChrome } from '../lib/browser.js';
import { run, summary } from '../lib/cli.js';
import { cleanupLocalProfile } from '../lib/import.js';
import { allowedDomain, canonical, filterState, loadBundle, saveBundle, signingIdentity, signObject, toStorageState, verifyObject, writeJson } from '../lib/util.js';
import { createFacade } from '../facade/server.js';

const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const NO_CHROME_MESSAGE = 'Chrome tests disabled by ABRA_BROWSER_TEST_NO_CHROME=1';
process.env.ABRA_BROWSER_DATA_DIR = await mkdtemp(path.join(os.tmpdir(), 'abra-browser-data-test-'));
test.after(() => rm(process.env.ABRA_BROWSER_DATA_DIR, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 }));

async function adapterRequest(request) {
  const child = spawn(process.execPath, [path.resolve('bin/adapter.js')], { stdio: ['pipe', 'pipe', 'pipe'], env: process.env });
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

test('DBSC heuristic remains explicitly heuristic and preserves flagged cookie', async () => {
  const dir=await mkdtemp(path.join(os.tmpdir(),'abra-dbsc-')),state={cookies:[{name:'__Host-session',value:'secret',domain:'accounts.google.com',secure:true,httpOnly:true}],origins:[],tabs:[]},manifest=await saveBundle(dir,state);
  assert.equal(manifest.non_teleportable[0].heuristic,true);assert.equal((await loadBundle(dir)).state.cookies[0].value,'secret');assert.match(summary(manifest),/heuristic/);
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

test('adapter rejects invalid source and destination forms', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-adapter-validation-'));
  const exportBase = { protocol: 'abra-adapter/1', kind: 'dev.abra.browser.session.v1', verb: 'export', options: {}, staging_dir: path.join(root, 'out') };
  for (const [index, source] of ['local:', 'cdp:not-a-websocket', '/tmp/profile', { type: 'cdp', cdp_url: 'http://127.0.0.1' }, { type: 'local' }].entries()) {
    const response = await adapterRequest({ ...exportBase, request_id: `c${index}`, source });
    assert.equal(response.error.code, 'invalid_request');
  }

  const bundle = path.join(root, 'bundle');
  await saveBundle(bundle, { cookies: [], origins: [], tabs: [] });
  const importBase = { protocol: 'abra-adapter/1', kind: 'dev.abra.browser.session.v1', verb: 'import', payload: {}, materialized_files: bundle, options: {} };
  for (const [index, destination] of ['/tmp/materialized', 'cdp:http://127.0.0.1', { cdp_url: 'ws://127.0.0.1:1' }, { type: 'cdp', cdp_url: 'http://127.0.0.1' }].entries()) {
    const response = await adapterRequest({ ...importBase, request_id: `d${index}`, destination });
    assert.equal(response.error.code, 'invalid_request');
    assert.match(response.error.message, /requires --destination local or --destination cdp/);
  }
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
  const child = spawn(CHROME, ['--headless=new', '--no-sandbox', `--user-data-dir=${root}`, '--remote-debugging-port=0', '--no-first-run', 'about:blank'], { stdio: 'ignore' });
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
  return { cdp, session, close: () => cdp.close() };
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

  const state = await capture(a.ws);
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
  assert.match(imported.error.message, /requires --destination local or --destination cdp/);
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
