import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { CDP, attachPage, browserWebSocketFromPort, evalValue, waitForLoad } from '../lib/cdp.js';
import { capture, install, revoke } from '../lib/browser.js';
import { run, summary } from '../lib/cli.js';
import { allowedDomain, filterState, loadBundle, saveBundle, signingIdentity, signObject, toStorageState, verifyObject, writeJson } from '../lib/util.js';
import { createFacade } from '../facade/server.js';

const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
process.env.ABRA_BROWSER_DATA_DIR = await mkdtemp(path.join(os.tmpdir(), 'abra-browser-data-test-'));

test('domain policy is label-boundary based at both ends', () => {
  assert.equal(allowedDomain('a.example.com', ['example.com'], []), true);
  assert.equal(allowedDomain('badexample.com', ['example.com'], []), false);
  const state = { cookies: [{ domain: '.example.com' }, { domain: 'blocked.test' }], origins: [{ origin: 'https://a.example.com' }, { origin: 'https://blocked.test' }], tabs: [] };
  const filtered = filterState(state, ['example.com', 'blocked.test'], ['blocked.test']);
  assert.equal(filtered.cookies.length, 1); assert.equal(filtered.origins.length, 1);
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

async function chrome() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-browser-test-'));
  const child = spawn(CHROME, ['--headless=new', '--no-sandbox', `--user-data-dir=${root}`, '--remote-debugging-port=0', '--no-first-run', 'about:blank'], { stdio: 'ignore' });
  let port;
  for (let i = 0; i < 200; i++) { try { port = Number((await readFile(path.join(root, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); break; } catch { await delay(50); } }
  if (!port) throw new Error('Chrome failed to start');
  return { ws: await browserWebSocketFromPort(port), close: () => child.kill('SIGTERM') };
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

test('CDP export/import, receiver deny, inspect secrecy, and revoke', { timeout: 60000 }, async t => {
  const fixture = await fixtureServer();
  let a, b;
  try { a = await chrome(); b = await chrome(); }
  catch (error) { a?.close(); await fixture.close(); t.skip(`headless Chrome unavailable: ${error.message}`); return; }
  t.after(() => { a.close(); b.close(); return fixture.close(); });
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
