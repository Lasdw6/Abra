import { cp, lstat, mkdtemp, mkdir, readFile, readdir, rm } from 'node:fs/promises';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { CDP, attachPage, browserWebSocketFromPort, evalValue, waitForLoad } from './cdp.js';
import { filterState } from './util.js';

const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const execFileAsync = promisify(execFile);
const REMOVE_OPTIONS = { recursive: true, force: true, maxRetries: 10, retryDelay: 200 };

const CAPTURE_SCRIPT = `(() => {
  const entries = s => Object.keys(s).sort().map(name => ({name, value:s.getItem(name)}));
  return {origin:location.origin, localStorage:entries(localStorage), sessionStorage:entries(sessionStorage)};
})()`;

const MEDIA_CAPTURE_SCRIPT = `(() => {
  const media=[...document.querySelectorAll('video,audio')].find(item=>!item.paused)||document.querySelector('video,audio');
  return media ? {
    currentTime: media.currentTime,
    paused: media.paused,
    playbackRate: media.playbackRate,
    volume: media.volume,
    muted: media.muted
  } : null;
})()`;

const IDB_CAPTURE_SCRIPT = `(() => new Promise(async resolve => {
  const out={databases:[]};
  if (!indexedDB.databases) return resolve(out);
  for (const info of await indexedDB.databases()) {
    if (!info.name) continue;
    const db=await new Promise((ok,bad)=>{const r=indexedDB.open(info.name);r.onsuccess=()=>ok(r.result);r.onerror=()=>bad(r.error)});
    const d={name:info.name,version:db.version,stores:[]};
    for (const name of db.objectStoreNames) {
      const tx=db.transaction(name,'readonly'), store=tx.objectStore(name), rows=[];
      await new Promise((ok,bad)=>{const r=store.openCursor();r.onsuccess=()=>{const c=r.result;if(!c)return ok();try{rows.push({key:c.key,value:c.value})}catch{}c.continue()};r.onerror=()=>bad(r.error)});
      d.stores.push({name,keyPath:store.keyPath,autoIncrement:store.autoIncrement,records:rows});
    }
    db.close(); out.databases.push(d);
  }
  resolve(out);
}))()`;

function cookieForCdp(cookie) {
  const allowed = ['name','value','url','domain','path','secure','httpOnly','sameSite','expires','priority','sameParty','sourceScheme','sourcePort','partitionKey'];
  return Object.fromEntries(allowed.filter(k => cookie[k] !== undefined).map(k => [k, cookie[k]]));
}

export async function capture(wsUrl, policy = {}, options = {}) {
  const cdp = await new CDP(wsUrl).connect();
  try {
    const cookies = (await cdp.send('Storage.getCookies', options.browserContextId ? { browserContextId: options.browserContextId } : {})).cookies;
    const targets = (await cdp.send('Target.getTargets')).targetInfos.filter(t => t.type === 'page' && /^https?:/.test(t.url) && (!options.browserContextId || t.browserContextId === options.browserContextId));
    const origins = new Map();
    const tabs = [];
    for (const target of targets) {
      const session = await attachPage(cdp, target.targetId);
      try {
        await waitForLoad(cdp, session);
        const basic = await evalValue(cdp, session, CAPTURE_SCRIPT);
        if (!origins.has(basic.origin)) {
          let indexedDB = { databases: [] };
          try { indexedDB = await evalValue(cdp, session, IDB_CAPTURE_SCRIPT); } catch { /* best effort */ }
          origins.set(basic.origin, { ...basic, indexedDB });
        }
        const title = await evalValue(cdp, session, 'document.title');
        const url = await evalValue(cdp, session, 'location.href');
        const scroll = await evalValue(cdp, session, '({x:scrollX,y:scrollY,historyLength:history.length})');
        const media = await evalValue(cdp, session, MEDIA_CAPTURE_SCRIPT).catch(() => null);
        tabs.push({ url, title, scroll, ...(media ? { media } : {}) });
      } finally { await cdp.send('Target.detachFromTarget', { sessionId: session }).catch(() => {}); }
    }
    return filterState({ cookies, origins: [...origins.values()], tabs }, policy.includes || [], policy.excludes || [], { allowNonPortable: true });
  } finally { cdp.close(); }
}

function storageRestoreScript(originState) {
  return `(() => { const local=${JSON.stringify(originState.localStorage || [])}; const session=${JSON.stringify(originState.sessionStorage || [])}; localStorage.clear(); sessionStorage.clear(); for(const x of local)localStorage.setItem(x.name,x.value); for(const x of session)sessionStorage.setItem(x.name,x.value); return true })()`;
}

function idbRestoreScript(indexedDBState) {
  return `(() => new Promise(async (resolve,reject) => { try { for(const d of ${JSON.stringify(indexedDBState?.databases || [])}) { const create=db=>{for(const s of d.stores)if(!db.objectStoreNames.contains(s.name))db.createObjectStore(s.name,{keyPath:s.keyPath??null,autoIncrement:!!s.autoIncrement})};const open=version=>new Promise((ok,bad)=>{const r=version===undefined?indexedDB.open(d.name):indexedDB.open(d.name,version);r.onupgradeneeded=()=>create(r.result);r.onsuccess=()=>ok(r.result);r.onerror=()=>bad(r.error)});let db;try{db=await open(d.version||1)}catch(e){if(e?.name!=='VersionError')throw e;db=await open(undefined)}if(d.stores.some(s=>!db.objectStoreNames.contains(s.name))){const next=db.version+1;db.close();db=await open(next)}try{for(const s of d.stores){if(!db.objectStoreNames.contains(s.name))continue;const tx=db.transaction(s.name,'readwrite'),store=tx.objectStore(s.name);for(const row of s.records||[]){if(store.keyPath==null)store.put(row.value,row.key);else store.put(row.value)}await new Promise((a,b)=>{tx.oncomplete=a;tx.onerror=()=>b(tx.error)})}}finally{db.close()} } resolve(true) } catch(e){reject(e)} }))()`;
}

async function openBlankOrigin(cdp, sessionId, origin) {
  const body = Buffer.from('<!doctype html><title>Abra import</title>').toString('base64');
  let resolvePaused, rejectPaused;
  const paused = new Promise((resolve, reject) => { resolvePaused = resolve; rejectPaused = reject; });
  const timer = setTimeout(() => rejectPaused(new Error('origin bootstrap timed out')), 10000);
  const off = cdp.on('Fetch.requestPaused', (params, eventSessionId) => {
    if (eventSessionId && eventSessionId !== sessionId) return;
    cdp.send('Fetch.fulfillRequest', {
      requestId: params.requestId,
      responseCode: 200,
      responseHeaders: [{ name: 'Content-Type', value: 'text/html; charset=utf-8' }],
      body
    }, sessionId).then(resolvePaused, rejectPaused);
  });
  try {
    await cdp.send('Fetch.enable', { patterns: [{ resourceType: 'Document', requestStage: 'Request' }] }, sessionId);
    await Promise.all([cdp.send('Page.navigate', { url: origin }, sessionId), paused]);
  } finally {
    clearTimeout(timer);
    off();
    await cdp.send('Fetch.disable', {}, sessionId).catch(() => {});
  }
  await waitForLoad(cdp, sessionId);
}

export async function install(wsUrl, state, policy = {}, options = {}) {
  const filtered = filterState(state, policy.allows || [], policy.denies || [], { allowNonPortable: policy.allowNonPortable === true });
  const cdp = await new CDP(wsUrl).connect();
  const browserContextId = (await cdp.send('Target.createBrowserContext', { disposeOnDetach: false })).browserContextId;
  try {
    if (filtered.cookies.length) await cdp.send('Storage.setCookies', { cookies: filtered.cookies.map(cookieForCdp), browserContextId });
    const targetByOrigin = new Map();
    for (const origin of filtered.origins) {
      const targetId = (await cdp.send('Target.createTarget', { url: 'about:blank', browserContextId, background: false })).targetId;
      targetByOrigin.set(origin.origin, targetId);
      const session = await attachPage(cdp, targetId);
      await openBlankOrigin(cdp, session, origin.origin);
      await evalValue(cdp, session, storageRestoreScript(origin));
      try { await evalValue(cdp, session, idbRestoreScript(origin.indexedDB)); } catch { /* best effort */ }
      await cdp.send('Page.reload', {}, session);
      await waitForLoad(cdp, session);
      await cdp.send('Target.detachFromTarget', { sessionId: session }).catch(() => {});
    }
    for (const tab of filtered.tabs || []) {
      let origin; try { origin = new URL(tab.url).origin; } catch { continue; }
      if (targetByOrigin.has(origin)) { targetByOrigin.delete(origin); continue; }
      await cdp.send('Target.createTarget', { url: tab.url, browserContextId, background: false });
    }
    // Re-apply the filtered cookie set to targets/contexts created during this live import operation.
    await cdp.send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true });
    const off = cdp.on('Target.attachedToTarget', async params => {
      if (params.targetInfo?.browserContextId !== browserContextId) return;
      if (filtered.cookies.length) await cdp.send('Storage.setCookies', { cookies: filtered.cookies.map(cookieForCdp), browserContextId }).catch(() => {});
    });
    if (options.watchMs) await delay(options.watchMs);
    off();
    await cdp.send('Target.setAutoAttach', { autoAttach: false, waitForDebuggerOnStart: false, flatten: true }).catch(() => {});
    return {
      kind: 'dev.abra.browser-session.receipt.v1',
      installed_at: new Date().toISOString(),
      browser_context_id: browserContextId,
      cookies: filtered.cookies.map(c => Object.fromEntries([
        ['name', c.name],
        ['domain', c.domain],
        ['path', c.path || '/'],
        ['partitionKey', c.partitionKey]
      ].filter(([, value]) => value !== undefined))),
      origins: filtered.origins.map(o => o.origin),
      policy: { allow_domains: policy.allows || [], deny_domains: policy.denies || [] }
    };
  } catch (error) {
    await cdp.send('Target.disposeBrowserContext', { browserContextId }).catch(() => {});
    throw error;
  } finally { cdp.close(); }
}

export async function revoke(wsUrl, browserContextId, origins = []) {
  const cdp = await new CDP(wsUrl).connect();
  try {
    await cdp.send('Target.disposeBrowserContext', { browserContextId });
    return { revoked_at: new Date().toISOString(), browser_context_id: browserContextId, cleared_origins: origins };
  } finally { cdp.close(); }
}

async function rejectSymlinks(root) {
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const file = path.join(root, entry.name), info = await lstat(file);
    if (info.isSymbolicLink()) throw new Error(`refusing Chrome profile containing symlink: ${entry.name}`);
    if (info.isDirectory()) await rejectSymlinks(file);
  }
}

async function chromePids(profileDir) {
  if (!profileDir) return [];
  const { stdout } = await execFileAsync('/bin/ps', ['-ax', '-o', 'pid=', '-o', 'command=']);
  const marker = `--user-data-dir=${profileDir}`;
  return stdout.split('\n').flatMap(line => {
    const match = line.match(/^\s*(\d+)\s+([\s\S]+)$/);
    return match && match[2].includes(marker) ? [Number(match[1])] : [];
  });
}

function processExists(pid) {
  try { process.kill(pid, 0); return true; }
  catch (error) { if (error.code === 'ESRCH') return false; throw error; }
}

async function waitForChromeExit(pids, profileDir, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!pids.some(processExists) && !(await chromePids(profileDir)).length) return true;
    await delay(50);
  }
  return !pids.some(processExists) && !(await chromePids(profileDir)).length;
}

export async function stopChrome(pid, profileDir, timeoutMs = 5000) {
  const initial = new Set([pid, ...await chromePids(profileDir)].filter(value => Number.isSafeInteger(value) && value > 0));
  for (const processId of initial) {
    try { process.kill(processId, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
  if (await waitForChromeExit([...initial], profileDir, timeoutMs)) return;
  const remaining = new Set([[...initial].filter(processExists), await chromePids(profileDir)].flat());
  for (const processId of remaining) {
    try { process.kill(processId, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
  if (!await waitForChromeExit([...remaining], profileDir, 2000)) throw new Error(`Chrome did not exit within ${timeoutMs + 2000}ms`);
}

export async function launchLocalChrome(profile, { fresh = false, root } = {}) {
  const sourceRoot = path.join(os.homedir(), 'Library/Application Support/Google/Chrome');
  const profileName = profile || 'Default';
  const tempRoot = root || await mkdtemp(path.join(os.tmpdir(), fresh ? 'abra-browser-import-' : 'abra-browser-export-'));
  await mkdir(tempRoot, { recursive: true, mode: 0o700 });
  let child;
  try {
    if (!fresh) {
      await rejectSymlinks(path.join(sourceRoot, profileName));
      await mkdir(path.join(tempRoot, profileName), { recursive: true, mode: 0o700 });
      await cp(path.join(sourceRoot, profileName), path.join(tempRoot, profileName), { recursive: true, dereference: false });
      await cp(path.join(sourceRoot, 'Local State'), path.join(tempRoot, 'Local State'), { dereference: false }).catch(() => {});
    }
    child = spawn(CHROME, [`--user-data-dir=${tempRoot}`, ...(fresh ? [] : [`--profile-directory=${profileName}`]), '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', '--no-first-run', '--no-default-browser-check', 'about:blank'], { stdio: 'ignore' });
    let port;
    for (let i = 0; i < 200; i++) {
      try { port = Number((await readFile(path.join(tempRoot, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); break; } catch { await delay(50); }
    }
    if (!port) throw new Error('Chrome did not expose a debugging port');
    return { wsUrl: await browserWebSocketFromPort(port), child, tempRoot };
  } catch (error) {
    if (child) await stopChrome(child.pid, tempRoot);
    await rm(tempRoot, REMOVE_OPTIONS);
    throw new Error(`${fresh ? 'isolated import' : 'copied-profile capture'} failed; SQLite/Keychain fallback is unavailable`);
  }
}

export async function withLocalChrome(profile, fn) {
  const local = await launchLocalChrome(profile);
  let cleaning=false;
  const cleanup=async()=>{if(cleaning)return;cleaning=true;await stopChrome(local.child.pid,local.tempRoot);await rm(local.tempRoot,REMOVE_OPTIONS);};
  const interrupted=()=>{cleanup().finally(()=>process.exit(130));};
  process.once('SIGINT',interrupted);process.once('SIGTERM',interrupted);
  try { return await fn(local.wsUrl); }
  finally { process.off('SIGINT',interrupted);process.off('SIGTERM',interrupted);await cleanup(); }
}

export async function stopLocalChrome(local) {
  await stopChrome(local.child.pid, local.tempRoot); await rm(local.tempRoot, REMOVE_OPTIONS);
}
