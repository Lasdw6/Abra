import { cp, lstat, mkdtemp, mkdir, readFile, readdir, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { CDP, attachPage, browserWebSocketFromPort, evalValue, waitForLoad } from './cdp.js';
import { filterState } from './util.js';

const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const CAPTURE_SCRIPT = `(() => {
  const entries = s => Object.keys(s).sort().map(name => ({name, value:s.getItem(name)}));
  return {origin:location.origin, localStorage:entries(localStorage), sessionStorage:entries(sessionStorage)};
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
        const scroll = await evalValue(cdp, session, '({x:scrollX,y:scrollY,historyLength:history.length})');
        tabs.push({ url: target.url, title, scroll });
      } finally { await cdp.send('Target.detachFromTarget', { sessionId: session }).catch(() => {}); }
    }
    return filterState({ cookies, origins: [...origins.values()], tabs }, policy.includes || [], policy.excludes || []);
  } finally { cdp.close(); }
}

function storageRestoreScript(originState) {
  return `(() => { const local=${JSON.stringify(originState.localStorage || [])}; const session=${JSON.stringify(originState.sessionStorage || [])}; localStorage.clear(); sessionStorage.clear(); for(const x of local)localStorage.setItem(x.name,x.value); for(const x of session)sessionStorage.setItem(x.name,x.value); return true })()`;
}

function idbRestoreScript(indexedDBState) {
  return `(() => new Promise(async (resolve,reject) => { try { for(const d of ${JSON.stringify(indexedDBState?.databases || [])}) { await new Promise((ok,bad)=>{const r=indexedDB.open(d.name,d.version||1);r.onupgradeneeded=()=>{for(const s of d.stores)if(!r.result.objectStoreNames.contains(s.name))r.result.createObjectStore(s.name,{keyPath:s.keyPath??null,autoIncrement:!!s.autoIncrement})};r.onsuccess=async()=>{const db=r.result;try{for(const s of d.stores){if(!db.objectStoreNames.contains(s.name))continue;const tx=db.transaction(s.name,'readwrite'),store=tx.objectStore(s.name);for(const row of s.records||[]){if(store.keyPath==null)store.put(row.value,row.key);else store.put(row.value)}await new Promise((a,b)=>{tx.oncomplete=a;tx.onerror=()=>b(tx.error)})}db.close();ok()}catch(e){bad(e)}};r.onerror=()=>bad(r.error)}) } resolve(true) } catch(e){reject(e)} }))()`;
}

export async function install(wsUrl, state, policy = {}, options = {}) {
  const filtered = filterState(state, policy.allows || [], policy.denies || []);
  const cdp = await new CDP(wsUrl).connect();
  const browserContextId = (await cdp.send('Target.createBrowserContext', { disposeOnDetach: false })).browserContextId;
  try {
    if (filtered.cookies.length) await cdp.send('Storage.setCookies', { cookies: filtered.cookies.map(cookieForCdp), browserContextId });
    const targetByOrigin = new Map();
    for (const origin of filtered.origins) {
      const targetId = (await cdp.send('Target.createTarget', { url: origin.origin, browserContextId, background: false })).targetId;
      targetByOrigin.set(origin.origin, targetId);
      const session = await attachPage(cdp, targetId);
      await waitForLoad(cdp, session);
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
      cookies: filtered.cookies.map(c => ({ name: c.name, domain: c.domain, path: c.path || '/', partitionKey: c.partitionKey })),
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

async function waitForExit(child, timeoutMs = 5000) {
  if (child.exitCode !== null) return;
  await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(timeoutMs)]);
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
    child?.kill('SIGTERM');
    await waitForExit(child || { exitCode: 0 });
    await rm(tempRoot, { recursive: true, force: true });
    throw new Error(`${fresh ? 'isolated import' : 'copied-profile capture'} failed; SQLite/Keychain fallback is unavailable`);
  }
}

export async function withLocalChrome(profile, fn) {
  const local = await launchLocalChrome(profile);
  let cleaning=false;
  const cleanup=async()=>{if(cleaning)return;cleaning=true;local.child.kill('SIGTERM');await waitForExit(local.child);await rm(local.tempRoot,{recursive:true,force:true});};
  const interrupted=()=>{cleanup().finally(()=>process.exit(130));};
  process.once('SIGINT',interrupted);process.once('SIGTERM',interrupted);
  try { return await fn(local.wsUrl); }
  finally { process.off('SIGINT',interrupted);process.off('SIGTERM',interrupted);await cleanup(); }
}

export async function stopLocalChrome(local) {
  local.child.kill('SIGTERM'); await waitForExit(local.child); await rm(local.tempRoot, { recursive: true, force: true });
}
