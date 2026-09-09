import { cp, lstat, mkdtemp, mkdir, readFile, readdir, rm } from 'node:fs/promises';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { CDP, attachPage, browserWebSocketFromPort, evalValue, waitForLoad } from './cdp.js';
import { chromeBinary, exists, managedBrowserStatus, stopChrome } from './managed.js';
import { filterState } from './util.js';

export { stopChrome } from './managed.js';

const execFileAsync = promisify(execFile);
const REMOVE_OPTIONS = { recursive: true, force: true, maxRetries: 10, retryDelay: 200 };
const PROFILE_STATE_ENTRIES = [
  'Cookies', 'Cookies-journal', 'Cookies-wal',
  'Preferences', 'Secure Preferences',
  'Local Storage', 'Session Storage', 'IndexedDB', 'WebStorage', 'Storage',
  'Network'
];
const CHROME_TABS_SCRIPT = `
const chrome = Application('Google Chrome');
if (!chrome.running()) JSON.stringify([]);
else JSON.stringify(chrome.windows().flatMap((window, windowIndex) =>
  window.tabs().map((tab, tabIndex) => ({
    id: String(window.id()) + ':' + String(tabIndex + 1),
    windowId: String(window.id()),
    windowIndex: windowIndex + 1,
    tabIndex: tabIndex + 1,
    title: tab.title(),
    url: tab.url(),
    active: window.activeTabIndex() === tabIndex + 1
  }))
));`;

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

function cookieIdentity(cookie) {
  return JSON.stringify([cookie.domain, cookie.path || '/', cookie.name, cookie.partitionKey || null]);
}

function mergeCookies(lists) {
  const seen = new Set(), cookies = [];
  for (const list of lists) {
    for (const cookie of list || []) {
      const key = cookieIdentity(cookie);
      if (seen.has(key)) continue;
      seen.add(key);
      cookies.push(cookie);
    }
  }
  return cookies;
}

async function capturePages(cdp, targets) {
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
  return { origins: [...origins.values()], tabs };
}

export async function capture(wsUrl, policy = {}, options = {}) {
  const cdp = await new CDP(wsUrl).connect();
  try {
    const cookies = (await cdp.send('Storage.getCookies', options.browserContextId ? { browserContextId: options.browserContextId } : {})).cookies;
    const targets = (await cdp.send('Target.getTargets')).targetInfos.filter(t => t.type === 'page' && /^https?:/.test(t.url) && (!options.browserContextId || t.browserContextId === options.browserContextId));
    const { origins, tabs } = await capturePages(cdp, targets);
    return filterState({ cookies, origins, tabs }, policy.includes || [], policy.excludes || [], { allowNonPortable: true });
  } finally { cdp.close(); }
}

export async function captureAllContexts(wsUrl, policy = {}) {
  const cdp = await new CDP(wsUrl).connect();
  try {
    const extra = (await cdp.send('Target.getBrowserContexts')).browserContextIds || [];
    const cookieLists = [(await cdp.send('Storage.getCookies', {})).cookies];
    for (const browserContextId of extra) {
      cookieLists.push((await cdp.send('Storage.getCookies', { browserContextId })).cookies);
    }
    const targets = (await cdp.send('Target.getTargets')).targetInfos.filter(t => t.type === 'page' && /^https?:/.test(t.url));
    const { origins, tabs } = await capturePages(cdp, targets);
    return filterState({ cookies: mergeCookies(cookieLists), origins, tabs }, policy.includes || [], policy.excludes || [], { allowNonPortable: true });
  } finally { cdp.close(); }
}

// Capture one exact page. This is the stable primitive used by clients that let
// a user choose a tab instead of exporting an entire browser context.
export async function captureTarget(wsUrl, targetId, expectedUrl, options = {}) {
  const expected = new URL(expectedUrl);
  if (!['http:', 'https:'].includes(expected.protocol)) throw new Error('selected target must use HTTP or HTTPS');
  const cdp = await new CDP(wsUrl).connect();
  let session;
  try {
    const { targetInfo } = await cdp.send('Target.getTargetInfo', { targetId: String(targetId || '') });
    if (targetInfo.type !== 'page' || new URL(targetInfo.url).href !== expected.href) throw new Error('selected target changed before capture');
    session = await attachPage(cdp, targetInfo.targetId);
    await waitForLoad(cdp, session);
    const tab = {
      url: await evalValue(cdp, session, 'location.href'),
      title: await evalValue(cdp, session, 'document.title'),
      scroll: await evalValue(cdp, session, '({x:scrollX,y:scrollY,historyLength:history.length})'),
      media: await evalValue(cdp, session, MEDIA_CAPTURE_SCRIPT).catch(() => null)
    };
    let cookies = (await cdp.send('Network.getCookies', { urls: [expected.href] }, session)).cookies;
    if (options.selectedCookieKeys !== undefined) {
      const selected = new Set(options.selectedCookieKeys);
      cookies = cookies.filter(cookie => selected.has(cookieKey(cookie)));
    }
    const origins = [];
    if (options.includeStorage !== false && options.metadataOnly !== true) {
      const basic = await evalValue(cdp, session, CAPTURE_SCRIPT);
      const indexedDB = await evalValue(cdp, session, IDB_CAPTURE_SCRIPT);
      origins.push({ ...basic, indexedDB });
    }
    const finalUrl = await evalValue(cdp, session, 'location.href');
    if (tab.url !== expected.href || finalUrl !== expected.href) throw new Error('selected target navigated during capture');
    return { cookies: cookies.map(cookie => options.metadataOnly ? { ...cookie, value: '' } : cookie), origins, tabs: [tab] };
  } finally {
    if (session) await cdp.send('Target.detachFromTarget', { sessionId: session }).catch(() => {});
    cdp.close();
  }
}

function cookieKey(cookie) {
  const host = String(cookie.domain || new URL(cookie.url).hostname).replace(/^\./, '').toLowerCase();
  return Buffer.from(JSON.stringify([host, cookie.path || '/', cookie.name, cookie.partitionKey || null])).toString('base64url');
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
      let targetId = targetByOrigin.get(origin);
      if (targetId) targetByOrigin.delete(origin);
      else targetId = (await cdp.send('Target.createTarget', { url: 'about:blank', browserContextId, background: false })).targetId;
      const session = await attachPage(cdp, targetId);
      try {
        await cdp.send('Page.navigate', { url: tab.url }, session);
        await waitForLoad(cdp, session);
        const x = Number.isFinite(tab.scroll?.x) ? tab.scroll.x : 0;
        const y = Number.isFinite(tab.scroll?.y) ? tab.scroll.y : 0;
        if (x || y) await evalValue(cdp, session, `window.scrollTo(${x}, ${y})`).catch(() => {});
        if (tab.media && Number.isFinite(tab.media.currentTime)) {
          const media = { currentTime: Math.max(0, tab.media.currentTime), paused: tab.media.paused !== false,
            playbackRate: Number.isFinite(tab.media.playbackRate) ? tab.media.playbackRate : 1,
            volume: Number.isFinite(tab.media.volume) ? Math.min(1, Math.max(0, tab.media.volume)) : 1, muted: Boolean(tab.media.muted) };
          await evalValue(cdp, session, `(async()=>{const wanted=${JSON.stringify(media)},deadline=Date.now()+10000;let item;while(Date.now()<deadline){item=[...document.querySelectorAll('video,audio')].find(x=>!x.paused)||document.querySelector('video,audio');if(item)break;await new Promise(resolve=>setTimeout(resolve,100))}if(!item)return false;item.currentTime=wanted.currentTime;item.playbackRate=wanted.playbackRate;item.volume=wanted.volume;item.muted=wanted.muted;if(wanted.paused)item.pause();else await item.play().catch(()=>{});return true})()`).catch(() => {});
        }
      } finally { await cdp.send('Target.detachFromTarget', { sessionId: session }).catch(() => {}); }
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
  const rootInfo = await lstat(root);
  if (rootInfo.isSymbolicLink()) throw new Error(`refusing Chrome profile containing symlink: ${path.basename(root)}`);
  if (!rootInfo.isDirectory()) return;
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const file = path.join(root, entry.name), info = await lstat(file);
    if (info.isSymbolicLink()) throw new Error(`refusing Chrome profile containing symlink: ${entry.name}`);
    if (info.isDirectory()) await rejectSymlinks(file);
  }
}

export function chromeRoot() {
  if (process.env.ABRA_BROWSER_CHROME_ROOT) return path.resolve(process.env.ABRA_BROWSER_CHROME_ROOT);
  return path.join(os.homedir(), 'Library', 'Application Support', 'Google', 'Chrome');
}

export async function hasDesktopChromeRoot() {
  return process.platform === 'darwin' && await exists(chromeRoot());
}

async function httpTabs(tabs) {
  return (tabs || []).filter(tab => {
    try { return ['http:', 'https:'].includes(new URL(tab.url).protocol); }
    catch { return false; }
  });
}

async function listChromeTabs() {
  if (process.env.ABRA_BROWSER_TABS_JSON) {
    try { return JSON.parse(process.env.ABRA_BROWSER_TABS_JSON); }
    catch { throw new Error('ABRA_BROWSER_TABS_JSON must be a JSON array'); }
  }
  try {
    const { stdout } = await execFileAsync('/usr/bin/osascript', ['-l', 'JavaScript', '-e', CHROME_TABS_SCRIPT]);
    return JSON.parse(stdout);
  } catch { return []; }
}

async function resolveProfile(name) {
  const root = chromeRoot();
  if (name) {
    if (!await exists(path.join(root, name))) throw new Error(`Chrome profile does not exist: ${name}`);
    return name;
  }
  let lastUsed;
  try {
    lastUsed = JSON.parse(await readFile(path.join(root, 'Local State'), 'utf8')).profile?.last_used;
  } catch { /* fall back to Default */ }
  if (lastUsed && await exists(path.join(root, lastUsed))) return lastUsed;
  if (await exists(path.join(root, 'Default'))) return 'Default';
  throw new Error('Chrome profile does not exist: Default');
}

async function copyProfileState(source, destination) {
  await mkdir(destination, { recursive: true, mode: 0o700 });
  await Promise.all(PROFILE_STATE_ENTRIES.map(async name => {
    const from = path.join(source, name);
    if (!await exists(from)) return;
    await rejectSymlinks(from);
    await cp(from, path.join(destination, name), { recursive: true, dereference: false });
  }));
}

async function withHeadlessProfile(profile, fn) {
  const sourceRoot = chromeRoot();
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'abra-browser-profile-'));
  let child;
  try {
    await copyProfileState(path.join(sourceRoot, profile), path.join(temporary, profile));
    await cp(path.join(sourceRoot, 'Local State'), path.join(temporary, 'Local State'), { dereference: false }).catch(() => {});
    const binary = await chromeBinary();
    child = spawn(binary, [
      `--user-data-dir=${temporary}`,
      `--profile-directory=${profile}`,
      '--remote-debugging-address=127.0.0.1',
      '--remote-debugging-port=0',
      '--headless=new',
      '--no-first-run',
      '--no-default-browser-check',
      ...(process.getuid?.() === 0 || process.platform === 'linux' ? ['--no-sandbox'] : []),
      ...(process.platform === 'linux' ? ['--disable-dev-shm-usage'] : []),
      'about:blank'
    ], { stdio: 'ignore' });
    let port;
    for (let attempt = 0; attempt < 200; attempt++) {
      try {
        port = Number((await readFile(path.join(temporary, 'DevToolsActivePort'), 'utf8')).split('\n')[0]);
        if (port) break;
      } catch { /* Chrome is still starting. */ }
      if (child.exitCode !== null) break;
      await delay(50);
    }
    if (!port) throw new Error('the copied Chrome profile did not start');
    return await fn(await browserWebSocketFromPort(port));
  } finally {
    if (child) await stopChrome(child.pid, temporary).catch(() => {});
    await rm(temporary, REMOVE_OPTIONS).catch(() => {});
  }
}

async function captureCopiedTab(wsUrl, url) {
  const expected = new URL(url).href;
  const cdp = await new CDP(wsUrl).connect();
  let targetId;
  try {
    const existing = (await cdp.send('Target.getTargets')).targetInfos.filter(item => item.type === 'page');
    for (const target of existing) await cdp.send('Target.closeTarget', { targetId: target.targetId }).catch(() => {});
    targetId = (await cdp.send('Target.createTarget', { url: 'about:blank', background: false })).targetId;
    const session = await attachPage(cdp, targetId);
    try {
      await cdp.send('Page.navigate', { url: expected }, session);
      await waitForLoad(cdp, session);
    } finally { await cdp.send('Target.detachFromTarget', { sessionId: session }).catch(() => {}); }
  } finally { cdp.close(); }
  return captureTarget(wsUrl, targetId, expected);
}

function parseMaxTabs(value) {
  if (value === undefined || value === '') return 25;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) throw new Error('max_tabs must be a positive integer');
  return parsed;
}

export async function captureLocalProfile(source = {}, policy = {}) {
  const profile = await resolveProfile(source.profile);
  const tabs = await httpTabs(await listChromeTabs());
  const maxTabs = parseMaxTabs(source.max_tabs);
  if (!tabs.length) return withLocalChrome(profile, ws => capture(ws, policy));
  const captured = await withHeadlessProfile(profile, async wsUrl => {
    const cookieLists = [], origins = [], seenOrigins = new Set();
    const urls = [];
    const seenUrls = new Set();
    for (const tab of tabs) {
      const href = new URL(tab.url).href;
      if (seenUrls.has(href)) continue;
      seenUrls.add(href);
      urls.push(href);
      if (urls.length >= maxTabs) break;
    }
    for (const url of urls) {
      const page = await captureCopiedTab(wsUrl, url);
      cookieLists.push(page.cookies);
      for (const origin of page.origins || []) {
        if (seenOrigins.has(origin.origin)) continue;
        seenOrigins.add(origin.origin);
        origins.push(origin);
      }
    }
    return { cookies: mergeCookies(cookieLists), origins, tabs: tabs.map(({ url, title }) => ({ url, title })) };
  });
  return filterState(captured, policy.includes || [], policy.excludes || [], { allowNonPortable: true });
}

export async function captureManaged(policy = {}) {
  const chrome = await managedBrowserStatus();
  if (!chrome) {
    throw Object.assign(new Error('no managed browser is running'), { code: 'not_found' });
  }
  return captureAllContexts(chrome.wsUrl, policy);
}

export async function captureFrom(source, policy = {}) {
  if (source.type === 'managed' || (source.type === 'local' && !await hasDesktopChromeRoot())) return captureManaged(policy);
  if (source.type === 'local') return captureLocalProfile(source, policy);
  throw new Error('unsupported browser-session source');
}

export async function launchLocalChrome(profile, { fresh = false, root } = {}) {
  const sourceRoot = chromeRoot();
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
    const binary = await chromeBinary();
    child = spawn(binary, [`--user-data-dir=${tempRoot}`, ...(fresh ? [] : [`--profile-directory=${profileName}`]), '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', '--no-first-run', '--no-default-browser-check', 'about:blank'], { stdio: 'ignore' });
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
