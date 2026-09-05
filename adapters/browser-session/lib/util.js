import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { chmod, lstat, mkdir, open, readFile, readdir, rename, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { domainToASCII } from 'node:url';
import { isIP } from 'node:net';

export const KIND = 'dev.abra.browser.session.v1';
export const LEGACY_KIND = 'dev.abra.browser-session.v1';
export const RECEIPT_KIND = 'dev.abra.browser-session.receipt.v1';
const SIGNING_PREFIX = 'abra-browser-session-v1';

export function dataDir() {
  if (process.env.ABRA_BROWSER_DATA_DIR) return path.resolve(process.env.ABRA_BROWSER_DATA_DIR);
  if (process.platform === 'darwin') return path.join(os.homedir(), 'Library', 'Application Support', 'Abra', 'browser-session');
  return path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share'), 'abra', 'browser-session');
}

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().filter(k => value[k] !== undefined).map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  if (value === undefined) throw new Error('canonical: undefined');
  return JSON.stringify(value);
}
export function sha256(value) { return createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : canonical(value)).digest('hex'); }

async function privateDir(dir) { await mkdir(dir, { recursive: true, mode: 0o700 }); await chmod(dir, 0o700); }
export async function secureTree(target) {
  const info = await lstat(target);
  if (info.isSymbolicLink()) throw new Error('bundle contains a symbolic link');
  if (info.isDirectory()) {
    await chmod(target, 0o700);
    for (const name of await readdir(target)) await secureTree(path.join(target, name));
  } else {
    await chmod(target, 0o600);
  }
}
export async function writePrivate(file, bytes) {
  await privateDir(path.dirname(file));
  const handle = await open(file, 'w', 0o600);
  try { await handle.writeFile(bytes); await handle.chmod(0o600); } finally { await handle.close(); }
}
export async function writeJson(file, value) { await writePrivate(file, `${JSON.stringify(value, null, 2)}\n`); }
export async function readJson(file) { return JSON.parse(await readFile(file, 'utf8')); }

export async function signingIdentity(root = dataDir()) {
  const keys = path.join(root, 'keys'), privateFile = path.join(keys, 'ed25519-private.pem'), publicFile = path.join(keys, 'ed25519-public.der');
  await privateDir(keys);
  try {
    const publicDer = await readFile(publicFile);
    return { privateKey: createPrivateKey(await readFile(privateFile, 'utf8')), publicDer, fingerprint: sha256(publicDer) };
  } catch {
    const pair = generateKeyPairSync('ed25519');
    const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicDer = pair.publicKey.export({ type: 'spki', format: 'der' });
    const suffix = `${process.pid}-${Date.now()}`;
    const tmpPrivate = `${privateFile}.${suffix}`, tmpPublic = `${publicFile}.${suffix}`;
    await writePrivate(tmpPrivate, privatePem); await writePrivate(tmpPublic, publicDer);
    try { await rename(tmpPrivate, privateFile); await rename(tmpPublic, publicFile); }
    catch { /* another process may have won initialization */ }
    const storedDer = await readFile(publicFile);
    return { privateKey: createPrivateKey(await readFile(privateFile, 'utf8')), publicDer: storedDer, fingerprint: sha256(storedDer) };
  }
}

export function signObject(object, identity, domain) {
  if (!identity?.privateKey || !identity?.publicDer) throw new Error('a persistent signing identity is required');
  const unsigned = structuredClone(object); delete unsigned.signature;
  const payload = Buffer.from(`${SIGNING_PREFIX}\0${domain}\0${canonical(unsigned)}`);
  return { algorithm: 'Ed25519', domain, public_key: identity.publicDer.toString('base64url'), fingerprint: identity.fingerprint, value: sign(null, payload, identity.privateKey).toString('base64url') };
}
export function verifyObject(object, { domain, publicKey, fingerprint } = {}) {
  const unsigned = structuredClone(object), signature = unsigned.signature; delete unsigned.signature;
  if (!signature || signature.algorithm !== 'Ed25519' || signature.domain !== domain) return false;
  const der = publicKey || Buffer.from(signature.public_key || '', 'base64url');
  if (!der.length || signature.fingerprint !== sha256(der) || (fingerprint && fingerprint !== signature.fingerprint)) return false;
  try { return verify(null, Buffer.from(`${SIGNING_PREFIX}\0${domain}\0${canonical(unsigned)}`), createPublicKey({ key: der, type: 'spki', format: 'der' }), Buffer.from(signature.value, 'base64url')); } catch { return false; }
}

export function parseList(value) { return value ? [...new Set(value.split(',').map(normalizeHost).filter(Boolean))] : []; }
export function normalizeHost(host) { return domainToASCII(String(host || '').trim().replace(/^\.+/, '').toLowerCase()).toLowerCase(); }
export function cookieDomain(cookie) { try { return cookie.domain ? normalizeHost(cookie.domain) : normalizeHost(new URL(cookie.url).hostname); } catch { return ''; } }
export function domainMatches(host, rule) { host = normalizeHost(host); rule = normalizeHost(rule); return Boolean(host && rule && (host === rule || host.endsWith(`.${rule}`))); }
export function allowedDomain(host, includes = [], excludes = []) { return (!includes.length || includes.some(r => domainMatches(host, r))) && !excludes.some(r => domainMatches(host, r)); }
const MULTIPART_SUFFIXES = new Set(['co.uk','org.uk','ac.uk','gov.uk','com.au','net.au','org.au','co.jp','co.nz','com.br','com.cn','com.sg','co.in','github.io']);
export function isPublicSuffix(host) { const h = normalizeHost(host), labels = h.split('.'); if (h === 'localhost' || isIP(h)) return false; return labels.length < 2 || MULTIPART_SUFFIXES.has(h); }
function cookieAllowed(cookie, includes, excludes) {
  const host = cookieDomain(cookie);
  if (!host || (cookie.domain && isPublicSuffix(host))) return false;
  if (cookie.domain && cookie.url) { try { if (!domainMatches(normalizeHost(new URL(cookie.url).hostname), host)) return false; } catch { return false; } }
  if (!allowedDomain(host, includes, excludes)) return false;
  // A Domain cookie applies to every subdomain, so a denied descendant makes it unsafe.
  if (cookie.domain && excludes.some(denied => domainMatches(denied, host))) return false;
  return true;
}
const BOUND_SESSION_DOMAINS = ['accounts.google.com','google.com','googleapis.com','workspace.google.com','youtube.com'];
export function nonPortableCookieReasons(cookie) {
  const domain = cookieDomain(cookie);
  const reasons = [];
  if (BOUND_SESSION_DOMAINS.some(candidate => domainMatches(domain, candidate))) reasons.push('known device-bound session domain');
  if (cookie.secure && cookie.httpOnly && /(^|[-_.])(?:dbsc|device[-_.]?bound|bound[-_.]?session)([-_.]|$)/i.test(cookie.name || '')) {
    reasons.push('device-bound cookie name and security attributes');
  }
  return reasons;
}
export function filterState(state, includes = [], excludes = [], options = {}) {
  includes = includes.map(normalizeHost); excludes = excludes.map(normalizeHost);
  const originAllowed = origin => { try { const url = new URL(origin), h = normalizeHost(url.hostname); return ['http:','https:'].includes(url.protocol) && !isPublicSuffix(h) && allowedDomain(h, includes, excludes); } catch { return false; } };
  return { ...state, cookies: (state.cookies || []).filter(c => cookieAllowed(c, includes, excludes) && (options.allowNonPortable || !nonPortableCookieReasons(c).length)), origins: (state.origins || []).filter(o => originAllowed(o.origin)), tabs: (state.tabs || []).filter(t => originAllowed(t.url)) };
}

export async function loadBundle(dir, options = {}) {
  const manifest = await loadManifest(dir, options);
  const state = await readJson(path.join(dir, 'state.json'));
  if (manifest.state_sha256 !== sha256(state)) throw new Error('state.json does not match manifest');
  if (manifest.storage_state_sha256 !== sha256(await readFile(path.join(dir, 'storage_state.json')))) throw new Error('storage_state.json does not match manifest');
  return { manifest, state };
}
export async function loadManifest(dir, options = {}) {
  const manifest = await readJson(path.join(dir, 'manifest.json'));
  if (![KIND, LEGACY_KIND].includes(manifest.kind) || manifest.version !== 1) throw new Error(`unsupported browser-session bundle kind or version: ${manifest.kind} v${manifest.version}`);
  if (!verifyObject(manifest, { domain: 'browser-session-manifest' })) throw new Error('manifest signature is invalid');
  if (options.trustSender && manifest.signature.fingerprint !== options.trustSender) throw new Error(`sender key is not trusted (fingerprint ${manifest.signature.fingerprint})`);
  return manifest;
}
export async function saveBundle(dir, state, metadata = {}) {
  await privateDir(dir);
  const blockedCookies = (state.cookies || []).filter(cookie => nonPortableCookieReasons(cookie).length);
  const portableState = { ...state, cookies: (state.cookies || []).filter(cookie => !nonPortableCookieReasons(cookie).length) };
  const storageState = blockedCookies.length ? toStorageState(portableState) : metadata.storageState || toStorageState(portableState);
  const storageStateRaw = blockedCookies.length || metadata.storageStateRaw === undefined
    ? `${JSON.stringify(storageState, null, 2)}\n`
    : metadata.storageStateRaw;
  await writeJson(path.join(dir, 'state.json'), portableState);
  await writePrivate(path.join(dir, 'storage_state.json'), storageStateRaw);
  const manifest = buildManifest(portableState, { ...metadata, blockedCookies });
  manifest.state_sha256 = sha256(portableState); manifest.storage_state_sha256 = sha256(await readFile(path.join(dir, 'storage_state.json')));
  const identity = metadata.identity || await signingIdentity();
  manifest.signature = signObject(manifest, identity, 'browser-session-manifest');
  await writeJson(path.join(dir, 'manifest.json'), manifest); return manifest;
}
export function toStorageState(state) {
  return { cookies: (state.cookies || []).map(c => Object.fromEntries(['name','value','domain','path','expires','httpOnly','secure','sameSite','partitionKey'].filter(k => c[k] !== undefined).map(k => [k,c[k]]))), origins: (state.origins || []).map(o => ({ origin:o.origin, localStorage:o.localStorage || [] })) };
}
function dbscReasons(domain,cookies) { const r=[]; if(BOUND_SESSION_DOMAINS.some(d=>domainMatches(domain,d)))r.push('known device-bound session domain'); if(cookies.some(c=>c.secure&&c.httpOnly&&/(^__Host-|^(bound|device|session|sid)([-_.]|$))/i.test(c.name)))r.push('Secure+HttpOnly session-name attribute hint'); return r; }
function blockedCookieGroups(cookies) {
  const groups = new Map();
  for (const cookie of cookies || []) {
    const domain = cookieDomain(cookie);
    if (!groups.has(domain)) groups.set(domain, { domain, cookie_count: 0, reasons: new Set() });
    const group = groups.get(domain); group.cookie_count++;
    for (const reason of nonPortableCookieReasons(cookie)) group.reasons.add(reason);
  }
  return [...groups.values()].map(group => ({ domain: group.domain, cookie_count: group.cookie_count, reasons: [...group.reasons], heuristic: true, action: 'omitted' }));
}
function safeTabUrl(value) { try { const u=new URL(value); u.search=''; u.hash=''; return u.href; } catch { return ''; } }
export function buildManifest(state, metadata={}) {
  const groups=new Map(); for(const c of state.cookies||[]){const d=cookieDomain(c);if(!groups.has(d))groups.set(d,[]);groups.get(d).push(c);}
  const domains=[...groups].sort(([a],[b])=>a.localeCompare(b)).map(([domain,cookies])=>({domain,cookie_count:cookies.length,http_only_count:cookies.filter(c=>c.httpOnly).length,secure_count:cookies.filter(c=>c.secure).length}));
  return { kind:KIND,version:1,capture_time:metadata.captureTime||new Date().toISOString(),source_browser:metadata.sourceBrowser||'Chrome via CDP',source:metadata.source||'cdp',policy:metadata.policy||{include_domains:[],exclude_domains:[]},domains,origins:(state.origins||[]).map(o=>({origin:o.origin,local_storage:Boolean(o.localStorage?.length),session_storage:Boolean(o.sessionStorage?.length),indexed_db:Boolean(o.indexedDB?.databases?.length)})),tabs:(state.tabs||[]).map(({url,title})=>({url:safeTabUrl(url),title})),total_size:Buffer.byteLength(JSON.stringify(state)),non_teleportable:[...blockedCookieGroups(metadata.blockedCookies),...[...groups].flatMap(([domain,cookies])=>{const reasons=dbscReasons(domain,cookies);return reasons.length?[{domain,reasons,heuristic:true}]:[]})],cookie_flags_preserved:['HttpOnly','Secure','SameSite','priority','sameParty','sourceScheme','sourcePort','partitionKey'],provenance:metadata.provenance||{capture:'direct-cdp',reexportable:true} };
}
export async function assertPrivateFile(file) { const mode=(await stat(file)).mode & 0o777; return mode === 0o600; }
