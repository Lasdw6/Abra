import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

export const KIND = 'dev.abra.browser-session.v1';

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}

export function sha256(value) {
  return createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : canonical(value)).digest('hex');
}

export function signObject(object, domain = 'browser-session-manifest') {
  const unsigned = structuredClone(object);
  delete unsigned.signature;
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const payload = Buffer.from(`abra-browser-session-v1\0${domain}\0${canonical(unsigned)}`);
  return {
    algorithm: 'Ed25519',
    domain,
    public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    value: sign(null, payload, privateKey).toString('base64url')
  };
}

export function verifyObject(object) {
  const unsigned = structuredClone(object);
  const signature = unsigned.signature;
  delete unsigned.signature;
  if (!signature || signature.algorithm !== 'Ed25519') return false;
  const payload = Buffer.from(`abra-browser-session-v1\0${signature.domain}\0${canonical(unsigned)}`);
  return verify(null, payload, { key: Buffer.from(signature.public_key, 'base64url'), type: 'spki', format: 'der' }, Buffer.from(signature.value, 'base64url'));
}

export function parseList(value) {
  return value ? [...new Set(value.split(',').map(v => v.trim().toLowerCase()).filter(Boolean))] : [];
}

export function cookieDomain(cookie) {
  return String(cookie.domain || '').replace(/^\./, '').toLowerCase();
}

export function domainMatches(host, rule) {
  host = host.toLowerCase().replace(/^\./, '');
  rule = rule.toLowerCase().replace(/^\./, '');
  return host === rule || host.endsWith(`.${rule}`);
}

export function allowedDomain(host, includes = [], excludes = []) {
  return (!includes.length || includes.some(r => domainMatches(host, r))) && !excludes.some(r => domainMatches(host, r));
}

export function filterState(state, includes = [], excludes = []) {
  const originAllowed = origin => {
    try { return allowedDomain(new URL(origin).hostname, includes, excludes); } catch { return false; }
  };
  return {
    ...state,
    cookies: (state.cookies || []).filter(c => allowedDomain(cookieDomain(c), includes, excludes)),
    origins: (state.origins || []).filter(o => originAllowed(o.origin)),
    tabs: (state.tabs || []).filter(t => originAllowed(t.url))
  };
}

export async function readJson(file) { return JSON.parse(await readFile(file, 'utf8')); }
export async function writeJson(file, value) { await writeFile(file, `${JSON.stringify(value, null, 2)}\n`); }

export async function loadBundle(dir) {
  const manifest = await readJson(path.join(dir, 'manifest.json'));
  const state = await readJson(path.join(dir, 'state.json'));
  if (manifest.kind !== KIND) throw new Error(`unsupported bundle kind: ${manifest.kind}`);
  if (!verifyObject(manifest)) throw new Error('manifest signature is invalid');
  if (manifest.state_sha256 !== sha256(state)) throw new Error('state.json does not match manifest');
  if (manifest.storage_state_sha256 !== sha256(await readFile(path.join(dir, 'storage_state.json')))) throw new Error('storage_state.json does not match manifest');
  return { manifest, state };
}

export async function saveBundle(dir, state, metadata = {}) {
  await mkdir(dir, { recursive: true });
  const storageState = metadata.storageState || toStorageState(state);
  await writeJson(path.join(dir, 'state.json'), state);
  if (metadata.storageStateRaw !== undefined) await writeFile(path.join(dir, 'storage_state.json'), metadata.storageStateRaw);
  else await writeJson(path.join(dir, 'storage_state.json'), storageState);
  const manifest = buildManifest(state, metadata);
  manifest.state_sha256 = sha256(state);
  manifest.storage_state_sha256 = sha256(await readFile(path.join(dir, 'storage_state.json')));
  manifest.signature = signObject(manifest);
  await writeJson(path.join(dir, 'manifest.json'), manifest);
  return manifest;
}

export function toStorageState(state) {
  return {
    cookies: (state.cookies || []).map(({ name, value, domain, path = '/', expires = -1, httpOnly = false, secure = false, sameSite = 'Lax' }) => ({ name, value, domain, path, expires, httpOnly, secure, sameSite })),
    origins: (state.origins || []).map(o => ({ origin: o.origin, localStorage: o.localStorage || [] }))
  };
}

const DBSC_DOMAINS = ['accounts.google.com', 'google.com', 'googleapis.com', 'workspace.google.com'];

function dbscReasons(domain, cookies) {
  const reasons = [];
  if (DBSC_DOMAINS.some(d => domainMatches(domain, d))) reasons.push('known DBSC-capable domain');
  if (cookies.some(c => c.secure && c.httpOnly && /(^__Host-|bound|device|session|sid)/i.test(c.name))) reasons.push('Secure+HttpOnly session-name attribute hint');
  return reasons;
}

export function buildManifest(state, metadata = {}) {
  const groups = new Map();
  for (const cookie of state.cookies || []) {
    const domain = cookieDomain(cookie);
    if (!groups.has(domain)) groups.set(domain, []);
    groups.get(domain).push(cookie);
  }
  const domains = [...groups].sort(([a], [b]) => a.localeCompare(b)).map(([domain, cookies]) => ({
    domain,
    cookie_count: cookies.length,
    http_only_count: cookies.filter(c => c.httpOnly).length,
    secure_count: cookies.filter(c => c.secure).length
  }));
  const nonTeleportable = [...groups].flatMap(([domain, cookies]) => {
    const reasons = dbscReasons(domain, cookies);
    return reasons.length ? [{ domain, reasons, heuristic: true }] : [];
  });
  const origins = (state.origins || []).map(o => ({
    origin: o.origin,
    local_storage: Boolean(o.localStorage?.length),
    session_storage: Boolean(o.sessionStorage?.length),
    indexed_db: Boolean(o.indexedDB?.databases?.length)
  }));
  return {
    kind: KIND,
    version: 1,
    capture_time: metadata.captureTime || new Date().toISOString(),
    source_browser: metadata.sourceBrowser || 'Chrome via CDP',
    source: metadata.source || 'cdp',
    policy: metadata.policy || { include_domains: [], exclude_domains: [] },
    domains,
    origins,
    tabs: (state.tabs || []).map(({ url, title }) => ({ url, title })),
    total_size: Buffer.byteLength(JSON.stringify(state)),
    non_teleportable: nonTeleportable,
    cookie_flags_preserved: ['HttpOnly', 'Secure', 'SameSite', 'priority', 'sameParty', 'sourceScheme', 'sourcePort', 'partitionKey'],
    provenance: metadata.provenance || { capture: 'direct-cdp', reexportable: true }
  };
}

export function receiptPath(bundleDir) { return path.join(bundleDir, `receipt-${Date.now()}.json`); }
