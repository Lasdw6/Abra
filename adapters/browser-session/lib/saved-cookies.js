import { DatabaseSync } from 'node:sqlite';
import { createDecipheriv, createHash, pbkdf2Sync } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const CHROME_EPOCH_SECONDS = 11644473600;

export const SAVED_COOKIE_CAPTURE_SCOPE = Object.freeze({
  source: 'saved-cookie-db-read-only',
  includes: Object.freeze(['cookies', 'selected-tab-url']),
  excludes: Object.freeze(['partitioned-cookies', 'page-state', 'localStorage', 'sessionStorage', 'IndexedDB', 'preferences', 'account-state'])
});

function chromeSafeStorageKey() {
  return new Promise((resolve, reject) => {
    execFile('/usr/bin/security', ['find-generic-password', '-w', '-s', 'Chrome Safe Storage'], { encoding: 'utf8', maxBuffer: 64 * 1024, timeout: 20000, killSignal: 'SIGKILL' }, (error, stdout) => {
      if (error) reject(Object.assign(new Error(error.killed ? 'Chrome Safe Storage access timed out' : 'Chrome Safe Storage access was denied or unavailable'), { code: 'unavailable' }));
      else resolve(stdout.replace(/[\r\n]+$/, ''));
    });
  });
}

function domainCandidates(hostname) {
  const labels = hostname.toLowerCase().split('.');
  const result = new Set([hostname.toLowerCase()]);
  for (let index = 0; index < labels.length - 1; index++) result.add(`.${labels.slice(index).join('.')}`);
  return [...result];
}

function pathMatches(requestPath, cookiePath) {
  if (requestPath === cookiePath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith('/') || requestPath[cookiePath.length] === '/';
}

function decryptCookie(row, password, databaseVersion) {
  const encrypted = Buffer.from(row.encrypted_value);
  if (encrypted.subarray(0, 3).toString() !== 'v10') throw Object.assign(new Error(`unsupported Chrome cookie encryption for ${row.host_key}`), { code: 'unsupported' });
  const key = pbkdf2Sync(password, 'saltysalt', 1003, 16, 'sha1');
  const decipher = createDecipheriv('aes-128-cbc', key, Buffer.alloc(16, 0x20));
  let plaintext;
  try { plaintext = Buffer.concat([decipher.update(encrypted.subarray(3)), decipher.final()]); }
  catch { throw Object.assign(new Error(`invalid encrypted Chrome cookie for ${row.host_key}`), { code: 'invalid' }); }
  if (databaseVersion >= 24) {
    const expected = createHash('sha256').update(row.host_key).digest();
    if (plaintext.length < expected.length || !plaintext.subarray(0, expected.length).equals(expected)) {
      throw Object.assign(new Error(`Chrome cookie host hash mismatch for ${row.host_key}`), { code: 'invalid' });
    }
    plaintext = plaintext.subarray(expected.length);
  }
  return plaintext.toString('utf8');
}

function sameSite(value) { return value === 0 ? 'None' : value === 1 ? 'Lax' : value === 2 ? 'Strict' : undefined; }
function priority(value) { return value === 0 ? 'Low' : value === 2 ? 'High' : 'Medium'; }

function identity(info) { return [info.dev, info.ino, info.size, info.mtimeMs, info.ctimeMs].join(':'); }

async function stableRead(file, optional = false) {
  for (let attempt = 0; attempt < 3; attempt++) {
    let before;
    try { before = await stat(file); }
    catch (error) { if (optional && error.code === 'ENOENT') return null; throw error; }
    const bytes = await readFile(file);
    const after = await stat(file);
    if (identity(before) === identity(after) && bytes.length === after.size) return bytes;
  }
  throw Object.assign(new Error(`Chrome cookie database changed while taking a read-only snapshot: ${path.basename(file)}`), { code: 'busy' });
}

async function snapshotDatabase(databasePath) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-cookie-snapshot-'));
  const target = path.join(root, 'Cookies');
  try {
    const [main, wal] = await Promise.all([stableRead(databasePath), stableRead(`${databasePath}-wal`, true)]);
    // Confirm neither input changed while the pair was read.
    const [mainAgain, walAgain] = await Promise.all([stableRead(databasePath), stableRead(`${databasePath}-wal`, true)]);
    if (!main.equals(mainAgain) || Boolean(wal) !== Boolean(walAgain) || (wal && !wal.equals(walAgain))) throw Object.assign(new Error('Chrome cookie database changed while taking a read-only snapshot'), { code: 'busy' });
    await writeFile(target, main, { mode: 0o600 });
    if (wal) await writeFile(`${target}-wal`, wal, { mode: 0o600 });
    return { root, target };
  } catch (error) { await rm(root, { recursive: true, force: true }); throw error; }
}

export async function readSavedCookies({ databasePath, expectedUrl, keyProvider = chromeSafeStorageKey }) {
  if (process.platform !== 'darwin' && keyProvider === chromeSafeStorageKey) throw Object.assign(new Error('saved Chrome cookie decryption is only supported on macOS'), { code: 'unsupported' });
  const expected = new URL(expectedUrl);
  if (!['http:', 'https:'].includes(expected.protocol)) throw Object.assign(new Error('expected URL must use HTTP or HTTPS'), { code: 'invalid' });
  const snapshot = await snapshotDatabase(databasePath);
  let db;
  try {
    db = new DatabaseSync(snapshot.target);
    const columns = new Set(db.prepare('PRAGMA table_info(cookies)').all().map(column => column.name));
    for (const required of ['host_key', 'name', 'path', 'expires_utc', 'is_secure', 'is_httponly', 'samesite', 'priority', 'encrypted_value']) {
      if (!columns.has(required)) throw Object.assign(new Error(`unsupported Chrome Cookies schema: missing ${required}`), { code: 'unsupported' });
    }
    const versionRow = db.prepare("SELECT value FROM meta WHERE key = 'version'").get();
    const databaseVersion = Number(versionRow?.value);
    if (!Number.isInteger(databaseVersion) || databaseVersion < 24) throw Object.assign(new Error('unsupported Chrome Cookies database version; version 24 or newer is required'), { code: 'unsupported' });
    const domains = domainCandidates(expected.hostname);
    const optional = ['source_scheme', 'source_port', 'top_frame_site_key', 'has_cross_site_ancestor'].filter(column => columns.has(column));
    const placeholders = domains.map(() => '?').join(',');
    const rows = db.prepare(`SELECT host_key,name,path,CAST(expires_utc AS TEXT) AS expires_utc,is_secure,is_httponly,samesite,priority,encrypted_value${optional.length ? `,${optional.join(',')}` : ''} FROM cookies WHERE host_key IN (${placeholders})`).all(...domains);
    const now = Date.now() / 1000;
    const eligible = rows.filter(row => (!row.is_secure || expected.protocol === 'https:')
      && pathMatches(expected.pathname || '/', row.path || '/')
      && (!Number(row.expires_utc) || Number(row.expires_utc) / 1e6 - CHROME_EPOCH_SECONDS > now)
      && !row.top_frame_site_key);
    if (!eligible.length) return [];
    const password = await keyProvider();
    if (typeof password !== 'string' || !password) throw Object.assign(new Error('Chrome Safe Storage returned no key'), { code: 'unavailable' });
    return eligible.map(row => ({
      name: row.name,
      value: decryptCookie(row, password, databaseVersion),
      domain: row.host_key,
      path: row.path || '/',
      expires: Number(row.expires_utc) ? Number(row.expires_utc) / 1e6 - CHROME_EPOCH_SECONDS : -1,
      httpOnly: Boolean(row.is_httponly),
      secure: Boolean(row.is_secure),
      sameSite: sameSite(row.samesite),
      priority: priority(row.priority),
      ...(row.source_scheme !== undefined ? { sourceScheme: row.source_scheme === 2 ? 'Secure' : row.source_scheme === 1 ? 'NonSecure' : 'Unset' } : {}),
      ...(row.source_port !== undefined && row.source_port >= 0 ? { sourcePort: row.source_port } : {}),
    }));
  } finally {
    try { db?.close(); }
    finally { await rm(snapshot.root, { recursive: true, force: true }); }
  }
}

export const savedCookieInternals = { decryptCookie, domainCandidates, pathMatches };
