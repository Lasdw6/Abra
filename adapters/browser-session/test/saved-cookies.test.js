import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createCipheriv, createHash, pbkdf2Sync } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { readSavedCookies } from '../lib/saved-cookies.js';
import { captureSavedCookieTab } from '../lib/browser.js';

const password = 'synthetic safe storage key';

function encrypted(host, value, { hash = true, prefix = 'v10' } = {}) {
  const body = hash ? Buffer.concat([createHash('sha256').update(host).digest(), Buffer.from(value)]) : Buffer.from(value);
  const cipher = createCipheriv('aes-128-cbc', pbkdf2Sync(password, 'saltysalt', 1003, 16, 'sha1'), Buffer.alloc(16, 0x20));
  return Buffer.concat([Buffer.from(prefix), cipher.update(body), cipher.final()]);
}

async function fixture(rows, version = 24) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-saved-cookies-'));
  const file = path.join(root, 'Cookies');
  const db = new DatabaseSync(file);
  db.exec('CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR); CREATE TABLE cookies (host_key TEXT, name TEXT, path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER, priority INTEGER, encrypted_value BLOB, source_scheme INTEGER, source_port INTEGER, top_frame_site_key TEXT, has_cross_site_ancestor INTEGER)');
  db.prepare('INSERT INTO meta(key,value) VALUES (?,?)').run('version', String(version));
  const insert = db.prepare('INSERT INTO cookies VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)');
  for (const row of rows) insert.run(row.host, row.name, row.path || '/', row.expires || 0, row.secure ? 1 : 0, row.httpOnly ? 1 : 0, row.sameSite ?? -1, row.priority ?? 1, row.encrypted, row.sourceScheme ?? 2, row.sourcePort ?? 443, row.partition || '', row.crossSite ? 1 : 0);
  db.close(); await chmod(file, 0o444);
  return { root, file };
}

test('saved cookie reader selects only cookies eligible for the exact URL and never writes its source', async () => {
  const { root, file } = await fixture([
    { host: '.github.com', name: 'session', path: '/', secure: true, httpOnly: true, sameSite: 1, encrypted: encrypted('.github.com', 'secret') },
    { host: 'github.com', name: 'wrong-path', path: '/settings', encrypted: encrypted('github.com', 'no') },
    { host: '.example.com', name: 'unrelated', encrypted: encrypted('.example.com', 'no') },
    { host: '.github.com', name: 'wrong-partition', partition: 'https://example.com', encrypted: encrypted('.github.com', 'no') },
    { host: '.github.com', name: 'partitioned', partition: 'https://github.com', crossSite: true, encrypted: encrypted('.github.com', 'partition') },
    { host: '.github.com', name: 'expired', expires: 11644473601000000n, encrypted: encrypted('.github.com', 'expired') }
  ]);
  try {
    const before = createHash('sha256').update(await readFile(file)).digest('hex');
    let keyCalls = 0;
    const cookies = await readSavedCookies({ databasePath: file, expectedUrl: 'https://github.com/Lasdw6/morse', keyProvider: async () => { keyCalls++; return password; } });
    assert.deepEqual(cookies.map(cookie => cookie.name), ['session']);
    assert.equal(cookies[0].value, 'secret');
    assert.equal(cookies[0].httpOnly, true);
    assert.equal(cookies[0].sameSite, 'Lax');
    assert.equal(keyCalls, 1);
    assert.equal(createHash('sha256').update(await readFile(file)).digest('hex'), before);
  } finally { await chmod(file, 0o600); await rm(root, { recursive: true, force: true }); }
});

test('saved cookie reader includes committed WAL rows without creating source sidecars or changing source bytes', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-saved-cookie-wal-'));
  const file = path.join(root, 'Cookies');
  const db = new DatabaseSync(file);
  try {
    db.exec('PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT); CREATE TABLE cookies (host_key TEXT, name TEXT, path TEXT, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER, priority INTEGER, encrypted_value BLOB);');
    db.prepare('INSERT INTO meta VALUES (?,?)').run('version', '24');
    db.prepare('INSERT INTO cookies VALUES (?,?,?,?,?,?,?,?,?)').run('github.com', 'wal-session', '/', 0, 1, 1, 1, 1, encrypted('github.com', 'from-wal'));
    const names = (await readdir(root)).sort();
    const before = Object.fromEntries(await Promise.all(names.map(async name => {
      const filename = path.join(root, name), info = await stat(filename);
      return [name, { bytes: (await readFile(filename)).toString('base64'), size: info.size, mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs, mode: info.mode }];
    })));
    const cookies = await readSavedCookies({ databasePath: file, expectedUrl: 'https://github.com/', keyProvider: async () => password });
    assert.equal(cookies.find(cookie => cookie.name === 'wal-session')?.value, 'from-wal');
    assert.deepEqual((await readdir(root)).sort(), names);
    for (const name of names) {
      const filename = path.join(root, name), info = await stat(filename);
      assert.deepEqual({ bytes: (await readFile(filename)).toString('base64'), size: info.size, mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs, mode: info.mode }, before[name]);
    }
  } finally { db.close(); await rm(root, { recursive: true, force: true }); }
});

test('saved cookie reader fails closed for unknown encryption and mismatched host hashes', async t => {
  for (const [name, bytes, message] of [
    ['unknown prefix', encrypted('github.com', 'secret', { prefix: 'v20' }), /unsupported Chrome cookie encryption/],
    ['host hash mismatch', encrypted('example.com', 'secret'), /host hash mismatch/]
  ]) await t.test(name, async () => {
    const { root, file } = await fixture([{ host: 'github.com', name: 'session', encrypted: bytes }]);
    try { await assert.rejects(readSavedCookies({ databasePath: file, expectedUrl: 'https://github.com/', keyProvider: async () => password }), message); }
    finally { await chmod(file, 0o600); await rm(root, { recursive: true, force: true }); }
  });
});

test('saved cookie reader does not request a key when no matching cookie exists', async () => {
  const { root, file } = await fixture([{ host: '.example.com', name: 'other', encrypted: encrypted('.example.com', 'secret') }]);
  try {
    const cookies = await readSavedCookies({ databasePath: file, expectedUrl: 'https://github.com/', keyProvider: async () => { throw new Error('must not run'); } });
    assert.deepEqual(cookies, []);
  } finally { await chmod(file, 0o600); await rm(root, { recursive: true, force: true }); }
});

test('saved-cookie-tab resolves one profile under the Chrome root and revalidates tab identity', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-saved-route-'));
  const profile = path.join(root, 'Profile 1');
  const db = new DatabaseSync(path.join(root, 'make-profile.sqlite'));
  db.close();
  await mkdir(profile);
  await writeFile(path.join(profile, 'Cookies'), 'fixture');
  let calls = 0, databasePath;
  try {
    const state = await captureSavedCookieTab({ type: 'saved-cookie-tab', profile: 'Profile 1', tab_id: '42', expected_url: 'https://github.com/Lasdw6/morse' }, {}, {
      root,
      listTabs: async () => { calls++; return [{ id: '42', url: 'https://github.com/Lasdw6/morse' }]; },
      readCookies: async options => { databasePath = options.databasePath; return [{ name: 'session', value: 'x', domain: '.github.com', path: '/', secure: true }]; }
    });
    assert.equal(calls, 2);
    assert.equal(databasePath, path.join(await (await import('node:fs/promises')).realpath(profile), 'Cookies'));
    assert.deepEqual(state.origins, []);
    assert.deepEqual(state.tabs, [{ url: 'https://github.com/Lasdw6/morse', title: 'https://github.com/Lasdw6/morse' }]);
    assert.equal(state.cookies.length, 1);
    await assert.rejects(captureSavedCookieTab({ profile: '../Profile 1', tab_id: '42', expected_url: 'https://github.com/' }, {}, { root }), /profile directory name/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('saved-cookie-tab rejects a Network parent symlink escaping the selected profile', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-saved-route-root-'));
  const outside = await mkdtemp(path.join(os.tmpdir(), 'abra-saved-route-outside-'));
  await mkdir(path.join(root, 'Profile 1'));
  await writeFile(path.join(outside, 'Cookies'), 'fixture');
  await symlink(outside, path.join(root, 'Profile 1', 'Network'));
  try {
    await assert.rejects(captureSavedCookieTab({ profile: 'Profile 1', tab_id: '42', expected_url: 'https://github.com/' }, {}, {
      root,
      listTabs: async () => [{ id: '42', url: 'https://github.com/' }],
      readCookies: async () => []
    }), /non-regular Network directory/);
  } finally { await Promise.all([rm(root, { recursive: true, force: true }), rm(outside, { recursive: true, force: true })]); }
});
