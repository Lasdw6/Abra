import assert from 'node:assert/strict';
import { chmod, mkdir, readFile, stat, truncate, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdtemp } from 'node:fs/promises';
import { acquireWriterLock, exportSession, importSession, inspectSession, scanSecrets } from '../lib/session.js';

const SESSION_ID = '123e4567-e89b-42d3-a456-426614174000';
const TS = '2026-09-02T12-34-56';

function rollout(extra = []) {
  return [
    JSON.stringify({
      timestamp: '2026-09-02T12:34:56Z',
      type: 'session_meta',
      payload: {
        id: SESSION_ID,
        session_id: SESSION_ID,
        timestamp: '2026-09-02T12:34:56Z',
        cwd: '/work/demo',
        cli_version: '9.9.9',
        model_provider: 'openai',
        history_mode: 'full'
      }
    }),
    JSON.stringify({ timestamp: '2026-09-02T12:35:00Z', type: 'event_msg', payload: { type: 'user_message', message: 'hello' } }),
    ...extra.map(message => JSON.stringify({ timestamp: '2026-09-02T12:36:00Z', type: 'event_msg', payload: { type: 'agent_message', message } }))
  ].join('\n') + '\n';
}

async function putSession(home, contents = rollout()) {
  const directory = path.join(home, 'sessions', '2026', '09', '02');
  await mkdir(directory, { recursive: true });
  const file = path.join(directory, `rollout-${TS}-${SESSION_ID}.jsonl`);
  await writeFile(file, contents);
  return file;
}

async function adapterExport(home, staging, options = {}) {
  return exportSession({
    source: {
      session_id: SESSION_ID,
      codex_home: home,
      workspace_snapshot_id: 'a'.repeat(64),
      workspace_capsule_id: 'b'.repeat(64),
      workspace_name: 'demo'
    },
    staging_dir: staging,
    options
  });
}

async function adapterImport(bundle, home, payload) {
  return importSession({
    materialized_files: bundle,
    destination: { codex_home: home, workspace: '/work/demo' },
    payload,
    options: { skip_version_check: 'true' }
  });
}

test('Codex adapter round trip advances an unchanged ancestor', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-codex-'));
  const local = path.join(root, 'local');
  const cloud = path.join(root, 'cloud');
  const firstBundle = path.join(root, 'first');
  const secondBundle = path.join(root, 'second');
  const localFile = await putSession(local);

  const first = await adapterExport(local, firstBundle);
  await adapterImport(firstBundle, cloud, first.payload);
  const relative = first.payload.relative_path.split('/');
  const cloudFile = path.join(cloud, ...relative);
  await writeFile(cloudFile, rollout(['cloud changed it']));

  const second = await adapterExport(cloud, secondBundle);
  await adapterImport(secondBundle, local, second.payload);
  assert.equal(await readFile(localFile, 'utf8'), rollout(['cloud changed it']));
  assert.equal((await stat(localFile)).mode & 0o777, 0o600);
  assert.equal(second.payload.ancestor_sha256, first.payload.sha256);
});

test('Codex adapter rejects divergent histories', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-codex-diverge-'));
  const local = path.join(root, 'local');
  const cloud = path.join(root, 'cloud');
  const firstBundle = path.join(root, 'first');
  const secondBundle = path.join(root, 'second');
  const localFile = await putSession(local);
  const first = await adapterExport(local, firstBundle);
  await adapterImport(firstBundle, cloud, first.payload);
  await writeFile(localFile, rollout(['local branch']));
  await writeFile(path.join(cloud, ...first.payload.relative_path.split('/')), rollout(['cloud branch']));
  const second = await adapterExport(cloud, secondBundle);
  await assert.rejects(adapterImport(secondBundle, local, second.payload), /diverged/);
  assert.equal(await readFile(localFile, 'utf8'), rollout(['local branch']));
});

test('Codex adapter secret scan reports only category and line', async () => {
  const fakeKey = `sk-${'x'.repeat(32)}`;
  const findings = scanSecrets(Buffer.from(`safe\n${fakeKey}\n`));
  assert.deepEqual(findings, [{ category: 'openai-key', line: 2 }]);

  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-codex-secret-'));
  const home = path.join(root, 'home');
  await putSession(home, rollout([fakeKey]));
  await assert.rejects(adapterExport(home, path.join(root, 'bundle')), error => {
    assert.match(error.message, /openai-key@3/);
    assert.doesNotMatch(error.message, /sk-/);
    return true;
  });
});

test('Codex adapter refuses an active writer lock', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-codex-lock-'));
  const source = path.join(root, 'source');
  const destination = path.join(root, 'destination');
  const bundle = path.join(root, 'bundle');
  await putSession(source);
  const exported = await adapterExport(source, bundle);
  const guard = await acquireWriterLock(destination, SESSION_ID);
  try { await assert.rejects(adapterImport(bundle, destination, exported.payload), /active writer/); }
  finally { await guard.release(); }
});

test('Codex adapter refuses the same UUID at a different rollout path', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-codex-path-'));
  const source = path.join(root, 'source');
  const destination = path.join(root, 'destination');
  const bundle = path.join(root, 'bundle');
  await putSession(source);
  await putSession(destination);
  const exported = await adapterExport(source, bundle);
  const manifestFile = path.join(bundle, 'manifest.json');
  const manifest = JSON.parse(await readFile(manifestFile, 'utf8'));
  manifest.relative_path = manifest.relative_path.replace('sessions/2026/09/02/', 'sessions/2099/01/01/');
  await writeFile(manifestFile, `${JSON.stringify(manifest)}\n`);
  await assert.rejects(adapterImport(bundle, destination, { ...exported.payload, relative_path: manifest.relative_path }), /does not match the existing session UUID/);
});

const ADAPTER = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'adapter.js');

async function adapterRequest(request, env = {}) {
  const child = spawn(process.execPath, [ADAPTER], { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, ...env } });
  const stdout = [], stderr = [];
  child.stdout.on('data', chunk => stdout.push(chunk));
  child.stderr.on('data', chunk => stderr.push(chunk));
  child.stdin.end(`${JSON.stringify({ protocol: 'abra-adapter/1', request_id: 'c0de', kind: 'dev.abra.codex.session.v1', ...request })}\n`);
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
  assert.equal(code, 0, Buffer.concat(stderr).toString());
  return JSON.parse(Buffer.concat(stdout).toString().trim());
}

test('Codex adapter binary round trips over the stdio contract', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-codex-stdio-'));
  const local = path.join(root, 'local');
  const cloud = path.join(root, 'cloud');
  const bundle = path.join(root, 'bundle');
  await putSession(local);

  const exported = await adapterRequest({
    verb: 'export',
    source: { session_id: SESSION_ID, codex_home: local },
    staging_dir: bundle,
    options: {}
  });
  assert.equal(exported.ok, true);
  assert.equal(exported.payload.session_id, SESSION_ID);
  assert.equal(exported.files_path, bundle);

  const imported = await adapterRequest({
    verb: 'import',
    payload: exported.payload,
    materialized_files: bundle,
    destination: { codex_home: cloud },
    options: { skip_version_check: 'true' }
  });
  assert.equal(imported.ok, true);
  assert.equal(imported.result.session_id, SESSION_ID);

  const wrongKind = await adapterRequest({ verb: 'export', kind: 'dev.abra.folder', source: SESSION_ID, staging_dir: bundle });
  assert.equal(wrongKind.error.code, 'unsupported_kind');
  const wrongVerb = await adapterRequest({ verb: 'watch', source: SESSION_ID });
  assert.equal(wrongVerb.error.code, 'unsupported_verb');

  const inspected = await adapterRequest({
    verb: 'inspect',
    source: { session_id: SESSION_ID, codex_home: local },
    options: {}
  });
  assert.equal(inspected.ok, true);
  assert.deepEqual(inspected.blocked, []);
  assert.ok(Array.isArray(inspected.warnings));
});

// Only this test needs a real `codex` on PATH; every other test uses temp homes
// and skip_version_check, so the suite runs anywhere.
test('Codex adapter checks the installed CLI version', { skip: process.env.ABRA_CODEX_TEST_REAL === '1' ? false : 'set ABRA_CODEX_TEST_REAL=1 with codex installed' }, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-codex-version-'));
  const local = path.join(root, 'local');
  const bundle = path.join(root, 'bundle');
  await putSession(local);
  const exported = await adapterExport(local, bundle);
  await assert.rejects(
    importSession({
      materialized_files: bundle,
      destination: { codex_home: path.join(root, 'cloud') },
      payload: exported.payload,
      options: {}
    }),
    /Codex version mismatch|cannot check destination Codex version/
  );
});

// A fake `codex` on PATH keeps the control test hermetic: it records the argv
// the adapter chose instead of running a model.
async function fakeCodex(root) {
  const bin = path.join(root, 'bin');
  await mkdir(bin, { recursive: true });
  const log = path.join(root, 'codex-argv.txt');
  await writeFile(path.join(bin, 'codex'), `#!/bin/sh\nprintf '%s\\n' "$@" > '${log}'\necho done\n`);
  await chmod(path.join(bin, 'codex'), 0o755);
  return { bin, log };
}

test('control instruct resumes the session recorded in the workspace', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-codex-control-'));
  const local = path.join(root, 'local');
  const cloud = path.join(root, 'cloud');
  const bundle = path.join(root, 'bundle');
  const workspace = path.join(root, 'workspace');
  await mkdir(workspace, { recursive: true });
  await putSession(local);
  const exported = await adapterExport(local, bundle);
  await importSession({
    materialized_files: bundle,
    destination: { codex_home: cloud, workspace },
    payload: exported.payload,
    options: { skip_version_check: 'true' }
  });
  assert.equal(
    JSON.parse(await readFile(path.join(workspace, '.abra', 'codex-session.json'), 'utf8')).session_id,
    SESSION_ID
  );

  const { bin, log } = await fakeCodex(root);
  const instructed = await adapterRequest(
    { verb: 'control', kind: 'dev.abra.workspace', op: 'instruct', text: 'add a test', workspace, options: {} },
    { PATH: `${bin}:${process.env.PATH}`, ABRA_CODEX_TEST_REAL: '1', CODEX_BIN: 'codex' }
  );
  assert.equal(instructed.ok, true);
  assert.deepEqual(
    { session_id: instructed.result.session_id, completed: instructed.result.completed },
    { session_id: SESSION_ID, completed: true }
  );
  assert.deepEqual((await readFile(log, 'utf8')).trim().split('\n'), [
    'exec', '--sandbox', 'workspace-write', '-C', workspace, 'resume', '--skip-git-repo-check', SESSION_ID, 'add a test'
  ]);

  const paused = await adapterRequest({ verb: 'control', kind: 'dev.abra.workspace', op: 'pause', options: {} });
  assert.deepEqual(paused.result, { recorded: true });
  const unknown = await adapterRequest(
    { verb: 'control', kind: 'dev.abra.workspace', op: 'instruct', text: 'hi', workspace: path.join(root, 'nowhere'), options: {} },
    { ABRA_CODEX_TEST_REAL: '1' }
  );
  assert.equal(unknown.error.code, 'not_found');
});

test('cancel over stdio stops an in-flight Codex control child', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-codex-cancel-'));
  const workspace = path.join(root, 'workspace');
  const bin = path.join(root, 'bin');
  const pidFile = path.join(root, 'codex.pid');
  await mkdir(path.join(workspace, '.abra'), { recursive: true });
  await mkdir(bin, { recursive: true });
  await writeFile(path.join(workspace, '.abra', 'codex-session.json'), `${JSON.stringify({ session_id: SESSION_ID })}\n`);
  await writeFile(path.join(bin, 'codex'), `#!/bin/sh\necho $$ > '${pidFile}'\nexec sleep 60\n`);
  await chmod(path.join(bin, 'codex'), 0o755);

  const child = spawn(process.execPath, [ADAPTER], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, CODEX_BIN: 'codex', ABRA_CODEX_TEST_REAL: '1' }
  });
  const replies = [];
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', chunk => replies.push(...chunk.split('\n').filter(Boolean).map(JSON.parse)));
  child.stdin.write(`${JSON.stringify({ protocol: 'abra-adapter/1', request_id: 'cafe', kind: 'dev.abra.workspace', verb: 'control', op: 'instruct', text: 'wait', workspace, options: {} })}\n`);
  for (let attempt = 0; attempt < 100; attempt++) {
    try { await stat(pidFile); break; } catch { await new Promise(resolve => setTimeout(resolve, 10)); }
  }
  const pid = Number((await readFile(pidFile, 'utf8')).trim());
  child.stdin.end(`${JSON.stringify({ protocol: 'abra-adapter/1', request_id: 'cafe', verb: 'cancel' })}\n`);
  await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
  assert.equal(replies.length, 1);
  assert.equal(replies[0].error.code, 'cancelled');
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.throws(() => process.kill(pid, 0), error => error.code === 'ESRCH');
});

test('inspect warns per secret finding and blocks an oversized session', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-codex-inspect-'));
  const home = path.join(root, 'home');
  const fakeKey = `sk-${'x'.repeat(32)}`;
  const file = await putSession(home, rollout([fakeKey]));
  const report = await inspectSession({ source: { session_id: SESSION_ID, codex_home: home }, options: {} });
  assert.deepEqual(report.blocked, []);
  assert.equal(report.warnings.length, 1);
  assert.equal(report.warnings[0].code, 'possible_secret');
  assert.match(report.warnings[0].message, /openai-key/);

  // Sparse: the file only has to report a size over the limit.
  await truncate(file, 512 * 1024 * 1024 + 1);
  const oversized = await inspectSession({ source: { session_id: SESSION_ID, codex_home: home }, options: {} });
  assert.equal(oversized.warnings.length, 0);
  assert.equal(oversized.blocked[0].code, 'session_too_large');
});
