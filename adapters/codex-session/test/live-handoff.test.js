import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { exportSession, importSession } from '../lib/session.js';

const LIVE = process.env.ABRA_CODEX_TEST_LIVE === '1';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..', '..');
const ADAPTER = path.resolve(HERE, '..');
const ABRA = process.env.ABRA_BIN || path.join(REPO, 'target', 'debug', 'abra');
const CODEX = process.env.CODEX_BIN || 'codex';
const AUTH_FILE = process.env.ABRA_CODEX_TEST_AUTH_FILE
  || path.join(os.homedir(), '.codex', 'auth.json');

async function command(binary, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, {
      cwd: options.cwd,
      env: { ...process.env, ...options.env },
      stdio: ['pipe', 'pipe', 'pipe']
    });
    const stdout = [];
    const stderr = [];
    let bytes = 0;
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, options.timeout ?? 3 * 60 * 1000);
    child.stdout.on('data', chunk => {
      bytes += chunk.length;
      if (bytes <= 32 * 1024 * 1024) stdout.push(chunk);
    });
    child.stderr.on('data', chunk => {
      bytes += chunk.length;
      if (bytes <= 32 * 1024 * 1024) stderr.push(chunk);
    });
    child.once('error', error => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once('close', code => {
      clearTimeout(timeout);
      const out = Buffer.concat(stdout).toString();
      const err = Buffer.concat(stderr).toString();
      if (code === 0 && !timedOut && bytes <= 32 * 1024 * 1024) {
        resolve({ stdout: out, stderr: err });
        return;
      }
      const detail = [err.trim(), out.trim()].filter(Boolean).join('\n');
      const reason = timedOut ? 'timed out' : `exited ${code}`;
      reject(new Error(`${options.label || path.basename(binary)} ${reason}: ${detail || 'no output'}`));
    });
    child.stdin.end();
  });
}

async function commandJson(binary, args, options = {}) {
  const { stdout } = await command(binary, args, options);
  try {
    return JSON.parse(stdout);
  } catch {
    throw new Error(`${binary} returned invalid JSON: ${stdout.slice(0, 2000)}`);
  }
}

async function appServer(codexHome) {
  const child = spawn(CODEX, ['app-server', '--stdio'], {
    env: { ...process.env, CODEX_HOME: codexHome },
    stdio: ['pipe', 'pipe', 'pipe']
  });
  child.stdout.setEncoding('utf8');
  let buffer = '';
  let nextId = 1;
  const pending = new Map();
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', chunk => { stderr += chunk; });
  child.stdout.on('data', chunk => {
    buffer += chunk;
    for (;;) {
      const newline = buffer.indexOf('\n');
      if (newline < 0) break;
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      if (!line) continue;
      const message = JSON.parse(line);
      const waiter = pending.get(message.id);
      if (!waiter) continue;
      pending.delete(message.id);
      clearTimeout(waiter.timeout);
      if (message.error) waiter.reject(new Error(JSON.stringify(message.error)));
      else waiter.resolve(message.result);
    }
  });
  child.once('exit', code => {
    for (const waiter of pending.values()) {
      clearTimeout(waiter.timeout);
      waiter.reject(new Error(`Codex app-server exited ${code}: ${stderr.trim()}`));
    }
    pending.clear();
  });

  const rpc = (method, params) => new Promise((resolve, reject) => {
    const id = nextId++;
    const timeout = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`Codex app-server ${method} timed out`));
    }, 10_000);
    pending.set(id, { resolve, reject, timeout });
    child.stdin.write(`${JSON.stringify({ id, method, params })}\n`);
  });
  await rpc('initialize', {
    clientInfo: { name: 'abra_live_test', title: 'Abra live test', version: '0.1.0' },
    capabilities: { experimentalApi: true }
  });
  child.stdin.write(`${JSON.stringify({ method: 'initialized' })}\n`);
  return {
    rpc,
    async close() {
      child.kill('SIGTERM');
      const exited = new Promise(resolve => {
        if (child.exitCode !== null) resolve();
        else child.once('exit', resolve);
      });
      let forceTimer;
      const forced = new Promise(resolve => {
        forceTimer = setTimeout(() => {
          child.kill('SIGKILL');
          resolve();
        }, 5_000);
      });
      await Promise.race([exited, forced]);
      clearTimeout(forceTimer);
    }
  };
}

async function codexTurn(codexHome, workspace, args, prompt) {
  const { stdout } = await command(CODEX, [
    'exec', '--json', '--sandbox', 'workspace-write', '-C', workspace,
    ...args, prompt
  ], {
    env: { CODEX_HOME: codexHome },
    label: 'Codex turn',
    timeout: 8 * 60 * 1000
  });
  const events = stdout.split('\n').filter(Boolean).map(line => JSON.parse(line));
  const started = events.find(event => event.type === 'thread.started');
  const messages = events
    .filter(event => event.type === 'item.completed' && event.item?.type === 'agent_message')
    .map(event => event.item.text || '')
    .filter(Boolean);
  return {
    threadId: started?.thread_id,
    message: messages.at(-1) || '',
    events
  };
}

async function installAuth(codexHome) {
  await mkdir(codexHome, { recursive: true, mode: 0o700 });
  await chmod(codexHome, 0o700);
  await copyFile(AUTH_FILE, path.join(codexHome, 'auth.json'));
  await chmod(path.join(codexHome, 'auth.json'), 0o600);
}

async function startDaemon(root, codexHome) {
  await command(ABRA, [
    '--root', root, 'daemon', '--background', '--yes', '--adapters', ADAPTER
  ], {
    env: {
      ABRA_CODEX_TEST_REAL: '1',
      CODEX_BIN: CODEX,
      CODEX_HOME: codexHome
    },
    label: 'start Abra daemon'
  });
}

async function stopDaemon(root) {
  try {
    await command(ABRA, ['--root', root, 'stop'], { label: 'stop Abra daemon', timeout: 30_000 });
  } catch {
    // Cleanup must not hide the handoff assertion that failed.
  }
}

async function peerId(root) {
  const status = await commandJson(ABRA, ['--root', root, '--json', 'status'], { label: 'read Abra status' });
  assert.match(status.peer_id, /^[0-9a-f]+$/i);
  return status.peer_id;
}

async function pair(sourceRoot, destinationRoot) {
  const { stdout } = await command(ABRA, ['--root', destinationRoot, 'pair', 'ticket'], { label: 'create pairing ticket' });
  await command(ABRA, ['--root', sourceRoot, 'pair', 'add', stdout.trim()], { label: 'pair Abra peers' });
}

async function send(root, peer, sessionId, codexHome, workspace) {
  return commandJson(ABRA, [
    '--root', root, '--json', 'send', peer,
    '--kind', 'dev.abra.codex.session.v1',
    '--source', JSON.stringify({ session_id: sessionId, codex_home: codexHome }),
    '--workspace', workspace,
    '--wait'
  ], { label: 'send linked Codex handoff', timeout: 3 * 60 * 1000 });
}

async function accept(root, bundlePath, workspace, codexHome, label) {
  const args = [
    '--root', root, '--json', 'accept', '--latest',
    '--kind', 'dev.abra.codex.session.v1',
    bundlePath,
    '--workspace', workspace,
    '--destination', JSON.stringify({ codex_home: codexHome })
  ];
  return commandJson(ABRA, args, { label, timeout: 3 * 60 * 1000 });
}

async function instruct(root, peer, capsule, text) {
  return commandJson(ABRA, [
    '--root', root, '--json', 'control', peer,
    '--capsule', capsule, 'instruct', text
  ], { label: 'remote Codex instruct', timeout: 3 * 60 * 1000 });
}

test('a loaded real Codex thread blocks adapter export', {
  skip: process.env.ABRA_CODEX_TEST_REAL === '1'
    ? false
    : 'set ABRA_CODEX_TEST_REAL=1 to use a real Codex app-server',
  timeout: 60_000
}, async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-codex-lock-live-'));
  const codexHome = path.join(root, 'codex');
  const workspace = path.join(root, 'workspace');
  const bundle = path.join(root, 'bundle');
  await Promise.all([
    mkdir(codexHome, { recursive: true, mode: 0o700 }),
    mkdir(workspace, { recursive: true })
  ]);
  const server = await appServer(codexHome);
  t.after(async () => {
    await server.close();
    await rm(root, { recursive: true, force: true });
  });

  const started = await server.rpc('thread/start', {
    cwd: workspace,
    sandbox: 'read-only',
    approvalPolicy: 'never',
    ephemeral: false
  });
  const sessionId = started.thread.id;
  await server.rpc('thread/inject_items', {
    threadId: sessionId,
    items: [{
      type: 'message',
      role: 'user',
      content: [{ type: 'input_text', text: 'writer lock integration test' }]
    }]
  });

  await assert.rejects(
    exportSession({
      source: { session_id: sessionId, codex_home: codexHome },
      staging_dir: bundle,
      options: {}
    }),
    error => error.code === 'busy' && /active writer/.test(error.message)
  );
});

test('the current single-session bundle does not include a forked child thread', {
  skip: process.env.ABRA_CODEX_TEST_REAL === '1'
    ? false
    : 'set ABRA_CODEX_TEST_REAL=1 to use a real Codex app-server',
  timeout: 60_000
}, async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-codex-child-live-'));
  const sourceHome = path.join(root, 'source');
  const destinationHome = path.join(root, 'destination');
  const workspace = path.join(root, 'workspace');
  const bundle = path.join(root, 'bundle');
  await Promise.all([
    mkdir(sourceHome, { recursive: true, mode: 0o700 }),
    mkdir(destinationHome, { recursive: true, mode: 0o700 }),
    mkdir(workspace, { recursive: true })
  ]);
  const source = await appServer(sourceHome);
  let destination;
  t.after(async () => {
    await Promise.all([source.close(), destination?.close()]);
    await rm(root, { recursive: true, force: true });
  });

  const rootThread = await source.rpc('thread/start', {
    cwd: workspace,
    sandbox: 'read-only',
    approvalPolicy: 'never',
    ephemeral: false
  });
  const rootId = rootThread.thread.id;
  await source.rpc('thread/inject_items', {
    threadId: rootId,
    items: [{
      type: 'message', role: 'user',
      content: [{ type: 'input_text', text: 'root marker' }]
    }]
  });
  const forked = await source.rpc('thread/fork', { threadId: rootId });
  const childId = forked.thread.id;
  await source.rpc('thread/inject_items', {
    threadId: childId,
    items: [{
      type: 'message', role: 'user',
      content: [{ type: 'input_text', text: 'child marker' }]
    }]
  });
  await source.close();

  const exported = await exportSession({
    source: { session_id: rootId, codex_home: sourceHome },
    staging_dir: bundle,
    options: {}
  });
  await importSession({
    materialized_files: bundle,
    destination: { codex_home: destinationHome },
    payload: exported.payload,
    options: {}
  });

  destination = await appServer(destinationHome);
  const resumed = await destination.rpc('thread/resume', { threadId: rootId });
  assert.equal(resumed.thread.id, rootId);
  await assert.rejects(
    destination.rpc('thread/read', { threadId: childId, includeTurns: true })
  );
});

test('a real Codex agent session and workspace survive an Abra round trip', {
  skip: LIVE ? false : 'set ABRA_CODEX_TEST_LIVE=1 to use a real Codex login and two Abra daemons',
  timeout: 20 * 60 * 1000
}, async t => {
  await stat(AUTH_FILE);
  await stat(ABRA);

  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-codex-live-'));
  const aRoot = path.join(root, 'abra-a');
  const bRoot = path.join(root, 'abra-b');
  const aCodex = path.join(root, 'codex-a');
  const bCodex = path.join(root, 'codex-b');
  const aWorkspace = path.join(root, 'workspace-a');
  const bWorkspace = path.join(root, 'workspace-b');
  const receivedOnB = path.join(root, 'received-on-b');
  const receivedOnA = path.join(root, 'received-on-a');

  t.after(async () => {
    await Promise.all([stopDaemon(aRoot), stopDaemon(bRoot)]);
    await rm(root, { recursive: true, force: true });
  });

  await Promise.all([
    installAuth(aCodex),
    mkdir(bCodex, { recursive: true, mode: 0o700 }),
    mkdir(aWorkspace, { recursive: true })
  ]);

  const nonce = Date.now().toString(36).toUpperCase();
  const fileToken = `FILE_${nonce}`;
  const memoryToken = `MEMORY_${nonce}`;
  const first = await codexTurn(aCodex, aWorkspace, ['--skip-git-repo-check'], [
    'This is an Abra transport integration test.',
    `Use the shell to create transport-proof.txt containing exactly ${fileToken} followed by a newline.`,
    `Remember ${memoryToken} in this conversation, but do not write it to any file.`,
    'Reply exactly SOURCE_DONE after the file exists.'
  ].join(' '));
  assert.match(first.threadId || '', /^[0-9a-f-]{36}$/i);
  assert.equal(first.message.trim(), 'SOURCE_DONE');
  assert.equal((await readFile(path.join(aWorkspace, 'transport-proof.txt'), 'utf8')).trim(), fileToken);

  await Promise.all([startDaemon(aRoot, aCodex), startDaemon(bRoot, bCodex)]);
  await pair(aRoot, bRoot);
  const [aPeer, bPeer] = await Promise.all([peerId(aRoot), peerId(bRoot)]);

  const sentToB = await send(aRoot, bPeer, first.threadId, aCodex, aWorkspace);
  assert.equal(sentToB.entry.state, 'acked');
  assert.equal(sentToB.entries.length, 2);

  const acceptedOnB = await accept(
    bRoot, receivedOnB, bWorkspace, bCodex, 'accept Codex handoff on receiver'
  );
  assert.equal(acceptedOnB.import.result.session_id, first.threadId);
  assert.equal((await readFile(path.join(bWorkspace, 'transport-proof.txt'), 'utf8')).trim(), fileToken);
  await assert.rejects(
    command(CODEX, ['login', 'status'], { env: { CODEX_HOME: bCodex } }),
    /Not logged in/
  );
  const offlineReader = await appServer(bCodex);
  try {
    await offlineReader.rpc('thread/read', {
      threadId: first.threadId,
      includeTurns: true
    });
    const resumedOffline = await offlineReader.rpc('thread/resume', {
      threadId: first.threadId
    });
    assert.equal(resumedOffline.thread.id, first.threadId);
    const history = await offlineReader.rpc('thread/read', {
      threadId: first.threadId,
      includeTurns: true
    });
    const rendered = JSON.stringify(history.thread.turns);
    assert.match(rendered, new RegExp(memoryToken));
    assert.match(rendered, /SOURCE_DONE/);
  } finally {
    await offlineReader.close();
  }

  // Authentication is deliberately supplied at the receiver, outside the
  // transported adapter bundle.
  await installAuth(bCodex);
  const secondPrompt = [
    'Read transport-proof.txt without changing it.',
    `Reply exactly DESTINATION_CONTINUED FILE=${fileToken} MEMORY=${memoryToken}.`,
    'Use the memory token from the conversation that was transferred.'
  ].join(' ');
  const control = await instruct(aRoot, bPeer, sentToB.capsule_id, secondPrompt);
  assert.equal(control.ok, true);
  assert.equal(control.result.completed, true);
  const second = { threadId: first.threadId, message: control.result.output };
  assert.equal(second.threadId, first.threadId);
  assert.equal(second.message.trim(), `DESTINATION_CONTINUED FILE=${fileToken} MEMORY=${memoryToken}`);

  const sentBack = await send(bRoot, aPeer, first.threadId, bCodex, bWorkspace);
  assert.equal(sentBack.entry.state, 'acked');
  const acceptedOnA = await accept(
    aRoot, receivedOnA, aWorkspace, aCodex, 'accept Codex handoff back on source'
  );
  assert.equal(acceptedOnA.import.result.session_id, first.threadId);

  const third = await codexTurn(aCodex, aWorkspace, [
    'resume', '--skip-git-repo-check', first.threadId
  ], [
    'Confirm that the immediately preceding assistant reply began with DESTINATION_CONTINUED',
    `and that the original memory token was ${memoryToken}.`,
    'Reply exactly SOURCE_RESUMED.'
  ].join(' '));
  assert.equal(third.threadId, first.threadId);
  assert.equal(third.message.trim(), 'SOURCE_RESUMED');
});
