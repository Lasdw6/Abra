import { createHash, randomUUID } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { chmod, copyFile, lstat, mkdir, open, readFile, readdir, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const KIND = 'dev.abra.codex.session.v1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/;
const RELATIVE_SESSION = /^sessions\/(\d{4})\/(\d{2})\/(\d{2})\/rollout-([^/]+)-([0-9a-f-]{36})\.jsonl$/i;
const MAX_SESSION_BYTES = 512 * 1024 * 1024;

function coded(code, message) { return Object.assign(new Error(message), { code }); }
function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

async function pathType(file) {
  try { return await lstat(file); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

async function rejectSymlinkComponents(candidate, boundary = candidate) {
  const absolute = path.resolve(candidate);
  const root = path.resolve(boundary);
  if (absolute !== root && !absolute.startsWith(`${root}${path.sep}`)) throw coded('permission_denied', 'path escapes its trusted boundary');
  let current = root;
  const rootInfo = await pathType(current);
  if (rootInfo?.isSymbolicLink()) throw coded('permission_denied', `refusing symlinked path component: ${current}`);
  for (const part of path.relative(root, absolute).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const info = await pathType(current);
    if (info?.isSymbolicLink()) throw coded('permission_denied', `refusing symlinked path component: ${current}`);
  }
}

async function walk(directory, depth, files) {
  if (depth < 0) return;
  let entries;
  try { entries = await readdir(directory, { withFileTypes: true }); }
  catch (error) { if (error.code === 'ENOENT') return; throw error; }
  for (const entry of entries) {
    const file = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) await walk(file, depth - 1, files);
    else if (entry.isFile() && entry.name.startsWith('rollout-') && entry.name.endsWith('.jsonl')) files.push(file);
  }
}

export async function listSessions(codexHome) {
  const home = path.resolve(codexHome);
  const root = path.resolve(home, 'sessions');
  await rejectSymlinkComponents(home);
  await rejectSymlinkComponents(root, home);
  const files = [];
  await walk(root, 3, files);
  const rows = [];
  for (const file of files) {
    try {
      const handle = await open(file, 'r');
      let first;
      try {
        const buffer = Buffer.alloc(256 * 1024);
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
        first = buffer.subarray(0, bytesRead).toString('utf8').split('\n')[0];
      } finally { await handle.close(); }
      const record = JSON.parse(first);
      const meta = canonicalMeta(record);
      const info = await stat(file);
      rows.push({
        session_id: meta.sessionId,
        cwd: meta.payload.cwd,
        cli_version: meta.payload.cli_version,
        updated_at: info.mtime.toISOString(),
        bytes: info.size,
        file
      });
    } catch { /* An invalid rollout is not a movable session. */ }
  }
  return rows.sort((left, right) => right.updated_at.localeCompare(left.updated_at));
}

export async function findSession(codexHome, sessionId) {
  if (!UUID.test(sessionId || '')) throw coded('invalid_request', 'session_id must be a UUID');
  const sessions = await listSessions(codexHome);
  const exact = sessions.filter(item => item.session_id.toLowerCase() === sessionId.toLowerCase());
  if (exact.length !== 1) throw coded(exact.length ? 'busy' : 'not_found', exact.length ? 'multiple rollout files have that session id' : `Codex session not found: ${sessionId}`);
  return exact[0].file;
}

function canonicalMeta(record) {
  if (!record || record.type !== 'session_meta' || !record.payload || typeof record.payload !== 'object') {
    throw coded('invalid_request', 'first rollout record must be session_meta');
  }
  const sessionId = record.payload.session_id || record.payload.id;
  if (!UUID.test(sessionId || '')) throw coded('invalid_request', 'session_meta lacks a valid UUID');
  if (record.payload.id && record.payload.id !== sessionId) throw coded('invalid_request', 'session_meta id and session_id disagree');
  if (typeof record.payload.cli_version !== 'string' || !record.payload.cli_version) throw coded('invalid_request', 'session_meta lacks cli_version');
  return { payload: record.payload, sessionId: sessionId.toLowerCase() };
}

export async function validateRollout(file, expectedId) {
  const info = await stat(file);
  if (!info.isFile() || info.size === 0 || info.size > MAX_SESSION_BYTES) throw coded('invalid_request', 'rollout size is invalid');
  const bytes = await readFile(file);
  if (bytes.at(-1) !== 0x0a) throw coded('invalid_request', 'rollout must end with a newline');
  const lines = bytes.toString('utf8').slice(0, -1).split('\n');
  let first;
  for (let index = 0; index < lines.length; index++) {
    try {
      const record = JSON.parse(lines[index]);
      if (index === 0) first = canonicalMeta(record);
    } catch (error) {
      if (error.code) throw error;
      throw coded('invalid_request', `rollout line ${index + 1} is not valid JSON`);
    }
  }
  if (expectedId && first.sessionId !== expectedId.toLowerCase()) throw coded('invalid_request', 'rollout UUID does not match the requested session');
  return { bytes, lines: lines.length, ...first };
}

const SECRET_PATTERNS = [
  ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['openai-key', /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/],
  ['aws-access-key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
  ['github-token', /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/],
  ['slack-token', /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/],
  ['bearer-token', /(?:authorization|bearer)["'\s:=]+bearer?\s*[A-Za-z0-9._~-]{24,}/i]
];

export function scanSecrets(bytes) {
  const findings = [];
  for (const [index, line] of bytes.toString('utf8').split('\n').entries()) {
    for (const [category, pattern] of SECRET_PATTERNS) if (pattern.test(line)) findings.push({ category, line: index + 1 });
  }
  return findings;
}

function checkpointFile(codexHome, sessionId) {
  return path.join(codexHome, '.abra-teleport', 'checkpoints', `${sessionId}.json`);
}

export function sessionCheckpointFile(codexHome, sessionId) {
  return checkpointFile(path.resolve(codexHome), sessionId);
}

function transferLockFile(codexHome, sessionId) {
  return path.join(codexHome, '.abra-teleport', 'active-locks', `${sessionId}.json`);
}

export async function acquireWriterLock(codexHome, sessionId) {
  if (!UUID.test(sessionId || '')) throw coded('invalid_request', 'session_id must be a UUID');
  const directory = path.join(path.resolve(codexHome), 'thread-writer-locks');
  await rejectSymlinkComponents(path.resolve(codexHome));
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await rejectSymlinkComponents(directory, path.resolve(codexHome));
  const lockPath = path.join(directory, `${sessionId}.lock`);
  const perl = process.env.PERL_BIN || '/usr/bin/perl';
  const script = 'use Fcntl qw(:flock); use IO::Handle; open(my $fh, ">>", $ARGV[0]) or die $!; if (!flock($fh, LOCK_EX|LOCK_NB)) { exit 75; } STDOUT->autoflush(1); print "locked\\n"; while (<STDIN>) {}';
  const child = spawn(perl, ['-e', script, lockPath], { stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { child.kill('SIGKILL'); reject(coded('internal', 'timed out acquiring Codex writer lock')); }, 5000);
    const ready = () => {
      if (!stdout.includes('\n')) return;
      clearTimeout(timeout);
      cleanup();
      resolve();
    };
    const exited = code => {
      clearTimeout(timeout);
      cleanup();
      reject(coded(code === 75 ? 'busy' : 'internal', code === 75 ? 'Codex session already has an active writer' : `writer lock helper failed: ${stderr.trim() || code}`));
    };
    const failed = error => { clearTimeout(timeout); cleanup(); reject(coded('internal', `cannot start writer lock helper: ${error.message}`)); };
    const cleanup = () => { child.stdout.off('data', ready); child.off('exit', exited); child.off('error', failed); };
    child.stdout.on('data', ready);
    child.once('exit', exited);
    child.once('error', failed);
    ready();
  });
  let released = false;
  return {
    path: lockPath,
    async release() {
      if (released) return;
      released = true;
      child.stdin.end();
      await new Promise(resolve => { if (child.exitCode !== null) resolve(); else child.once('exit', resolve); });
    }
  };
}

async function authorizedWriterGuard(codexHome, sessionId, options = {}) {
  if (!options.lock_nonce) return acquireWriterLock(codexHome, sessionId);
  const markerFile = transferLockFile(codexHome, sessionId);
  const markerInfo = await pathType(markerFile);
  if (!markerInfo?.isFile() || markerInfo.isSymbolicLink()) throw coded('permission_denied', 'wrapper writer-lock marker is missing or unsafe');
  const marker = JSON.parse(await readFile(markerFile, 'utf8').catch(() => { throw coded('permission_denied', 'wrapper writer-lock marker is invalid'); }));
  if (marker.session_id !== sessionId || marker.nonce !== options.lock_nonce) throw coded('permission_denied', 'wrapper writer-lock marker does not match');
  return { release: async () => {} };
}

export async function acquireTransferLock(codexHome, sessionId) {
  const home = path.resolve(codexHome);
  const guard = await acquireWriterLock(home, sessionId);
  const nonce = randomUUID();
  const marker = transferLockFile(home, sessionId);
  try {
    await writePrivateJson(marker, { session_id: sessionId, nonce, pid: process.pid }, home);
  } catch (error) {
    await guard.release();
    throw error;
  }
  return {
    nonce,
    async release() {
      try { await rm(marker, { force: true }); }
      finally { await guard.release(); }
    }
  };
}

async function readCheckpoint(codexHome, sessionId) {
  const file = checkpointFile(codexHome, sessionId);
  const info = await pathType(file);
  if (info?.isSymbolicLink()) throw coded('permission_denied', 'Codex handoff checkpoint is a symlink');
  try { return JSON.parse(await readFile(file, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return null; throw coded('invalid_request', 'Codex handoff checkpoint is invalid'); }
}

async function writePrivateJson(file, value, boundary = path.dirname(file)) {
  await rejectSymlinkComponents(path.dirname(file), boundary);
  await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  await chmod(path.dirname(file), 0o700);
  const temporary = `${file}.tmp-${process.pid}-${Date.now()}`;
  const handle = await open(temporary, 'wx', 0o600);
  try { await handle.writeFile(`${JSON.stringify(value)}\n`); await handle.sync(); }
  finally { await handle.close(); }
  await rename(temporary, file);
  await chmod(file, 0o600);
}

function parseSource(source) {
  if (typeof source === 'string') return { session_id: source };
  if (!source || typeof source !== 'object' || Array.isArray(source)) throw coded('invalid_request', 'source must be a session UUID or object');
  return source;
}

function workspaceFields(source) {
  const result = {};
  for (const key of ['workspace_snapshot_id', 'workspace_capsule_id', 'workspace_ancestor_snapshot_id']) {
    if (source[key] !== undefined) {
      if (!HASH.test(source[key])) throw coded('invalid_request', `${key} must be a lowercase SHA-256 id`);
      result[key] = source[key];
    }
  }
  if (source.workspace_name !== undefined) {
    if (typeof source.workspace_name !== 'string' || source.workspace_name.length > 200) throw coded('invalid_request', 'workspace_name is invalid');
    result.workspace_name = source.workspace_name;
  }
  return result;
}

export async function exportSession(request) {
  const source = parseSource(request.source);
  const codexHome = path.resolve(source.codex_home || process.env.CODEX_HOME || path.join(process.env.HOME || '.', '.codex'));
  const guard = await authorizedWriterGuard(codexHome, source.session_id, request.options);
  try {
  const file = await findSession(codexHome, source.session_id);
  const validated = await validateRollout(file, source.session_id);
  const findings = scanSecrets(validated.bytes);
  if (findings.length && request.options?.allow_secrets !== 'true') {
    const summary = findings.slice(0, 8).map(item => `${item.category}@${item.line}`).join(', ');
    throw coded('permission_denied', `transcript may contain secrets (${summary}); inspect locally and retry with allow_secrets=true only if intended`);
  }

  const sessionsRoot = path.resolve(codexHome, 'sessions');
  const relativePath = path.relative(codexHome, file).split(path.sep).join('/');
  if (!path.resolve(file).startsWith(`${sessionsRoot}${path.sep}`) || !RELATIVE_SESSION.test(relativePath)) throw coded('permission_denied', 'rollout path is outside the Codex sessions directory');
  const nameMatch = relativePath.match(RELATIVE_SESSION);
  if (nameMatch[5].toLowerCase() !== validated.sessionId) throw coded('invalid_request', 'rollout filename UUID does not match session_meta');

  let ancestor = { bytes: validated.bytes.length, sha256: digest(validated.bytes) };
  const checkpoint = await readCheckpoint(codexHome, validated.sessionId);
  if (checkpoint) {
    if (!Number.isSafeInteger(checkpoint.bytes) || checkpoint.bytes < 0 || checkpoint.bytes > validated.bytes.length || !HASH.test(checkpoint.sha256 || '')) {
      throw coded('invalid_request', 'Codex handoff checkpoint has invalid bounds');
    }
    if (digest(validated.bytes.subarray(0, checkpoint.bytes)) !== checkpoint.sha256) {
      throw coded('busy', 'Codex session diverged from its last imported checkpoint');
    }
    ancestor = checkpoint;
  }

  await rejectSymlinkComponents(request.staging_dir);
  await mkdir(request.staging_dir, { recursive: true, mode: 0o700 });
  await rejectSymlinkComponents(request.staging_dir);
  const sessionOut = path.join(request.staging_dir, 'session.jsonl');
  await copyFile(file, sessionOut);
  await chmod(sessionOut, 0o600);
  const manifest = {
    schema: 'dev.abra.codex.session/1',
    kind: KIND,
    session_id: validated.sessionId,
    cli_version: validated.payload.cli_version,
    source_cwd: typeof validated.payload.cwd === 'string' ? validated.payload.cwd : null,
    history_mode: validated.payload.history_mode ?? null,
    relative_path: relativePath,
    records: validated.lines,
    bytes: validated.bytes.length,
    sha256: digest(validated.bytes),
    ancestor_bytes: ancestor.bytes,
    ancestor_sha256: ancestor.sha256,
    secret_scan_overridden: findings.length > 0,
    ...workspaceFields(source)
  };
  await writePrivateJson(path.join(request.staging_dir, 'manifest.json'), manifest, request.staging_dir);
  return {
    payload: manifest,
    files_path: request.staging_dir,
    floor: {
      title: `Codex session ${validated.sessionId.slice(0, 8)}`,
      summary: `${validated.lines} records, Codex ${validated.payload.cli_version}`
    }
  };
  } finally {
    await guard.release();
  }
}

function parseDestination(destination) {
  if (!destination || typeof destination !== 'object' || Array.isArray(destination) || typeof destination.codex_home !== 'string') {
    throw coded('invalid_request', 'destination must be {"codex_home":"...","workspace":"..."}');
  }
  return destination;
}

async function installedCodexVersion(options) {
  if (options?.skip_version_check === 'true') return null;
  const binary = process.env.CODEX_BIN || 'codex';
  try {
    const { stdout } = await execFileAsync(binary, ['--version'], { timeout: 10000 });
    const match = stdout.match(/codex-cli\s+([^\s]+)/);
    if (!match) throw new Error('unexpected version output');
    return match[1];
  } catch (error) {
    throw coded('not_found', `cannot check destination Codex version: ${error.message}`);
  }
}

function comparePayload(payload, manifest) {
  for (const key of ['schema', 'kind', 'session_id', 'cli_version', 'bytes', 'sha256', 'ancestor_bytes', 'ancestor_sha256']) {
    if (payload?.[key] !== manifest[key]) throw coded('invalid_request', `outer payload disagrees with manifest field ${key}`);
  }
  for (const key of ['workspace_snapshot_id', 'workspace_capsule_id', 'workspace_ancestor_snapshot_id', 'workspace_name']) {
    if (payload?.[key] !== manifest[key]) throw coded('invalid_request', `outer payload disagrees with manifest field ${key}`);
  }
}

export async function importSession(request) {
  const destination = parseDestination(request.destination);
  const workspace = request.workspace ?? destination.workspace;
  if (!request.materialized_files) throw coded('invalid_request', 'materialized_files is required');
  const bundle = path.resolve(request.materialized_files);
  await rejectSymlinkComponents(bundle);
  for (const name of ['manifest.json', 'session.jsonl']) {
    const info = await pathType(path.join(bundle, name));
    if (!info?.isFile() || info.isSymbolicLink()) throw coded('permission_denied', `bundle ${name} is not a regular file`);
  }
  const manifest = JSON.parse(await readFile(path.join(bundle, 'manifest.json'), 'utf8'));
  if (manifest.schema !== 'dev.abra.codex.session/1' || manifest.kind !== KIND || !UUID.test(manifest.session_id || '')) throw coded('invalid_request', 'Codex session manifest is invalid');
  if (!HASH.test(manifest.sha256 || '') || !HASH.test(manifest.ancestor_sha256 || '') || !Number.isSafeInteger(manifest.bytes) || !Number.isSafeInteger(manifest.ancestor_bytes)) {
    throw coded('invalid_request', 'Codex session hashes or sizes are invalid');
  }
  comparePayload(request.payload, manifest);
  if (destination.expected_workspace_ancestor !== undefined) {
    if (!HASH.test(destination.expected_workspace_ancestor) || manifest.workspace_ancestor_snapshot_id !== destination.expected_workspace_ancestor) {
      throw coded('busy', 'workspace handoff ancestor does not match the local checkpoint');
    }
  }
  const sessionIn = path.join(bundle, 'session.jsonl');
  const validated = await validateRollout(sessionIn, manifest.session_id);
  if (validated.bytes.length !== manifest.bytes || digest(validated.bytes) !== manifest.sha256 || validated.lines !== manifest.records) throw coded('invalid_request', 'Codex session bundle hash or size mismatch');
  if (manifest.ancestor_bytes < 0 || manifest.ancestor_bytes > validated.bytes.length || digest(validated.bytes.subarray(0, manifest.ancestor_bytes)) !== manifest.ancestor_sha256) {
    throw coded('invalid_request', 'Codex session does not contain its declared ancestor');
  }
  const version = await installedCodexVersion(request.options);
  if (version && version !== manifest.cli_version && request.options?.allow_version_mismatch !== 'true') {
    throw coded('permission_denied', `Codex version mismatch: bundle ${manifest.cli_version}, destination ${version}`);
  }

  const codexHome = path.resolve(destination.codex_home);
  await rejectSymlinkComponents(codexHome);
  const relativeMatch = String(manifest.relative_path || '').match(RELATIVE_SESSION);
  if (!relativeMatch || relativeMatch[5].toLowerCase() !== manifest.session_id.toLowerCase()) throw coded('invalid_request', 'manifest relative_path is invalid');
  const target = path.resolve(codexHome, ...manifest.relative_path.split('/'));
  if (!target.startsWith(`${codexHome}${path.sep}sessions${path.sep}`)) throw coded('permission_denied', 'destination rollout escapes CODEX_HOME');
  await rejectSymlinkComponents(path.dirname(target), codexHome);
  const existingSessions = await listSessions(codexHome);
  const sameId = existingSessions.filter(item => item.session_id === manifest.session_id);
  if (sameId.length > 1) throw coded('busy', 'multiple destination rollouts already use this session UUID');
  if (sameId.length === 1 && path.resolve(sameId[0].file) !== target) throw coded('busy', 'received rollout path does not match the existing session UUID');
  const guard = await authorizedWriterGuard(codexHome, manifest.session_id, request.options);
  try {

  const existingInfo = await pathType(target);
  if (existingInfo?.isSymbolicLink() || (existingInfo && !existingInfo.isFile())) throw coded('permission_denied', 'destination rollout is not a regular file');
  const existing = existingInfo ? await readFile(target) : null;
  if (existing && digest(existing) !== manifest.sha256) {
    if (existing.length !== manifest.ancestor_bytes || digest(existing) !== manifest.ancestor_sha256) {
      throw coded('busy', 'destination Codex session diverged after handoff; refusing to merge histories');
    }
  }

  if (request.options?.stage_only === 'true') {
    return { result: { session_id: manifest.session_id, staged: true, installed_to: target } };
  }

  await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
  await chmod(path.dirname(target), 0o700);
  if (!existing || digest(existing) !== manifest.sha256) {
    const temporary = `${target}.tmp-${process.pid}-${Date.now()}`;
    await copyFile(sessionIn, temporary);
    await chmod(temporary, 0o600);
    await rename(temporary, target);
  }
  await chmod(target, 0o600);
  await writePrivateJson(checkpointFile(codexHome, manifest.session_id), { bytes: manifest.bytes, sha256: manifest.sha256 }, codexHome);
  // The workspace marker is what `control` reads later to know which session
  // an instruction belongs to. A workspace we cannot mark is not fatal here.
  if (workspace) {
    try { await writeWorkspaceSession(workspace, manifest.session_id); }
    catch (error) { process.stderr.write(`codex-session: cannot record workspace session marker: ${error.message}\n`); }
  }
  return {
    result: {
      session_id: manifest.session_id,
      installed_to: target,
      workspace: workspace || null,
      resume: workspace ? `codex resume ${manifest.session_id} -C ${workspace}` : `codex resume ${manifest.session_id}`
    }
  };
  } finally {
    await guard.release();
  }
}

const WORKSPACE_MARKER = path.join('.abra', 'codex-session.json');

async function writeWorkspaceSession(workspace, sessionId) {
  const root = path.resolve(workspace);
  await rejectSymlinkComponents(root);
  await writePrivateJson(path.join(root, WORKSPACE_MARKER), { session_id: sessionId }, root);
}

async function readWorkspaceSession(workspace) {
  const file = path.join(path.resolve(workspace), WORKSPACE_MARKER);
  const info = await pathType(file);
  if (!info?.isFile() || info.isSymbolicLink()) return null;
  try { return JSON.parse(await readFile(file, 'utf8')).session_id ?? null; }
  catch { throw coded('invalid_request', 'workspace Codex session marker is invalid'); }
}

/**
 * Read-only pre-flight for a send: what the daemon should warn about, and what
 * it should refuse outright.
 */
export async function inspectSession(request) {
  const source = parseSource(request.source);
  const codexHome = path.resolve(source.codex_home || process.env.CODEX_HOME || path.join(process.env.HOME || '.', '.codex'));
  const file = await findSession(codexHome, source.session_id);
  const info = await stat(file);
  if (info.size > MAX_SESSION_BYTES) {
    return {
      summary: `${info.size} bytes, over the ${MAX_SESSION_BYTES} byte limit`,
      warnings: [],
      blocked: [{ code: 'session_too_large', message: `rollout is ${info.size} bytes; the limit is ${MAX_SESSION_BYTES}`, item: path.basename(file) }]
    };
  }
  const bytes = await readFile(file);
  const warnings = scanSecrets(bytes).map(finding => ({
    code: 'possible_secret',
    message: `transcript line looks like a ${finding.category}`,
    item: `line ${finding.line}`
  }));
  return { summary: `${info.size} bytes, ${warnings.length} possible secrets`, warnings, blocked: [] };
}

/**
 * Act on a control message aimed at the workspace this session lives in.
 * `instruct` resumes the session with `codex exec`; `pause` and `stop` are
 * recorded and left to the operator, exactly as the daemon does without an
 * adapter.
 */
export async function controlSession(request, context = {}) {
  if (request.op !== 'instruct') return { result: { recorded: true } };
  const workspace = request.workspace;
  if (typeof request.text !== 'string' || !request.text) throw coded('invalid_request', 'instruct requires text');
  if (typeof workspace !== 'string' || !workspace) throw coded('not_found', 'this capsule has no known workspace on this device');
  const sessionId = request.options?.session_id || await readWorkspaceSession(workspace);
  if (!UUID.test(sessionId || '')) throw coded('not_found', 'no Codex session is recorded for this workspace');
  if (process.env.ABRA_CODEX_TEST_REAL !== '1') {
    return { result: { session_id: sessionId, completed: false, skipped: 'set ABRA_CODEX_TEST_REAL=1 to run codex' } };
  }
  const binary = process.env.CODEX_BIN || 'codex';
  const { stdout } = await execFileAsync(
    binary,
    ['exec', '--sandbox', 'workspace-write', '-C', workspace, 'resume', '--skip-git-repo-check', sessionId, request.text],
    { timeout: 9 * 60 * 1000, maxBuffer: 16 * 1024 * 1024, signal: context.signal }
  );
  return { result: { session_id: sessionId, completed: true, output: stdout.slice(-2000) } };
}
