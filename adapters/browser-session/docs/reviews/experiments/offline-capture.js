import { access, realpath } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';

const SANDBOX_EXEC = '/usr/bin/sandbox-exec';
const MAX_PIPE_BUFFER = 1024 * 1024;

function sandboxString(value) {
  return `"${String(value).replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}

export function offlineCapturePolicy(temporaryRoot) {
  const root = path.resolve(temporaryRoot);
  if (root === path.parse(root).root) throw new Error('offline capture root must not be the filesystem root');
  return `(version 1)
(allow default)
(deny network*)
(deny file-write* (require-not (subpath ${sandboxString(root)})))
(allow file-write* (literal "/dev/null"))
`;
}

export class PipeCDP {
  constructor(child, { commandTimeout = 10000 } = {}) {
    this.child = child; this.input = child.stdio[3]; this.output = child.stdio[4];
    this.commandTimeout = commandTimeout; this.id = 0; this.pending = new Map(); this.listeners = new Map(); this.buffer = Buffer.alloc(0); this.closed = false;
    if (!this.input || !this.output) throw new Error('Chrome remote-debugging pipe is unavailable');
    this.output.on('data', chunk => { try { this.read(chunk); } catch (error) { this.fail(error, true); } });
    this.output.on('error', error => this.fail(error, true));
    this.input.on('error', error => this.fail(error, true));
    let stderr = '';
    child.stderr?.on('data', chunk => { if (stderr.length < 4096) stderr += chunk.toString(); });
    child.once('error', error => this.fail(error, true));
    child.once('exit', (_code, signal) => this.fail(new Error(`offline Chrome exited${signal ? ` with ${signal}` : ''}${stderr.trim() ? `: ${stderr.trim()}` : ''}`)));
  }
  read(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length > MAX_PIPE_BUFFER) throw Object.assign(new Error('CDP pipe message exceeds 1 MiB'), { code: 'too_large' });
    for (;;) {
      const end = this.buffer.indexOf(0);
      if (end < 0) return;
      const bytes = this.buffer.subarray(0, end); this.buffer = this.buffer.subarray(end + 1);
      if (!bytes.length) continue;
      const message = JSON.parse(bytes.toString('utf8'));
      if (message.id) {
        const pending = this.pending.get(message.id); this.pending.delete(message.id); clearTimeout(pending?.timer);
        if (message.error) pending?.reject(new Error(message.error.message || 'CDP command failed')); else pending?.resolve(message.result);
      } else for (const listener of this.listeners.get(message.method) || []) listener(message.params || {}, message.sessionId);
    }
  }
  send(method, params = {}, sessionId) {
    if (this.closed) return Promise.reject(Object.assign(new Error('CDP pipe is closed'), { code: 'closed' }));
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { if (this.pending.delete(id)) reject(Object.assign(new Error(`CDP pipe command timed out: ${method}`), { code: 'timeout' })); }, this.commandTimeout);
      this.pending.set(id, { resolve, reject, timer });
      const bytes = Buffer.concat([Buffer.from(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) })), Buffer.from([0])]);
      try {
        this.input.write(bytes, error => {
          if (!error) return;
          const pending = this.pending.get(id);
          if (!pending) return;
          this.pending.delete(id); clearTimeout(pending.timer); pending.reject(error);
        });
      } catch (error) {
        const pending = this.pending.get(id);
        this.pending.delete(id); clearTimeout(pending?.timer); pending?.reject(error);
      }
    });
  }
  on(method, listener) { if (!this.listeners.has(method)) this.listeners.set(method, new Set()); this.listeners.get(method).add(listener); return () => this.listeners.get(method).delete(listener); }
  fail(error, terminate = false) {
    if (this.closed) return;
    this.closed = true;
    for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(error); }
    this.pending.clear();
    this.input.destroy(); this.output.destroy();
    if (terminate && this.child.exitCode === null && this.child.signalCode === null) this.child.kill('SIGTERM');
  }
  close() { this.fail(Object.assign(new Error('CDP pipe was closed'), { code: 'closed' }), true); }
}

// sandbox-exec is deprecated but remains the only built-in macOS mechanism
// that constrains Chrome and every renderer it starts. Refuse capture when it
// is absent; never fall back to an unsandboxed process.
export async function offlineCaptureCommand(executable, args, temporaryRoot) {
  if (process.platform !== 'darwin') throw Object.assign(new Error('offline saved-profile capture is only supported on macOS'), { code: 'unsupported' });
  try { await access(SANDBOX_EXEC); }
  catch { throw Object.assign(new Error('macOS sandbox-exec is unavailable; refusing saved-profile capture without OS isolation'), { code: 'unavailable' }); }
  return { executable: SANDBOX_EXEC, args: ['-p', offlineCapturePolicy(await realpath(temporaryRoot)), executable, ...args] };
}

export async function spawnOfflineChrome(executable, args, temporaryRoot, spawnFn = spawn) {
  const command = await offlineCaptureCommand(executable, ['--remote-debugging-pipe', '--disable-breakpad', '--disable-crash-reporter', ...args], temporaryRoot);
  const root = await realpath(temporaryRoot);
  const child = spawnFn(command.executable, command.args, {
    stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'],
    env: { ...process.env, HOME: root, TMPDIR: `${root}${path.sep}`, XDG_CACHE_HOME: root, XDG_CONFIG_HOME: root }
  });
  try { return { child, cdp: new PipeCDP(child) }; }
  catch (error) { child.kill?.('SIGTERM'); throw error; }
}
