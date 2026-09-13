// Small cross-platform helpers shared by the JavaScript adapters. Nothing here
// depends on the adapter protocol; it exists so each adapter does not grow its
// own copy of the Windows process and path rules.
import { execFile, spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const WINDOWS = process.platform === 'win32';

/** Home directory that works when HOME is unset, which is the Windows norm. */
export function homeDir() { return os.homedir(); }

function pathExtensions() {
  const raw = process.env.PATHEXT || '.COM;.EXE;.BAT;.CMD';
  return raw.split(';').map(value => value.trim()).filter(Boolean);
}

/**
 * Look a program name up the way the shell would. Windows needs PATHEXT because
 * `CreateProcess` only ever appends `.exe` on its own. Returns null when the
 * program is not installed, so callers can fall back instead of throwing.
 */
export function resolveExecutable(name) {
  if (!name) return null;
  if (name.includes('/') || name.includes(path.sep)) return fs.existsSync(name) ? path.resolve(name) : null;
  const directories = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const suffixes = WINDOWS ? ['', ...pathExtensions()] : [''];
  for (const directory of directories) {
    for (const suffix of suffixes) {
      const candidate = path.join(directory, name + suffix);
      try { if (fs.statSync(candidate).isFile()) return candidate; } catch { /* keep looking */ }
    }
  }
  return null;
}

// cmd.exe re-parses its command line, so each argument is quoted for
// CommandLineToArgvW and then every cmd metacharacter is escaped with `^`.
function escapeForCmd(value) {
  let text = String(value);
  text = text.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\*)$/, '$1$1');
  text = `"${text}"`;
  return text.replace(/([()%!^"&|<>])/g, '^$1');
}

/**
 * Build the arguments for running `file` with `args`. On Windows a `.cmd` or
 * `.bat` cannot be handed to CreateProcess, so it goes through ComSpec.
 */
export function commandFor(file, args = []) {
  if (WINDOWS && /\.(cmd|bat)$/i.test(file)) {
    const line = [file, ...args].map(escapeForCmd).join(' ');
    return { file: process.env.ComSpec || 'cmd.exe', args: ['/d', '/s', '/c', `"${line}"`], windowsVerbatimArguments: true };
  }
  return { file, args, windowsVerbatimArguments: undefined };
}

/**
 * Terminate a process and everything it started. SIGTERM only reaches the
 * direct child on Windows, so a console child such as Chrome or a `.cmd`
 * wrapper needs `taskkill /T`.
 */
export function killTree(pid, signal = 'SIGTERM') {
  if (!Number.isSafeInteger(pid) || pid <= 0) return;
  if (!WINDOWS) {
    try { process.kill(pid, signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    return;
  }
  spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
}

/**
 * `execFile` that understands Windows `.cmd` wrappers and tears the whole
 * process tree down when the signal aborts or the timeout fires.
 */
export function execFileTree(file, args, options = {}) {
  const { signal, timeout, ...rest } = options;
  const resolved = commandFor(resolveExecutable(file) || file, args);
  return new Promise((resolve, reject) => {
    let timer, reason = null, settled = false;
    const child = execFile(resolved.file, resolved.args, {
      ...rest,
      ...(resolved.windowsVerbatimArguments === undefined ? {} : { windowsVerbatimArguments: resolved.windowsVerbatimArguments }),
      windowsHide: true
    }, (error, stdout, stderr) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener?.('abort', onAbort);
      if (reason === 'abort') return reject(Object.assign(new Error('The operation was aborted'), { name: 'AbortError', code: 'ABORT_ERR' }));
      if (reason === 'timeout') return reject(Object.assign(new Error(`${file} timed out after ${timeout}ms`), { killed: true, code: 'ETIMEDOUT' }));
      if (error) return reject(Object.assign(error, { stdout, stderr }));
      resolve({ stdout, stderr });
    });
    function onAbort() { reason = 'abort'; killTree(child.pid); }
    if (signal) {
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', onAbort, { once: true });
    }
    if (timeout) timer = setTimeout(() => { reason = 'timeout'; killTree(child.pid); }, timeout);
  });
}

export { spawn, spawnSync };
