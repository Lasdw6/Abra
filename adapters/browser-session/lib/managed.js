import { access, mkdir, readFile, readdir, rm, stat } from 'node:fs/promises';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { browserWebSocketFromUrl } from './cdp.js';
import { dataDir, readJson, writeJson } from './util.js';

const execFileAsync = promisify(execFile);

export function managedStateFile() { return path.join(dataDir(), 'managed-browser.json'); }
export function managedProfileDir() { return path.join(dataDir(), 'managed-profile'); }

export async function exists(file) {
  try { await access(file); return true; }
  catch { return false; }
}

async function executableOnPath(name) {
  try {
    const { stdout } = await execFileAsync('/usr/bin/which', [name]);
    return stdout.trim().split(/\r?\n/)[0] || null;
  } catch { return null; }
}

export async function chromeBinary() {
  const candidates = [
    process.env.CHROME_BIN,
    process.platform === 'darwin' ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : null,
    await executableOnPath('google-chrome'),
    await executableOnPath('google-chrome-stable'),
    await executableOnPath('chromium'),
    await executableOnPath('chromium-browser')
  ].filter(value => typeof value === 'string' && value.length > 0);
  for (const candidate of candidates) if (await exists(candidate)) return candidate;
  throw new Error('Google Chrome was not found. Set CHROME_BIN');
}

export function isProcessAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (error) { if (error.code === 'ESRCH') return false; throw error; }
}

export async function processIdentity(pid) {
  if (!isProcessAlive(pid)) return null;
  const { stdout } = await execFileAsync('/bin/ps', ['-p', String(pid), '-o', 'lstart=', '-o', 'command=']);
  const match = stdout.trim().match(/^(\S+\s+\S+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+([\s\S]+)$/);
  if (!match) return null;
  return { started_at: match[1].replace(/\s+/g, ' '), command: match[2] };
}

async function chromePids(profileDir) {
  if (!profileDir) return [];
  const { stdout } = await execFileAsync('/bin/ps', ['-ax', '-o', 'pid=', '-o', 'command=']);
  const marker = `--user-data-dir=${profileDir}`;
  return stdout.split('\n').flatMap(line => {
    const match = line.match(/^\s*(\d+)\s+([\s\S]+)$/);
    return match && match[2].includes(marker) ? [Number(match[1])] : [];
  });
}

async function waitForChromeExit(pids, profileDir, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!pids.some(isProcessAlive) && !(await chromePids(profileDir)).length) return true;
    await delay(50);
  }
  return !pids.some(isProcessAlive) && !(await chromePids(profileDir)).length;
}

export async function stopChrome(pid, profileDir, timeoutMs = 5000) {
  const initial = new Set([pid, ...await chromePids(profileDir)].filter(value => Number.isSafeInteger(value) && value > 0));
  for (const processId of initial) {
    try { process.kill(processId, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
  if (await waitForChromeExit([...initial], profileDir, timeoutMs)) return;
  const remaining = new Set([[...initial].filter(isProcessAlive), await chromePids(profileDir)].flat());
  for (const processId of remaining) {
    try { process.kill(processId, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
  if (!await waitForChromeExit([...remaining], profileDir, 2000)) throw new Error(`Chrome did not exit within ${timeoutMs + 2000}ms`);
}

export async function desktopEnvironment(env = process.env, platform = process.platform, socketDirectory = '/tmp/.X11-unix') {
  if (platform !== 'linux') return { available: true, env: {} };
  if (env.DISPLAY) return { available: true, env: { DISPLAY: env.DISPLAY } };
  if (env.WAYLAND_DISPLAY && env.XDG_RUNTIME_DIR) {
    return { available: true, env: { WAYLAND_DISPLAY: env.WAYLAND_DISPLAY, XDG_RUNTIME_DIR: env.XDG_RUNTIME_DIR } };
  }
  const sockets = await readdir(socketDirectory).catch(() => []);
  const displays = [];
  for (const name of sockets.filter(name => /^X\d+$/.test(name))) {
    if ((await stat(path.join(socketDirectory, name)).catch(() => null))?.isSocket()) displays.push(`:${name.slice(1)}`);
  }
  if (displays.length === 1) return { available: true, env: { DISPLAY: displays[0] } };
  return { available: false, env: {} };
}

async function waitForBrowser(httpUrl, alive, timeout = 15000) {
  const deadline = Date.now() + timeout;
  let lastError;
  do {
    if (alive && !await alive()) throw new Error('Chrome exited before its debugging endpoint was ready');
    try { return await browserWebSocketFromUrl(httpUrl); }
    catch (error) { lastError = error; }
    await delay(50);
  } while (Date.now() < deadline);
  throw new Error(`Chrome debugging endpoint did not become ready: ${lastError}`);
}

function matchesManagedIdentity(state, identity, profile) {
  return Boolean(
    identity
    && state.started_at
    && identity.started_at === state.started_at
    && identity.command === state.command
    && identity.command.includes(`--user-data-dir=${profile}`)
  );
}

export async function managedBrowserStatus() {
  let state;
  try { state = await readJson(managedStateFile()); }
  catch { return null; }
  const profile = state.profile || managedProfileDir();
  if (!isProcessAlive(state.pid)) return null;
  const identity = await processIdentity(state.pid);
  if (!matchesManagedIdentity(state, identity, profile)) return null;
  try {
    const wsUrl = await browserWebSocketFromUrl(`http://127.0.0.1:${state.port}`);
    return { ...state, profile, wsUrl };
  } catch { return null; }
}

export async function ensureManagedBrowser({ headless } = {}) {
  const current = await managedBrowserStatus();
  if (current) return { ...current, started: false };
  const profile = managedProfileDir();
  const desktop = await desktopEnvironment();
  headless ??= !desktop.available;
  await mkdir(dataDir(), { recursive: true, mode: 0o700 });
  await mkdir(profile, { recursive: true, mode: 0o700 });
  await rm(path.join(profile, 'DevToolsActivePort'), { force: true });
  const binary = await chromeBinary();
  const args = [
    `--user-data-dir=${profile}`,
    '--remote-debugging-address=127.0.0.1',
    '--remote-debugging-port=0',
    '--no-first-run',
    '--no-default-browser-check',
    ...(headless ? ['--headless=new'] : ['--window-position=0,0', '--window-size=1440,900']),
    ...(!headless && !desktop.env.DISPLAY && desktop.env.WAYLAND_DISPLAY ? ['--ozone-platform=wayland'] : []),
    ...(process.getuid?.() === 0 || (process.platform === 'linux' && headless) ? ['--no-sandbox'] : []),
    ...(process.platform === 'linux' ? ['--disable-dev-shm-usage'] : []),
    'about:blank'
  ];
  const child = spawn(binary, args, { detached: true, stdio: 'ignore', env: { ...process.env, ...desktop.env } });
  child.unref();
  let port;
  for (let attempt = 0; attempt < 300; attempt++) {
    try {
      port = Number((await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]);
      if (port) break;
    } catch { /* Chrome is still starting. */ }
    if (!isProcessAlive(child.pid)) break;
    await delay(50);
  }
  if (!port) {
    await stopChrome(child.pid, profile).catch(() => {});
    throw new Error('Chrome did not expose a debugging port');
  }
  let wsUrl;
  try {
    wsUrl = await waitForBrowser(`http://127.0.0.1:${port}`, () => Promise.resolve(isProcessAlive(child.pid)));
  } catch (error) {
    await stopChrome(child.pid, profile).catch(() => {});
    throw error;
  }
  const identity = await processIdentity(child.pid);
  if (!identity) {
    await stopChrome(child.pid, profile).catch(() => {});
    throw new Error('Chrome exited before startup');
  }
  const state = {
    pid: child.pid,
    port,
    wsUrl,
    profile,
    started_at: identity.started_at,
    command: identity.command,
    binary,
    headless
  };
  await writeJson(managedStateFile(), state);
  return { ...state, started: true };
}

export async function stopManagedBrowser() {
  let state;
  try { state = await readJson(managedStateFile()); }
  catch { return { stopped: false }; }
  const profile = state.profile || managedProfileDir();
  if (!isProcessAlive(state.pid)) {
    await rm(managedStateFile(), { force: true });
    return { stopped: false };
  }
  const identity = await processIdentity(state.pid);
  if (!matchesManagedIdentity(state, identity, profile)) {
    throw new Error(`refusing to stop PID ${state.pid}; process identity does not match`);
  }
  await stopChrome(state.pid, profile);
  await rm(managedStateFile(), { force: true });
  return { stopped: true };
}
