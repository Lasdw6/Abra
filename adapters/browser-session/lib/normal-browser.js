import net from 'node:net';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { chmod, mkdir, open } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { dataDir } from './util.js';

export function normalBrowserSocket() {
  return path.join(dataDir(), 'chrome-bridge.sock');
}

// A persistent local host owns this user-only socket and holds Chrome's
// permission-gated CDP connection. No HTTP server or CDP capability is exposed.
export async function normalBrowserRequest(operation, payload = {}, options = {}) {
  const socketPath = options.socketPath || normalBrowserSocket();
  const autoStart = operation === 'connect' && (options.autoStart ?? socketPath === normalBrowserSocket());
  try { return await requestOnce(operation, payload, { ...options, socketPath }); }
  catch (error) {
    if (!['ENOENT', 'ECONNREFUSED'].includes(error.socketCode)) throw error;
    if (!autoStart) throw Object.assign(new Error('Connect Abra to normal Chrome explicitly with `abra-native-browser-host --connect` before reading or changing browser data.'), { code: 'setup_required' });
    await startNormalBrowserHost({ ...options, socketPath });
    return requestOnce(operation, payload, { ...options, socketPath });
  }
}

function requestOnce(operation, payload, { timeoutMs = 30000, socketPath }) {
  return new Promise((resolve, reject) => {
    const request = JSON.stringify({ operation, payload }) + '\n';
    if (Buffer.byteLength(request) > 900 * 1024) return reject(Object.assign(new Error('The selected browser state is too large for the Chrome connection.'), { code: 'invalid_request' }));
    const socket = net.createConnection(socketPath);
    let bytes = Buffer.alloc(0), settled = false;
    function finish(error, result) {
      if (settled) return;
      settled = true; socket.destroy();
      error ? reject(error) : resolve(result);
    }
    socket.setTimeout(timeoutMs, () => finish(Object.assign(new Error('Your Chrome browser did not respond in time.'), { code: 'timeout' })));
    socket.on('connect', () => socket.write(request));
    socket.on('error', error => finish(Object.assign(new Error(['ENOENT', 'ECONNREFUSED'].includes(error.code) ? 'The normal Chrome connection is not running.' : `Chrome connection failed: ${error.message}`), { code: 'unavailable', socketCode: error.code })));
    socket.on('data', chunk => {
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length > 1024 * 1024) return finish(Object.assign(new Error('Chrome response exceeds 1 MiB.'), { code: 'invalid_request' }));
      const newline = bytes.indexOf(0x0a);
      if (newline < 0) return;
      try {
        if (bytes.subarray(newline + 1).some(byte => ![0x0a, 0x0d, 0x20, 0x09].includes(byte))) throw new Error('Chrome sent more than one response.');
        const response = JSON.parse(bytes.subarray(0, newline).toString('utf8'));
        if (response.error) finish(Object.assign(new Error(response.error.message || 'Chrome operation failed'), { code: response.error.code || 'internal' }));
        else finish(null, response.result);
      } catch (error) { finish(Object.assign(new Error(`Invalid Chrome response: ${error.message}`), { code: 'invalid_response' })); }
    });
    socket.on('end', () => { if (!settled) finish(Object.assign(new Error('Chrome disconnected before completing the operation.'), { code: 'unavailable' })); });
  });
}

export async function startNormalBrowserHost({ socketPath = normalBrowserSocket(), chromeRoot, spawnFn = spawn, endpointFn, startupMs = 3000, logDir = path.join(dataDir(), 'logs') } = {}) {
  const hostModule = await import('./native-browser-host.js');
  const endpoint = endpointFn || hostModule.normalBrowserEndpoint;
  await endpoint(chromeRoot || hostModule.defaultNormalChromeRoot());
  await mkdir(logDir, { recursive: true, mode: 0o700 });
  await chmod(logDir, 0o700);
  const log = await open(path.join(logDir, 'native-browser-host.log'), 'a', 0o600);
  await log.chmod(0o600);
  const executable = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'native-browser-host.js');
  let spawnError;
  try {
    const child = spawnFn(process.execPath, [executable], {
      detached: true,
      stdio: ['ignore', log.fd, log.fd],
      env: { ...process.env, ...(chromeRoot ? { ABRA_BROWSER_CHROME_ROOT: chromeRoot } : {}), ABRA_BROWSER_SOCKET: socketPath }
    });
    child.once?.('error', error => { spawnError = error; });
    child.unref?.();
  } finally { await log.close(); }
  const deadline = Date.now() + startupMs;
  while (Date.now() < deadline) {
    if (spawnError) throw Object.assign(new Error(`The normal Chrome connection host failed to start: ${spawnError.message}`), { code: 'unavailable' });
    if (await socketAcceptsConnections(socketPath)) return;
    await delay(25);
  }
  throw Object.assign(new Error('The normal Chrome connection host did not start. See its private log for details.'), { code: 'unavailable' });
}

async function socketAcceptsConnections(socketPath) {
  return new Promise(resolve => {
    const socket = net.createConnection(socketPath);
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', () => resolve(false));
  });
}
