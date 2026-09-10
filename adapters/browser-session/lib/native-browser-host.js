import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, readFile, unlink } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { CDP } from './cdp.js';
import { normalBrowserSocket } from './normal-browser.js';

const MAX_MESSAGE = 1024 * 1024;
const OPERATIONS = new Set(['connect', 'inventory', 'export', 'import']);

export async function normalBrowserEndpoint(chromeRoot) {
  let text;
  try { text = await readFile(path.join(chromeRoot, 'DevToolsActivePort'), 'utf8'); }
  catch (error) {
    if (error.code === 'ENOENT') throw coded('setup_required', 'Enable remote debugging for this Chrome profile at chrome://inspect/#remote-debugging, approve Chrome’s prompt, and try again. Chrome was not changed or restarted.');
    throw coded('unavailable', `Cannot read Chrome remote debugging state: ${error.message}`);
  }
  const [portText, browserPath, ...extra] = text.trim().split(/\r?\n/);
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535 || extra.length || !/^\/devtools\/browser\/[A-Za-z0-9._-]+$/.test(browserPath || '')) {
    throw coded('unavailable', 'Chrome remote debugging state is invalid. Disable and re-enable it at chrome://inspect/#remote-debugging.');
  }
  const wsUrl = `ws://127.0.0.1:${port}${browserPath}`;
  return { wsUrl, browserSession: createHash('sha256').update(wsUrl).digest('hex').slice(0, 32) };
}

export function defaultNormalChromeRoot() {
  if (process.env.ABRA_BROWSER_CHROME_ROOT) return path.resolve(process.env.ABRA_BROWSER_CHROME_ROOT);
  if (process.platform === 'darwin') return path.join(os.homedir(), 'Library', 'Application Support', 'Google', 'Chrome');
  if (process.platform === 'linux') return path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'google-chrome');
  throw coded('unsupported', 'Normal Chrome remote debugging currently supports macOS and Linux.');
}

export class NativeBrowserHost {
  constructor({ chromeRoot = defaultNormalChromeRoot(), socketPath = process.env.ABRA_BROWSER_SOCKET || normalBrowserSocket(), connect = connectCdp, operations, operationsFactory }) {
    this.chromeRoot = chromeRoot;
    this.socketPath = socketPath;
    this.connect = connect;
    this.operations = operations;
    this.operationsFactory = operationsFactory;
    this.jobs = Promise.resolve();
  }

  async connection() {
    const endpoint = await normalBrowserEndpoint(this.chromeRoot);
    const ws = this.current?.cdp?.ws;
    const connectionOpen = !ws || ws.readyState === 1;
    if (this.current?.wsUrl === endpoint.wsUrl && this.current.cdp && connectionOpen) return this.current;
    if (this.connecting) return this.connecting;
    this.connecting = (async () => {
      this.current?.cdp?.close();
      const cdp = await this.connect(endpoint.wsUrl);
      try {
        const operations = this.operationsFactory ? await this.operationsFactory(cdp, { browserSession: endpoint.browserSession }) : this.operations;
        this.current = { ...endpoint, cdp, operations };
        return this.current;
      } catch (error) { cdp.close(); throw error; }
    })();
    try { return await this.connecting; }
    finally { this.connecting = null; }
  }

  async approvedConnection() {
    const endpoint = await normalBrowserEndpoint(this.chromeRoot);
    const ws = this.current?.cdp?.ws;
    const connectionOpen = this.current?.cdp && (!ws || ws.readyState === 1);
    if (connectionOpen && this.current.wsUrl === endpoint.wsUrl) return this.current;
    throw coded('setup_required', 'Connect Abra to normal Chrome explicitly before reading or changing browser data.');
  }

  async start() {
    if ((!this.operations || typeof this.operations !== 'object') && typeof this.operationsFactory !== 'function') throw new Error('native browser operations are required');
    await mkdir(path.dirname(this.socketPath), { recursive: true, mode: 0o700 });
    await removeStaleSocket(this.socketPath);
    this.server = net.createServer(socket => this.handle(socket));
    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.socketPath, resolve);
    });
    await chmod(this.socketPath, 0o600);
    return this;
  }

  handle(socket) {
    let input = Buffer.alloc(0), handled = false;
    socket.setTimeout(35_000, () => reply(socket, failure('timeout', 'Chrome operation timed out.')));
    socket.on('data', async chunk => {
      if (handled) return;
      input = Buffer.concat([input, chunk]);
      if (input.length > MAX_MESSAGE) { handled = true; return reply(socket, failure('invalid_request', 'Browser request exceeds 1 MiB.')); }
      const newline = input.indexOf(0x0a);
      if (newline < 0) return;
      handled = true;
      try {
        if (input.subarray(newline + 1).some(byte => ![9, 10, 13, 32].includes(byte))) throw coded('invalid_request', 'Only one request is allowed per connection.');
        const request = JSON.parse(input.subarray(0, newline).toString('utf8'));
        if (!request || typeof request !== 'object' || Array.isArray(request) || !request.payload || typeof request.payload !== 'object' || Array.isArray(request.payload)) throw coded('invalid_request', 'Browser request must contain an object payload.');
        if (!OPERATIONS.has(request.operation)) throw coded('invalid_request', 'Unsupported browser operation.');
        const result = await this.exclusive(async () => {
          if (socket.destroyed) return undefined;
          const connection = request.operation === 'connect' ? await this.connection() : await this.approvedConnection();
          if (socket.destroyed) return undefined;
          if (request.operation === 'connect') return { connected: true, browser_session: connection.browserSession };
          const operation = connection.operations[request.operation];
          if (typeof operation !== 'function') throw coded('invalid_request', 'Unsupported browser operation.');
          return operation(request.payload, connection);
        });
        if (!socket.destroyed) reply(socket, { result });
      } catch (error) { reply(socket, failure(error.code || 'browser_error', error.message || 'Chrome operation failed.')); }
    });
    socket.on('error', () => {});
  }

  exclusive(job) {
    const result = this.jobs.then(job, job);
    this.jobs = result.catch(() => {});
    return result;
  }

  async close() {
    this.current?.cdp?.close();
    if (this.server) await new Promise(resolve => this.server.close(resolve));
    await unlink(this.socketPath).catch(error => { if (error.code !== 'ENOENT') throw error; });
  }
}

async function removeStaleSocket(socketPath) {
  let info;
  try { info = await lstat(socketPath); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (!info.isSocket() || info.uid !== process.getuid()) throw new Error('Unexpected normal-browser socket path.');
  const alive = await new Promise(resolve => {
    const socket = net.createConnection(socketPath);
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', () => resolve(false));
  });
  if (alive) throw new Error('A normal-browser host is already running.');
  await unlink(socketPath);
}

function reply(socket, value) {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
  if (bytes.length > MAX_MESSAGE) return socket.end(`${JSON.stringify(failure('invalid_response', 'Chrome response exceeds 1 MiB.'))}\n`);
  socket.end(bytes);
}
function failure(code, message) { return { error: { code, message } }; }
function coded(code, message) { return Object.assign(new Error(message), { code }); }

async function connectCdp(url) {
  const cdp = new CDP(url);
  let timer;
  try {
    await Promise.race([
      cdp.connect(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(coded('timeout', 'Chrome did not approve the remote debugging connection within 25 seconds.')), 25_000); })
    ]);
    return cdp;
  } catch (error) { cdp.close(); throw error; }
  finally { clearTimeout(timer); }
}
