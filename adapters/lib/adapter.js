// Shared abra-adapter/1 NDJSON loop for JavaScript adapters. Zero dependencies,
// Node 20+. See docs/ADAPTERS.md for the contract this implements.
import { createInterface } from 'node:readline';

const PROTOCOL = 'abra-adapter/1';
const MAX_LINE = 1024 * 1024;

/** Error carrying one of the contract's error codes. */
export function coded(code, message) {
  return Object.assign(new Error(message), { code });
}

/**
 * Run the stdin/stdout loop until stdin ends.
 *
 * `verbs.export`, `verbs.import`, `verbs.inspect`, and `verbs.control` receive
 * `(request, { signal, emit })` and resolve with the response fields.
 * Reserved until the Rust runner has a streaming operation: `verbs.watch` is
 * answered with `{watching:true}` first and then emits
 * `{event,cursor,hint}` objects through `emit` until `signal` aborts.
 *
 * `controls` lists the capsule kinds this adapter answers `control` for. They
 * are separate from `kinds`, so a session adapter can be driven through the
 * workspace capsule it belongs to.
 */
export async function runAdapter({
  kinds,
  controls = [],
  verbs,
  internalMessage = 'adapter operation failed',
  input = process.stdin,
  output = process.stdout
}) {
  const supported = new Set(kinds);
  const controlled = new Set([...kinds, ...controls]);
  const pending = new Map();
  const running = [];
  const write = value => output.write(`${JSON.stringify(value)}\n`);

  for await (const line of createInterface({ input, crlfDelay: Infinity })) {
    let request;
    try {
      request = parse(line);
      validate(request);
    } catch (error) {
      write(failure(idOf(request), error, internalMessage));
      continue;
    }
    if (request.verb === 'cancel') {
      const active = pending.get(request.request_id);
      active?.controller.abort();
      (active?.reply ?? write)(failure(request.request_id, coded('cancelled', 'cancelled')));
      continue;
    }
    running.push(dispatch(request));
  }
  await Promise.all(running);

  async function dispatch(request) {
    const controller = new AbortController();
    let replied = false;
    const reply = value => {
      if (replied) return;
      replied = true;
      write(value);
    };
    pending.set(request.request_id, { controller, reply });
    try {
      const accepted = request.verb === 'control' ? controlled : supported;
      if (!accepted.has(request.kind)) throw coded('unsupported_kind', `unsupported kind: ${request.kind}`);
      const verb = verbs[request.verb];
      if (typeof verb !== 'function') throw coded('unsupported_verb', `unsupported verb: ${request.verb}`);
      const context = {
        signal: controller.signal,
        emit: event => write({ request_id: request.request_id, ...event })
      };
      if (request.verb === 'watch') {
        reply({ request_id: request.request_id, ok: true, watching: true });
        await verb(request, context);
      } else {
        const result = await verb(request, context);
        reply({ request_id: request.request_id, ok: true, ...result });
      }
    } catch (error) {
      if (replied) process.stderr.write(`${error.stack || error}\n`);
      else reply(failure(request.request_id, error, internalMessage));
    } finally {
      pending.delete(request.request_id);
    }
  }
}

function parse(line) {
  if (Buffer.byteLength(line) > MAX_LINE) throw coded('invalid_request', 'request exceeds 1 MiB');
  try {
    return JSON.parse(line);
  } catch {
    throw coded('invalid_request', 'request is not valid JSON');
  }
}

function validate(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) throw coded('invalid_request', 'request must be an object');
  if (request.protocol !== PROTOCOL || !/^[0-9a-f]+$/.test(request.request_id || '')) {
    throw coded('invalid_request', 'invalid protocol or request_id');
  }
}

function idOf(request) {
  const id = request?.request_id;
  return typeof id === 'string' && /^[0-9a-f]+$/.test(id) ? id : '';
}

function failure(request_id, error, internalMessage = 'adapter operation failed') {
  return {
    request_id,
    ok: false,
    error: {
      code: error.code || 'internal',
      message: error.code ? error.message : internalMessage,
      retryable: error.retryable === true
    }
  };
}
