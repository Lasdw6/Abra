#!/usr/bin/env node
import { createInterface } from 'node:readline';
import path from 'node:path';
import { capture, install, withLocalChrome } from '../lib/browser.js';
import { KIND, parseList, saveBundle } from '../lib/util.js';

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  let request;
  try {
    if (Buffer.byteLength(line) > 1024 * 1024) throw coded('invalid_request', 'request exceeds 1 MiB');
    request = JSON.parse(line);
    if (request.protocol !== 'abra-adapter/1' || !/^[0-9a-f]+$/.test(request.request_id || '')) throw coded('invalid_request', 'invalid protocol or request_id');
    if (request.kind !== KIND) throw coded('unsupported_kind', `expected ${KIND}`);
    const response = request.verb === 'export' ? await exportRequest(request)
      : request.verb === 'import' ? await importRequest(request)
      : (() => { throw coded('unsupported_verb', `unsupported verb: ${request.verb}`); })();
    emit({ request_id: request.request_id, ok: true, ...response });
  } catch (error) {
    emit({ request_id: request?.request_id || '', ok: false, error: { code: error.code || 'internal', message: error.message, retryable: false } });
  }
}

async function exportRequest(r) {
  const options = r.options || {}, source = r.source || {};
  const policy = { includes: parseList(options.include_domains), excludes: parseList(options.exclude_domains) };
  const state = source.type === 'local' ? await withLocalChrome(source.profile, ws => capture(ws, policy)) : await capture(source.cdp_url, policy);
  const manifest = await saveBundle(r.staging_dir, state, { source: source.type || 'cdp', policy: { include_domains: policy.includes, exclude_domains: policy.excludes } });
  return { payload: { kind: KIND, bundle_path: '.', manifest }, files_path: r.staging_dir, floor: { title: 'Browser session', summary: `${manifest.domains.length} domains, ${manifest.tabs.length} tabs` } };
}

async function importRequest(r) {
  const bundle = r.materialized_files || r.payload?.bundle_path;
  if (!bundle) throw coded('invalid_request', 'materialized_files is required');
  const { loadBundle } = await import('../lib/util.js');
  const { state } = await loadBundle(path.resolve(bundle));
  const receipt = await install(r.destination?.cdp_url || r.destination, state, { allows: parseList(r.options?.allow_domains), denies: parseList(r.options?.deny_domains) });
  return { result: { receipt } };
}

function coded(code, message) { return Object.assign(new Error(message), { code }); }
function emit(value) { process.stdout.write(`${JSON.stringify(value)}\n`); }
