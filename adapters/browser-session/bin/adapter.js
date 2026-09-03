#!/usr/bin/env node
import { createInterface } from 'node:readline';
import path from 'node:path';
import { capture, withLocalChrome } from '../lib/browser.js';
import { installBundle } from '../lib/import.js';
import { KIND, LEGACY_KIND, parseList, saveBundle, secureTree } from '../lib/util.js';

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  let request;
  try {
    if (Buffer.byteLength(line) > 1024 * 1024) throw coded('invalid_request', 'request exceeds 1 MiB');
    request = JSON.parse(line);
    if (request.protocol !== 'abra-adapter/1' || !/^[0-9a-f]+$/.test(request.request_id || '')) throw coded('invalid_request', 'invalid protocol or request_id');
    if (![KIND, LEGACY_KIND].includes(request.kind)) throw coded('unsupported_kind', `expected ${KIND} or ${LEGACY_KIND}`);
    const response = request.verb === 'export' ? await exportRequest(request)
      : request.verb === 'import' ? await importRequest(request)
      : (() => { throw coded('unsupported_verb', `unsupported verb: ${request.verb}`); })();
    emit({ request_id: request.request_id, ok: true, ...response });
  } catch (error) {
    emit({ request_id: request?.request_id || '', ok: false, error: { code: error.code || 'internal', message: error.code ? error.message : 'browser-session operation failed', retryable: false } });
  }
}

async function exportRequest(r) {
  const options = requestOptions(r), source = parseSource(r.source, options);
  const policy = { includes: parseList(options.include_domains), excludes: parseList(options.exclude_domains) };
  const state = source.type === 'local' ? await withLocalChrome(source.profile, ws => capture(ws, policy)) : await capture(source.cdp_url, policy, { browserContextId: source.browser_context_id });
  const manifest = await saveBundle(r.staging_dir, state, { source: source.type || 'cdp', policy: { include_domains: policy.includes, exclude_domains: policy.excludes } });
  return { payload: { kind: KIND, bundle_path: '.', manifest }, files_path: r.staging_dir, floor: { title: 'Browser session', summary: `${manifest.domains.length} domains, ${manifest.tabs.length} tabs` } };
}

async function importRequest(r) {
  const bundle = r.materialized_files;
  if (!bundle) throw coded('invalid_request', 'materialized_files is required');
  const options = requestOptions(r);
  const destination = parseDestination(r.destination);
  const bundleDir = path.resolve(bundle);
  await secureTree(bundleDir);
  const { receipt, receiptPath } = await installBundle(bundleDir, destination, {
    policy: { allows: parseList(options.allow_domains), denies: parseList(options.deny_domains) },
    watchMs: parseWatchMs(options.watch_ms),
    trustSender: options.trust_sender
  });
  return { result: { receipt, receipt_path: receiptPath } };
}

function requestOptions(request) {
  if (request.options === undefined) return {};
  if (!request.options || typeof request.options !== 'object' || Array.isArray(request.options)) throw coded('invalid_request', 'options must be an object');
  return request.options;
}

function parseSource(source, options) {
  if (typeof source === 'string') {
    if (source.startsWith('local:') && (source.slice(6) || options.profile)) return { type: 'local', profile: source.slice(6) || options.profile };
    if (source.startsWith('cdp:') && /^wss?:\/\//.test(source.slice(4))) return { type: 'cdp', cdp_url: source.slice(4), browser_context_id: options.browser_context_id };
    if (/^wss?:\/\//.test(source)) return { type: 'cdp', cdp_url: source, browser_context_id: options.browser_context_id };
    throw coded('invalid_request', 'source must be local:<profile>, cdp:<ws-url>, or a ws(s) URL');
  }
  if (!source || typeof source !== 'object' || Array.isArray(source)) throw coded('invalid_request', 'source must be a string or object');
  if (source.type === 'local' && (source.profile || options.profile)) return { type: 'local', profile: source.profile || options.profile };
  if (source.type === 'cdp' && typeof source.cdp_url === 'string' && /^wss?:\/\//.test(source.cdp_url)) return { ...source, browser_context_id: source.browser_context_id || options.browser_context_id };
  throw coded('invalid_request', 'invalid browser-session source object');
}

function parseDestination(destination) {
  if (typeof destination === 'string') {
    if (destination === 'local') return { type: 'local' };
    if (destination.startsWith('cdp:') && /^wss?:\/\//.test(destination.slice(4))) return { type: 'cdp', cdpUrl: destination.slice(4) };
    if (/^wss?:\/\//.test(destination)) return { type: 'cdp', cdpUrl: destination };
  }
  if (destination && typeof destination === 'object' && !Array.isArray(destination)) {
    if (destination.type === 'local') return { type: 'local' };
    if (destination.type === 'cdp' && typeof destination.cdp_url === 'string' && /^wss?:\/\//.test(destination.cdp_url)) return { type: 'cdp', cdpUrl: destination.cdp_url };
  }
  throw coded('invalid_request', 'browser-session import requires --destination local or --destination cdp:<ws-url>');
}

function parseWatchMs(value) {
  if (value === undefined || value === '') return 0;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) throw coded('invalid_request', 'watch_ms must be a non-negative number');
  return parsed;
}

function coded(code, message) { return Object.assign(new Error(message), { code }); }
function emit(value) { process.stdout.write(`${JSON.stringify(value)}\n`); }
