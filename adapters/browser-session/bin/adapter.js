#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { runAdapter } from '../../lib/adapter.js';
import { capture, withLocalChrome } from '../lib/browser.js';
import { installBundle } from '../lib/import.js';
import { KIND, LEGACY_KIND, loadBundle, parseList, saveBundle, secureTree, writePrivate } from '../lib/util.js';

const BUNDLE_FILES = ['state.json', 'storage_state.json', 'manifest.json'];

await runAdapter({
  kinds: [KIND, LEGACY_KIND],
  verbs: { export: exportRequest, import: importRequest },
  internalMessage: 'browser-session operation failed'
});

async function exportRequest(r) {
  const options = requestOptions(r), source = parseSource(r.source, options);
  if (source.type === 'bundle') return exported(await copyBundle(source.path, r.staging_dir), r.staging_dir);
  const policy = { includes: parseList(options.include_domains), excludes: parseList(options.exclude_domains) };
  const state = source.type === 'local' ? await withLocalChrome(source.profile, ws => capture(ws, policy)) : await capture(source.cdp_url, policy, { browserContextId: source.browser_context_id });
  return exported(await saveBundle(r.staging_dir, state, { source: source.type || 'cdp', allowNonPortable: options.allow_non_portable === 'true', policy: { include_domains: policy.includes, exclude_domains: policy.excludes } }), r.staging_dir);
}

function exported(manifest, dir) {
  return { payload: { kind: KIND, bundle_path: '.', manifest }, files_path: dir, floor: { title: 'Browser session', summary: `${manifest.domains.length} domains, ${manifest.tabs.length} tabs` } };
}

// Re-export a bundle another installation captured, such as one the sandbox
// coordinator pulled out of a sandbox. The bytes, signature and fingerprint
// travel unchanged so the receiver can trust the original signer.
async function copyBundle(dir, stagingDir) {
  const { manifest } = await loadBundle(dir);
  if (manifest.provenance?.reexportable === false) throw coded('invalid_request', 'bundle is not re-exportable');
  for (const name of BUNDLE_FILES) await writePrivate(path.join(stagingDir, name), await readFile(path.join(dir, name)));
  return manifest;
}

async function importRequest(r) {
  const bundle = r.materialized_files;
  if (!bundle) throw coded('invalid_request', 'materialized_files is required');
  const options = requestOptions(r);
  const destination = parseDestination(r.destination);
  const bundleDir = path.resolve(bundle);
  await secureTree(bundleDir);
  const { receipt, receiptPath } = await installBundle(bundleDir, destination, {
    policy: { allows: parseList(options.allow_domains), denies: parseList(options.deny_domains), allowNonPortable: options.allow_non_portable === 'true' },
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
    if (source.startsWith('bundle:') && source.slice(7)) return { type: 'bundle', path: path.resolve(source.slice(7)) };
    throw coded('invalid_request', 'source must be local:<profile>, cdp:<ws-url>, bundle:<dir>, or a ws(s) URL');
  }
  if (!source || typeof source !== 'object' || Array.isArray(source)) throw coded('invalid_request', 'source must be a string or object');
  if (source.type === 'bundle' && typeof source.path === 'string' && source.path) return { type: 'bundle', path: path.resolve(source.path) };
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
