import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { capture, install, launchLocalChrome, revoke, withLocalChrome } from './browser.js';
import { filterState, loadBundle, parseList, readJson, receiptPath, saveBundle, signObject, toStorageState, writeJson } from './util.js';

export function parseArgs(argv) {
  const positionals = [], flags = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) positionals.push(arg);
    else {
      const key = arg.slice(2);
      if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) flags[key] = argv[++i]; else flags[key] = true;
    }
  }
  return { positionals, flags };
}

function need(flags, name) { if (!flags[name] || flags[name] === true) throw new Error(`--${name} is required`); return flags[name]; }

export function summary(manifest) {
  const lines = [
    `${manifest.kind} captured ${manifest.capture_time}`,
    `Source: ${manifest.source_browser}`,
    `Size: ${manifest.total_size} bytes`,
    'Domains:'
  ];
  for (const d of manifest.domains) lines.push(`  ${d.domain}: ${d.cookie_count} cookies (${d.http_only_count} HttpOnly, ${d.secure_count} Secure)`);
  lines.push('Tabs:');
  for (const tab of manifest.tabs) lines.push(`  ${tab.title || '(untitled)'} — ${tab.url}`);
  lines.push('Non-teleportable (heuristic):');
  if (!manifest.non_teleportable.length) lines.push('  none detected');
  for (const item of manifest.non_teleportable) lines.push(`  ${item.domain}: ${item.reasons.join('; ')}`);
  return lines.join('\n');
}

export async function run(argv, io = console) {
  const { positionals, flags } = parseArgs(argv);
  const command = positionals[0];
  if (command === 'export') {
    const from = need(flags, 'from');
    const out = path.resolve(flags.out || `browser-session-${Date.now()}`);
    const policy = { includes: parseList(flags['include-domains']), excludes: parseList(flags['exclude-domains']) };
    const state = from === 'cdp' ? await capture(positionals[1] || need(flags, 'cdp'), policy)
      : from === 'local' ? await withLocalChrome(flags.profile, ws => capture(ws, policy))
      : (() => { throw new Error('--from must be local or cdp'); })();
    const manifest = await saveBundle(out, state, { source: from, sourceBrowser: 'Google Chrome 152 via CDP', policy: { include_domains: policy.includes, exclude_domains: policy.excludes } });
    io.log(out); return { out, manifest };
  }
  if (command === 'inspect') {
    const dir = path.resolve(positionals[1] || '.');
    const { manifest } = await loadBundle(dir);
    io.log(summary(manifest)); return manifest;
  }
  if (command === 'import') {
    const dir = path.resolve(positionals[1] || '.');
    const to = need(flags, 'to');
    const { state } = await loadBundle(dir);
    const policy = { allows: parseList(flags['allow-domains']), denies: parseList(flags['deny-domains']) };
    let receipt;
    if (to === 'cdp') receipt = await install(positionals[2] || need(flags, 'cdp'), state, policy, { watchMs: Number(flags['watch-ms'] || 0) });
    else if (to === 'local') {
      const local = await launchLocalChrome(flags.profile);
      receipt = await install(local.wsUrl, state, policy, { watchMs: Number(flags['watch-ms'] || 0) });
      receipt.local_chrome = { pid: local.child.pid, profile_copy: local.tempRoot };
      local.child.unref();
    } else throw new Error('--to must be local or cdp');
    receipt.source_bundle = dir;
    receipt.reexportable = false;
    receipt.signature = signObject(receipt, 'browser-session-install-receipt');
    const output = flags.receipt ? path.resolve(flags.receipt) : receiptPath(dir);
    await writeJson(output, receipt); io.log(output); return receipt;
  }
  if (command === 'revoke') {
    const file = path.resolve(positionals[1] || '');
    const receipt = await readJson(file);
    const result = await revoke(receipt); await writeJson(`${file}.revoked.json`, result); io.log(`${file}.revoked.json`); return result;
  }
  if (command === 'storage-state') return storageState(positionals.slice(1), flags, io);
  throw new Error('usage: abra-browser export|inspect|import|revoke|storage-state');
}

async function storageState(positionals, flags, io) {
  const verb = positionals[0];
  if (verb === 'import') {
    const input = path.resolve(positionals[1] || need(flags, 'in'));
    const out = path.resolve(flags.out || `browser-session-${Date.now()}`);
    const raw = await readFile(input);
    const storage = JSON.parse(raw);
    const state = { cookies: storage.cookies || [], origins: (storage.origins || []).map(o => ({ ...o, sessionStorage: [], indexedDB: { databases: [] } })), tabs: [] };
    await saveBundle(out, state, { source: 'playwright-storage-state', sourceBrowser: 'Playwright storage_state', storageState: storage, storageStateRaw: raw, provenance: { capture: 'storage_state-import', reexportable: true } });
    io.log(out); return { out };
  }
  if (verb === 'export') {
    const input = path.resolve(positionals[1] || need(flags, 'in'));
    const out = path.resolve(flags.out || 'storage_state.json');
    await loadBundle(input);
    await copyFile(path.join(input, 'storage_state.json'), out);
    io.log(out); return { out };
  }
  throw new Error('usage: abra-browser storage-state import <file> --out <bundle> | export <bundle> --out <file>');
}
