#!/usr/bin/env node
import { run, parseArgs } from '../lib/cli.js';
import { loadBundle } from '../lib/util.js';

const argv = process.argv.slice(2);
const { positionals, flags } = parseArgs(argv);
if (positionals[0] !== 'sync') {
  console.error('usage: profile-use sync --profile <name> [--include-domains a,b] [--exclude-domains c] --cloud-profile-id <id> [--endpoint URL]');
  process.exitCode = 1;
} else {
  const endpoint = String(flags.endpoint || process.env.BROWSER_USE_API_URL || 'http://127.0.0.1:8787').replace(/\/$/, '');
  const out = flags.out || `browser-session-${Date.now()}`;
  try {
    await run(['export', '--from', 'local', ...(flags.profile ? ['--profile', flags.profile] : []), ...(flags['include-domains'] ? ['--include-domains', flags['include-domains']] : []), ...(flags['exclude-domains'] ? ['--exclude-domains', flags['exclude-domains']] : []), '--out', out]);
    const { manifest } = await loadBundle(out);
    const response = await fetch(`${endpoint}/api/v4/profiles/${flags['cloud-profile-id']}`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ bundlePath: out, cookieDomains: manifest.domains.map(d => d.domain) }) });
    if (!response.ok) throw new Error(`profile API returned ${response.status}`);
    console.log(JSON.stringify(await response.json()));
  } catch (error) { console.error(`profile-use: ${error.message}`); process.exitCode = 1; }
}
