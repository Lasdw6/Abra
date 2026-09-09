import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { realpath, rm } from 'node:fs/promises';
import path from 'node:path';
import { install } from './browser.js';
import { ensureManagedBrowser, stopChrome } from './managed.js';
import { dataDir, loadBundle, signObject, signingIdentity, writeJson } from './util.js';

const execFileAsync = promisify(execFile);

export function registryFile(id) { return path.join(dataDir(), 'installs', `${id}.json`); }
export function receiptFile(id) { return path.join(dataDir(), 'receipts', `${id}.json`); }

export async function processIdentity(pid) {
  const { stdout } = await execFileAsync('/bin/ps', ['-p', String(pid), '-o', 'lstart=', '-o', 'command=']);
  const match = stdout.trim().match(/^(\S+\s+\S+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+([\s\S]+)$/);
  if (!match) throw new Error('cannot verify registered Chrome process identity');
  return { started_at: match[1], command: match[2] };
}

export async function safeContainedDelete(candidate, root) {
  const resolvedRoot = await realpath(root);
  const resolved = await realpath(candidate);
  if (resolved === resolvedRoot || !resolved.startsWith(`${resolvedRoot}${path.sep}`)) throw new Error('refusing to remove path outside the browser-session data directory');
  await rm(resolved, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
}

export async function cleanupLocalProfile(local, options = {}) {
  const stop = options.stop || stopChrome;
  const remove = options.remove || safeContainedDelete;
  let stopError;
  try {
    await stop(local.child.pid, local.tempRoot);
  } catch (error) {
    stopError = error;
  }
  try {
    await remove(local.tempRoot, path.join(dataDir(), 'profiles'));
  } catch (error) {
    throw new Error(`failed to delete browser profile ${local.tempRoot}; sender cookies remain on disk`, { cause: error });
  }
  if (stopError) throw stopError;
}

export async function installBundle(bundleDir, destination, options = {}) {
  const { state, manifest } = await loadBundle(bundleDir, options.trustSender ? { trustSender: options.trustSender } : {});
  if (options.requireLocalTrust) {
    const identity = await signingIdentity();
    if (manifest.signature.fingerprint !== identity.fingerprint && options.trustSender !== manifest.signature.fingerprint) {
      throw new Error(`untrusted sender ${manifest.signature.fingerprint}; rerun with --trust-sender ${manifest.signature.fingerprint} after verifying it out of band`);
    }
  }

  const installId = randomUUID();
  const managed = destination.type !== 'cdp';
  const wsUrl = managed ? (await ensureManagedBrowser()).wsUrl : destination.cdpUrl;

  const receipt = await install(wsUrl, state, options.policy || {}, { watchMs: options.watchMs || 0 });
  receipt.install_id = installId;
  receipt.source_bundle_sha256 = manifest.state_sha256;
  receipt.reexportable = false;
  if (managed) receipt.managed = true;
  await writeJson(registryFile(installId), {
    cdp_url: wsUrl,
    browser_context_id: receipt.browser_context_id,
    origins: receipt.origins,
    ...(managed ? { managed: true } : {})
  });
  receipt.signature = signObject(receipt, await signingIdentity(), 'browser-session-install-receipt');
  const output = options.receiptPath ? path.resolve(options.receiptPath) : receiptFile(installId);
  await writeJson(output, receipt);
  return { receipt, receiptPath: output };
}
