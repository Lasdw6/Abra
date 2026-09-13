import { randomUUID } from 'node:crypto';
import { realpath, rm } from 'node:fs/promises';
import path from 'node:path';
import { install } from './browser.js';
import { ensureManagedBrowser, processIdentity as managedProcessIdentity, stopChrome } from './managed.js';
import { dataDir, loadBundle, signObject, signingIdentity, writeJson } from './util.js';
import { applyTransferPolicy } from './transfer-policy.js';
import { normalBrowserRequest } from './normal-browser.js';

export function registryFile(id) { return path.join(dataDir(), 'installs', `${id}.json`); }
export function receiptFile(id) { return path.join(dataDir(), 'receipts', `${id}.json`); }

// managed.js owns the per-platform process lookup; a registered install must
// have an identity, so a missing one is an error here rather than a null.
export async function processIdentity(pid) {
  const identity = await managedProcessIdentity(pid);
  if (!identity) throw new Error('cannot verify registered Chrome process identity');
  return identity;
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

  if (manifest.source === 'saved-cookie-db-read-only') {
    throw Object.assign(new Error('Restoring saved-cookie captures is disabled after a reported source sign-out.'), { code: 'unavailable' });
  }

  const installId = randomUUID();
  const filtered = applyTransferPolicy(state, destination, options.policy || {});
  const authApplied = Boolean(filtered.cookies.length || filtered.origins.length);
  if (destination.type === 'normal') {
    const receipt = await normalBrowserRequest('import', { state: filtered });
    receipt.install_id = installId;
    receipt.source_bundle_sha256 = manifest.state_sha256;
    receipt.reexportable = false;
    receipt.auth_applied = authApplied;
    receipt.signature = signObject(receipt, await signingIdentity(), 'browser-session-install-receipt');
    const output = options.receiptPath ? path.resolve(options.receiptPath) : receiptFile(installId);
    await writeJson(output, receipt);
    return { receipt, receiptPath: output };
  }
  const managed = destination.type !== 'cdp';
  const wsUrl = managed ? (await ensureManagedBrowser()).wsUrl : destination.cdpUrl;

  const receipt = await install(wsUrl, filtered, { allows: options.policy?.allows, denies: options.policy?.denies }, { watchMs: options.watchMs || 0 });
  receipt.install_id = installId;
  receipt.source_bundle_sha256 = manifest.state_sha256;
  receipt.reexportable = false;
  receipt.auth_applied = authApplied;
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
