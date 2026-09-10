import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { offlineCaptureCommand, offlineCapturePolicy, spawnOfflineChrome } from './offline-capture.js';
import { chromeBinary, stopChrome } from '../../../lib/managed.js';

const execFileAsync = promisify(execFile);

test('offline capture policy permits only temporary writes and denies all network', () => {
  const policy = offlineCapturePolicy('/private/tmp/capture "copy"');
  assert.match(policy, /\(deny network\*\)/);
  assert.doesNotMatch(policy, /allow network/);
  assert.match(policy, /deny file-write\* \(require-not \(subpath/);
  assert.match(policy, /capture \\"copy\\"/);
  assert.throws(() => offlineCapturePolicy('/'), /filesystem root/);
});

test('strict write policy currently blocks Chrome process-singleton startup without weakening isolation', { timeout: 30000 }, async t => {
  if (process.platform !== 'darwin') { t.skip('macOS Chrome sandbox test'); return; }
  let binary;
  try { binary = await chromeBinary(); } catch (error) { t.skip(error.message); return; }
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'abra-offline-chrome-'));
  const outside = await mkdtemp(path.join(os.tmpdir(), 'abra-offline-source-'));
  await writeFile(path.join(outside, 'marker'), 'unchanged');
  let hits = 0;
  const canary = net.createServer(socket => { hits++; socket.end('network escaped'); });
  await new Promise(resolve => canary.listen(0, '127.0.0.1', resolve));
  let child, cdp;
  try {
    ({ child, cdp } = await spawnOfflineChrome(binary, [
      `--user-data-dir=${temporary}`, `--disk-cache-dir=${outside}`, '--headless=new', '--no-first-run', '--no-default-browser-check', 'about:blank'
    ], temporary));
    await assert.rejects(cdp.send('Browser.getVersion'), /Failed to create (?:socket directory|a ProcessSingleton)/);
    assert.equal(hits, 0);
    assert.deepEqual(await readdir(outside), ['marker']);
    assert.equal(await readFile(path.join(outside, 'marker'), 'utf8'), 'unchanged');
  } finally {
    cdp?.close();
    if (child?.pid) await stopChrome(child.pid, temporary).catch(() => {});
    await new Promise(resolve => canary.close(resolve));
    await rm(temporary, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('macOS offline capture sandbox blocks source writes and non-loopback traffic', { timeout: 15000 }, async t => {
  if (process.platform !== 'darwin') { t.skip('macOS sandbox enforcement test'); return; }
  const root = await mkdtemp(path.join(os.tmpdir(), 'abra-offline-capture-'));
  const source = path.join(root, 'source-marker');
  const allowed = await mkdtemp(path.join(os.tmpdir(), 'abra-offline-copy-'));
  await writeFile(source, 'unchanged');
  const loopback = net.createServer(socket => socket.end('ok'));
  await new Promise(resolve => loopback.listen(0, '127.0.0.1', resolve));
  const externalAddress = Object.values(os.networkInterfaces()).flat().find(item => item?.family === 'IPv4' && !item.internal)?.address;
  const external = externalAddress ? net.createServer(socket => socket.end('unexpected')) : null;
  if (external) await new Promise(resolve => external.listen(0, '0.0.0.0', resolve));
  try {
    const script = `
      const fs=require('fs'),net=require('net');
      let sourceBlocked=false,loopbackBlocked=false,externalBlocked=${external ? 'false' : 'true'};
      try{fs.writeFileSync(process.argv[1],'changed')}catch{sourceBlocked=true}
      fs.writeFileSync(process.argv[2],'allowed');
      const request=(host,port)=>new Promise((ok,bad)=>{const s=net.connect(port,host,()=>{s.destroy();ok()});s.on('error',bad)});
      request('127.0.0.1',Number(process.argv[3])).catch(()=>{loopbackBlocked=true}).then(async()=>{
        ${external ? `try{await request(process.argv[4],Number(process.argv[5]))}catch{externalBlocked=true}` : ''}
        process.stdout.write(JSON.stringify({sourceBlocked,loopbackBlocked,externalBlocked}));
      }).catch(error=>{process.stderr.write(error.stack);process.exit(2)});`;
    const command = await offlineCaptureCommand(process.execPath, ['-e', script, source, path.join(allowed, 'marker'), String(loopback.address().port), ...(external ? [externalAddress, String(external.address().port)] : [])], allowed);
    const { stdout } = await execFileAsync(command.executable, command.args);
    assert.deepEqual(JSON.parse(stdout), { sourceBlocked: true, loopbackBlocked: true, externalBlocked: true });
    assert.equal(await readFile(source, 'utf8'), 'unchanged');
    assert.equal(await readFile(path.join(allowed, 'marker'), 'utf8'), 'allowed');
  } finally {
    await Promise.all([new Promise(resolve => loopback.close(resolve)), ...(external ? [new Promise(resolve => external.close(resolve))] : [])]);
    await rm(root, { recursive: true, force: true });
    await rm(allowed, { recursive: true, force: true });
  }
});
