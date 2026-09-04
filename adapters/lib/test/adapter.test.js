import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const FIXTURE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixture-adapter.js');

// Writes each line to the fixture adapter's stdin and collects its NDJSON replies.
async function drive(lines) {
  const child = spawn(process.execPath, [FIXTURE], { stdio: ['pipe', 'pipe', 'pipe'] });
  const stdout = [], stderr = [];
  child.stdout.on('data', chunk => stdout.push(chunk));
  child.stderr.on('data', chunk => stderr.push(chunk));
  child.stdin.end(lines.map(line => `${typeof line === 'string' ? line : JSON.stringify(line)}\n`).join(''));
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
  const responses = Buffer.concat(stdout).toString().split('\n').filter(Boolean).map(line => JSON.parse(line));
  return { code, responses, stderr: Buffer.concat(stderr).toString() };
}

function request(fields) {
  return { protocol: 'abra-adapter/1', request_id: 'a1b2', kind: 'dev.abra.test.v1', ...fields };
}

test('export replies with flat result fields', async () => {
  const { code, responses } = await drive([request({ verb: 'export', source: 'folder', staging_dir: '/tmp/staging' })]);
  assert.equal(code, 0);
  assert.deepEqual(responses, [{
    request_id: 'a1b2',
    ok: true,
    payload: { echo: 'folder' },
    files_path: '/tmp/staging',
    floor: { title: 'fixture' }
  }]);
});

test('import replies and coded errors keep their code and message', async () => {
  const { responses } = await drive([
    request({ request_id: 'ff', verb: 'import', payload: {}, materialized_files: '/tmp/files', destination: '/tmp/out', workspace: '/tmp/workspace' }),
    request({ request_id: 'ee', verb: 'export', source: 'missing' }),
    request({ request_id: 'dd', verb: 'export', source: 'boom' })
  ]);
  assert.deepEqual(responses[0], { request_id: 'ff', ok: true, result: { imported: true, destination: '/tmp/out', workspace: '/tmp/workspace' } });
  assert.deepEqual(responses[1].error, { code: 'not_found', message: 'no such source', retryable: false });
  assert.deepEqual(responses[2].error, { code: 'internal', message: 'fixture operation failed', retryable: false });
});

test('unsupported verb and unsupported kind are reported per the contract', async () => {
  const { responses } = await drive([
    request({ request_id: 'aa', verb: 'watch', source: 'folder' }),
    request({ request_id: 'bb', verb: 'export', kind: 'dev.abra.other.v1' })
  ]);
  assert.equal(responses[0].ok, false);
  assert.equal(responses[0].error.code, 'unsupported_verb');
  assert.equal(responses[1].error.code, 'unsupported_kind');
});

test('bad protocol, bad request_id, and malformed JSON are invalid_request', async () => {
  const { responses } = await drive([
    { protocol: 'abra-adapter/2', request_id: 'cc', kind: 'dev.abra.test.v1', verb: 'export' },
    { protocol: 'abra-adapter/1', request_id: 'NOT-HEX', kind: 'dev.abra.test.v1', verb: 'export' },
    '{not json'
  ]);
  assert.deepEqual(responses.map(r => [r.request_id, r.ok, r.error.code]), [
    ['cc', false, 'invalid_request'],
    ['', false, 'invalid_request'],
    ['', false, 'invalid_request']
  ]);
});

test('cancel aborts the in-flight verb and answers once with cancelled', async () => {
  const { code, responses, stderr } = await drive([
    request({ verb: 'export', source: 'hang' }),
    { protocol: 'abra-adapter/1', request_id: 'a1b2', verb: 'cancel' }
  ]);
  assert.equal(code, 0);
  assert.equal(responses.length, 1);
  assert.deepEqual(responses[0], { request_id: 'a1b2', ok: false, error: { code: 'cancelled', message: 'cancelled', retryable: false } });
  assert.match(stderr, /aborted/);
});

test('control is dispatched for a declared capsule kind, not for other kinds', async () => {
  const { responses } = await drive([
    { protocol: 'abra-adapter/1', request_id: 'c1', kind: 'dev.abra.workspace', verb: 'control', op: 'instruct', text: 'ship it', workspace: '/w', options: {} },
    { protocol: 'abra-adapter/1', request_id: 'c2', kind: 'dev.abra.other', verb: 'control', op: 'pause' },
    request({ request_id: 'c3', verb: 'control', op: 'pause' })
  ]);
  assert.deepEqual(responses[0], {
    request_id: 'c1',
    ok: true,
    result: { op: 'instruct', text: 'ship it', workspace: '/w' }
  });
  assert.equal(responses[1].error.code, 'unsupported_kind');
  assert.deepEqual(responses[2].result, { op: 'pause', text: null, workspace: null });
});

test('inspect replies with summary, warnings, and blocked', async () => {
  const { responses } = await drive([
    request({ request_id: 'd1', verb: 'inspect', source: 'folder', options: {} }),
    request({ request_id: 'd2', verb: 'inspect', source: 'secrets', options: {} })
  ]);
  assert.deepEqual(responses[0], {
    request_id: 'd1',
    ok: true,
    summary: 'inspected folder',
    warnings: [{ code: 'big', message: 'large file', item: 'blob.bin' }],
    blocked: []
  });
  assert.equal(responses[1].blocked[0].code, 'dotenv');
});

test('cancel aborts an in-flight control', async () => {
  const { responses } = await drive([
    { protocol: 'abra-adapter/1', request_id: 'c9', kind: 'dev.abra.workspace', verb: 'control', op: 'instruct', text: 'hang' },
    { protocol: 'abra-adapter/1', request_id: 'c9', verb: 'cancel' }
  ]);
  assert.equal(responses.length, 1);
  assert.equal(responses[0].error.code, 'cancelled');
});
