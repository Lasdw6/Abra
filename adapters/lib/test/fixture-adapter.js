#!/usr/bin/env node
// Minimal adapter used by adapter.test.js to drive runAdapter over real pipes.
import { coded, runAdapter } from '../adapter.js';

await runAdapter({
  kinds: ['dev.abra.test.v1'],
  controls: ['dev.abra.workspace'],
  internalMessage: 'fixture operation failed',
  verbs: {
    async export(request, { signal }) {
      if (request.source === 'hang') {
        await new Promise(resolve => signal.addEventListener('abort', () => {
          process.stderr.write('aborted\n');
          resolve();
        }));
        return { payload: {}, files_path: null };
      }
      if (request.source === 'missing') throw coded('not_found', 'no such source');
      if (request.source === 'boom') throw new Error('leaky detail');
      return { payload: { echo: request.source }, files_path: request.staging_dir, floor: { title: 'fixture' } };
    },
    async import(request) {
      return { result: { imported: true, destination: request.destination, workspace: request.workspace } };
    },
    async inspect(request) {
      return {
        summary: `inspected ${request.source}`,
        warnings: [{ code: 'big', message: 'large file', item: 'blob.bin' }],
        blocked: request.source === 'secrets' ? [{ code: 'dotenv', message: 'refusing .env', item: '.env' }] : []
      };
    },
    async control(request, { signal }) {
      if (request.op === 'instruct' && request.text === 'hang') {
        await new Promise(resolve => signal.addEventListener('abort', resolve));
      }
      return { result: { op: request.op, text: request.text ?? null, workspace: request.workspace ?? null } };
    }
  }
});
