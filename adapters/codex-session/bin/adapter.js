#!/usr/bin/env node
import { runAdapter } from '../../lib/adapter.js';
import { controlSession, exportSession, importSession, inspectSession } from '../lib/session.js';

await runAdapter({
  kinds: ['dev.abra.codex.session.v1'],
  controls: ['dev.abra.workspace'],
  verbs: {
    export: exportSession,
    import: importSession,
    inspect: inspectSession,
    control: controlSession
  },
  internalMessage: 'Codex session operation failed'
});
