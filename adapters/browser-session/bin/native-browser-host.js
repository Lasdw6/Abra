#!/usr/bin/env node
import { NativeBrowserHost } from '../lib/native-browser-host.js';
import { normalBrowserRequest } from '../lib/normal-browser.js';

if (process.argv.includes('--connect')) {
  const result = await normalBrowserRequest('connect', {});
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exit(0);
}

const host = await new NativeBrowserHost({
  operationsFactory: async (cdp, context) => {
    const { createNativeBrowserOperations } = await import('../lib/native-browser-operations.js');
    return createNativeBrowserOperations(cdp, context);
  }
}).start();

let closing = false;
async function close() {
  if (closing) return;
  closing = true;
  await host.close();
}
process.on('SIGINT', () => { close().finally(() => process.exit(0)); });
process.on('SIGTERM', () => { close().finally(() => process.exit(0)); });
