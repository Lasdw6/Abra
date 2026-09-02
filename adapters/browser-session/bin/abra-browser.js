#!/usr/bin/env node
import { run } from '../lib/cli.js';

run(process.argv.slice(2)).catch(error => { console.error(`abra-browser: ${error.message}`); process.exitCode = 1; });
