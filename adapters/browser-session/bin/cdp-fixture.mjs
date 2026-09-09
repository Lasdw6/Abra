#!/usr/bin/env node
// Test helper: seed and read one origin's cookies, localStorage and tabs over
// raw CDP. Zero dependencies; needs ../lib/cdp.js next to it, so push bin/ and
// lib/ together. Prints cookie values, so it is for test browsers only.
//
//   node bin/cdp-fixture.mjs set --cdp ws://… --url http://127.0.0.1:8123/marker.txt --cookie name=value --local key=value
//   node bin/cdp-fixture.mjs get --cdp ws://… --url http://127.0.0.1:8123/
//
// `set` opens a tab at --url and leaves it open. `get` looks across every
// browser context, so it sees what an Abra import put in its own context.
import { CDP, attachPage, evalValue, waitForLoad } from '../lib/cdp.js';

function parseArgs(argv) { const positionals=[],flags={};for(let i=0;i<argv.length;i++){const arg=argv[i];if(!arg.startsWith('--')){positionals.push(arg);continue;}const key=arg.slice(2),value=i+1<argv.length&&!argv[i+1].startsWith('--')?argv[++i]:true;if(key==='cookie'||key==='local')(flags[key]??=[]).push(value);else flags[key]=value;}return{positionals,flags}; }
function need(flags,name){if(!flags[name]||flags[name]===true)throw new Error(`--${name} is required`);return flags[name];}
function pair(value){const i=String(value).indexOf('=');if(i<1)throw new Error(`expected key=value, got ${value}`);return{name:value.slice(0,i),value:value.slice(i+1)};}
function cookieMatches(cookie,host){const domain=String(cookie.domain||'').replace(/^\./,'');return domain===host||host.endsWith(`.${domain}`);}

export async function set(cdp, url, cookies, locals) {
  const targetId = (await cdp.send('Target.createTarget', { url })).targetId;
  const session = await attachPage(cdp, targetId);
  try {
    await waitForLoad(cdp, session);
    // A slow origin is still about:blank when the target attaches; wait until the page is really there.
    const origin = new URL(url).origin;
    const end = Date.now() + 20000;
    while (!(await evalValue(cdp, session, 'location.origin')).startsWith(origin)) {
      if (Date.now() > end) throw new Error(`page did not navigate to ${origin}`);
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    await waitForLoad(cdp, session);
    for (const cookie of cookies) await cdp.send('Network.setCookie', { url, ...cookie }, session);
    for (const item of locals) await evalValue(cdp, session, `(localStorage.setItem(${JSON.stringify(item.name)}, ${JSON.stringify(item.value)}), true)`);
  } finally { await cdp.send('Target.detachFromTarget', { sessionId: session }).catch(() => {}); }
  return { target_id: targetId, url, cookies: cookies.map(c => c.name), local_storage: locals.map(l => l.name) };
}

export async function get(cdp, url) {
  const { origin, hostname } = new URL(url);
  const contexts = [undefined, ...(await cdp.send('Target.getBrowserContexts')).browserContextIds];
  const cookies = [];
  for (const browserContextId of contexts) {
    for (const cookie of (await cdp.send('Storage.getCookies', browserContextId ? { browserContextId } : {})).cookies) if (cookieMatches(cookie, hostname)) cookies.push(cookie);
  }
  const tabs = (await cdp.send('Target.getTargets')).targetInfos.filter(t => t.type === 'page' && t.url.startsWith(origin));
  const local = new Map();
  for (const tab of tabs) {
    const session = await attachPage(cdp, tab.targetId);
    try {
      await waitForLoad(cdp, session);
      for (const item of await evalValue(cdp, session, 'Object.keys(localStorage).sort().map(name => ({ name, value: localStorage.getItem(name) }))')) local.set(`${item.name}\0${item.value}`, item);
    } finally { await cdp.send('Target.detachFromTarget', { sessionId: session }).catch(() => {}); }
  }
  return { origin, cookies, local_storage: [...local.values()], tabs: tabs.map(t => t.url) };
}

export async function run(argv) {
  const { positionals, flags } = parseArgs(argv), command = positionals[0];
  if (command !== 'set' && command !== 'get') throw new Error('usage: cdp-fixture set|get --cdp <ws> --url <url> [--cookie name=value ...] [--local key=value ...]');
  const cdp = await new CDP(need(flags, 'cdp')).connect(), url = need(flags, 'url');
  try { return command === 'set' ? await set(cdp, url, (flags.cookie || []).map(pair), (flags.local || []).map(pair)) : await get(cdp, url); }
  finally { cdp.close(); }
}

run(process.argv.slice(2)).then(result => console.log(JSON.stringify(result))).catch(error => { console.error(`cdp-fixture: ${error.message}`); process.exitCode = 1; });
