import { attachPage, evalValue, waitForLoad } from './cdp.js';
import { cookieForCdp, idbRestoreScript, openBlankOrigin } from './browser.js';

const fail = (code, message) => Object.assign(new Error(message), { code });
function webUrl(value) {
  try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) ? url : null; }
  catch { return null; }
}
function sharedStorage(origin) {
  return Boolean(origin.localStorage?.length || origin.indexedDB?.databases?.length);
}
function frameOrigins(frame, origins) {
  const url = webUrl(frame.frame?.url);
  if (url) origins.add(url.origin);
  for (const child of frame.childFrames || []) frameOrigins(child, origins);
}

// Inspect existing pages without navigating, reloading, or evaluating writes in them.
async function occupiedOrigins(cdp, created) {
  const { browserContextIds = [] } = await cdp.send('Target.getBrowserContexts');
  const privateContexts = new Set(browserContextIds);
  const { targetInfos } = await cdp.send('Target.getTargets');
  const origins = new Set();
  for (const target of targetInfos) {
    if (created.has(target.targetId) || privateContexts.has(target.browserContextId)) continue;
    const url = webUrl(target.url);
    if (url) origins.add(url.origin);
    if (target.type !== 'page' || !url) continue;
    let session;
    try {
      session = await attachPage(cdp, target.targetId);
      const { frameTree } = await cdp.send('Page.getFrameTree', {}, session);
      frameOrigins(frameTree, origins);
    } catch {
      throw fail('unavailable', 'An existing tab could not be checked. The transfer stopped; try again after it finishes loading.');
    } finally {
      if (session) await cdp.send('Target.detachFromTarget', { sessionId: session }).catch(() => {});
    }
  }
  return origins;
}

function validateState(state) {
  if (!state || !Array.isArray(state.tabs) || !state.tabs.length || state.tabs.length > 256 ||
      !Array.isArray(state.cookies) || !Array.isArray(state.origins) || state.tabs.some(tab => !webUrl(tab.url))) {
    throw fail('invalid_request', 'The session must contain valid web tabs, cookies, and site storage.');
  }
  const urls = state.tabs.map(tab => webUrl(tab.url));
  const origins = new Set(urls.map(url => url.origin));
  for (const origin of state.origins) {
    if (!origins.has(origin.origin)) throw fail('invalid_request', 'Site storage does not belong to a transferred tab.');
    for (const key of ['localStorage', 'sessionStorage']) {
      if (origin[key] !== undefined && (!Array.isArray(origin[key]) || origin[key].some(row => typeof row.name !== 'string' || typeof row.value !== 'string'))) {
        throw fail('invalid_request', 'Site storage contains an invalid entry.');
      }
    }
  }
  for (const cookie of state.cookies) {
    const domain = String(cookie.domain || webUrl(cookie.url)?.hostname || '').replace(/^\./, '').toLowerCase();
    if (!domain || typeof cookie.name !== 'string' || typeof cookie.value !== 'string' ||
        !urls.some(url => url.hostname === domain || url.hostname.endsWith('.' + domain)) ||
        (cookie.url && !urls.some(url => webUrl(cookie.url)?.origin === url.origin))) {
      throw fail('invalid_request', 'A cookie does not belong to a transferred tab.');
    }
  }
}

async function assertNoConflicts(cdp, state, created) {
  if (!state.cookies.length && !state.origins.some(sharedStorage)) return;
  const origins = await occupiedOrigins(cdp, created);
  const conflicts = new Set();
  for (const origin of state.origins) if (sharedStorage(origin) && origins.has(origin.origin)) conflicts.add(origin.origin);
  for (const cookie of state.cookies) {
    const domain = String(cookie.domain || webUrl(cookie.url)?.hostname || '').replace(/^\./, '').toLowerCase();
    for (const origin of origins) {
      const host = new URL(origin).hostname;
      if (host === domain || host.endsWith('.' + domain)) conflicts.add(origin);
    }
  }
  if (conflicts.size) throw fail('conflict', `This session would change shared sign-in or site data used by an existing tab (${[...conflicts].join(', ')}). Existing tabs were left untouched.`);
}

export async function importIntoNormalBrowser(cdp, state) {
  validateState(state);
  const created = new Set();
  await assertNoConflicts(cdp, state, created);
  try {
    if (state.cookies.length) await cdp.send('Storage.setCookies', { cookies: state.cookies.map(cookieForCdp) });
    for (const tab of state.tabs) {
      const origin = state.origins.find(item => item.origin === webUrl(tab.url).origin);
      const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank', newWindow: false, background: true });
      created.add(targetId);
      const session = await attachPage(cdp, targetId);
      try {
        if (origin) {
          await assertNoConflicts(cdp, { ...state, cookies: [], origins: [origin] }, created);
          await openBlankOrigin(cdp, session, origin.origin);
          const local = JSON.stringify(origin.localStorage || []), savedSession = JSON.stringify(origin.sessionStorage || []);
          await evalValue(cdp, session, `(() => { for (const item of ${local}) localStorage.setItem(item.name,item.value); for (const item of ${savedSession}) sessionStorage.setItem(item.name,item.value); return true; })()`);
          if (origin.indexedDB?.databases?.length) await evalValue(cdp, session, idbRestoreScript(origin.indexedDB));
        }
        await cdp.send('Page.navigate', { url: tab.url }, session);
        await waitForLoad(cdp, session);
        const x = Number.isFinite(tab.scroll?.x) ? tab.scroll.x : 0, y = Number.isFinite(tab.scroll?.y) ? tab.scroll.y : 0;
        if (x || y) await evalValue(cdp, session, `window.scrollTo(${x},${y})`);
      } finally {
        await cdp.send('Target.detachFromTarget', { sessionId: session }).catch(() => {});
      }
    }
    return {
      kind: 'dev.abra.browser-session.receipt.v1', installed_at: new Date().toISOString(),
      normal_browser: true, target_ids: [...created], reversible: false,
      cookies: state.cookies.map(({ name, domain, path }) => ({ name, domain, path })),
      origins: state.origins.map(origin => origin.origin),
      limitations: ['Existing tabs are never navigated, reloaded, or closed. Conflicting shared site state blocks restoration.', 'Imports into a normal profile cannot be atomically undone. Full navigation history and media playback are not restored.'],
    };
  } catch (error) {
    error.message += created.size ? ` ${created.size} new transfer tab(s) may remain open; existing tabs were not navigated or closed.` : '';
    throw error;
  }
}
