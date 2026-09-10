import { captureTarget } from './browser.js';
import { importIntoNormalBrowser } from './native-import.js';

const KIND = 'dev.abra.browser.session.v1';

function fail(code, message) {
  return Object.assign(new Error(message), { code });
}

function displayLabel(value) {
  const normalized = String(value || '').replace(/\p{Cc}/gu, ' ').trim() || 'Untitled tab';
  let label = '';
  let bytes = 0;
  for (const character of normalized) {
    const size = Buffer.byteLength(character);
    if (bytes + size > 200) break;
    label += character;
    bytes += size;
  }
  return label;
}

function webUrl(value) {
  try { return ['http:', 'https:'].includes(new URL(value).protocol); } catch { return false; }
}

export function createNativeBrowserOperations(cdp, { browserSession }) {
  if (!cdp?.send || typeof browserSession !== 'string' || !browserSession) {
    throw new Error('native browser operations require a CDP connection and browser session');
  }

  async function targets() {
    const privateContexts = new Set((await cdp.send('Target.getBrowserContexts')).browserContextIds || []);
    return (await cdp.send('Target.getTargets')).targetInfos.filter(target =>
      target.type === 'page' && webUrl(target.url) && !privateContexts.has(target.browserContextId)
    );
  }

  async function inventory() {
    const items = (await targets()).slice(0, 256).map(target => {
      const expectedUrl = new URL(target.url).href;
      return {
        id: `chrome:${browserSession}:${target.targetId}`,
        kind: KIND,
        label: displayLabel(target.title || expectedUrl),
        detail: expectedUrl.slice(0, 2000),
        source: { type: 'normal', target_id: target.targetId, expected_url: expectedUrl, browser_session: browserSession },
        options: {},
        transferable: true,
      };
    });
    return { label: 'Browser', items };
  }

  async function exportState({ source, options = {} } = {}) {
    if (!source || source.type !== 'normal' || source.browser_session !== browserSession) {
      throw fail('not_found', 'This tab belongs to an earlier Chrome session. Refresh the device contents and select it again.');
    }
    if (typeof source.target_id !== 'string' || !source.target_id || typeof source.expected_url !== 'string') {
      throw fail('invalid_request', 'The selected browser source is invalid.');
    }
    const target = (await targets()).find(item => item.targetId === source.target_id);
    if (!target || new URL(target.url).href !== new URL(source.expected_url).href) {
      throw fail('not_found', 'The selected tab was closed or navigated to another page. Select it again from the latest device contents.');
    }
    return captureTarget(null, source.target_id, source.expected_url, {
      connection: cdp,
      includeStorage: options.includeStorage !== false,
      selectedCookieKeys: options.selectedCookieKeys,
    });
  }

  async function importState({ state } = {}) {
    return importIntoNormalBrowser(cdp, state);
  }

  return { inventory, export: exportState, import: importState };
}
