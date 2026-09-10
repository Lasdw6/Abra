import { filterState } from './util.js';

export function userOwnedDestination(destination) {
  return destination?.type === 'normal';
}

export function applyTransferPolicy(state, destination, policy = {}) {
  const filtered = filterState(state, policy.allows || [], policy.denies || []);
  if (userOwnedDestination(destination)) return { ...filtered, cookies: [], origins: [] };
  return filtered;
}

export function resolveNamedDestination(destination, { userBrowser = false } = {}) {
  const fallback = userBrowser ? { type: 'normal' } : { type: 'managed' };
  if (destination === undefined || destination === null || destination === '') return fallback;
  const type = typeof destination === 'string' ? destination : destination.type;
  if (type === 'local') return fallback;
  if (type === 'normal') return { type: 'normal' };
  if (type === 'managed') return { type: 'managed' };
  return null;
}
