#!/usr/bin/env node
import { createServer } from 'node:http';
import { chmod, cp, mkdir, realpath, readdir, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { parseArgs } from '../lib/cli.js';
import { readJson, writeJson } from '../lib/util.js';

export function createFacade({ root, userId = 'local', secret, stagingRoot = path.join(root, 'staging') }) {
  if (!secret) throw new Error('facade shared secret is required');
  const profilesDir = path.join(root, 'profiles');
  const bundlesDir = path.join(root, 'bundles');
  const initialize = Promise.all([mkdir(profilesDir, { recursive: true, mode: 0o700 }), mkdir(bundlesDir, { recursive: true, mode: 0o700 }), mkdir(stagingRoot, { recursive: true, mode: 0o700 })]);
  const file = id => path.join(profilesDir, `${id}.json`);
  async function list() { await initialize; return Promise.all((await readdir(profilesDir)).filter(x => x.endsWith('.json')).map(x => readJson(path.join(profilesDir, x)))); }
  async function handler(req, res) {
    try {
      if (req.headers.authorization !== `Bearer ${secret}`) return json(res, 401, { error: 'unauthorized' });
      if (req.headers.origin && req.headers.origin !== `http://${req.headers.host}`) return json(res, 403, { error: 'forbidden' });
      const url = new URL(req.url, 'http://localhost');
      const match = url.pathname.match(/^\/api\/v4\/profiles(?:\/([^/]+))?$/);
      if (!match) return json(res, 404, { error: 'not found' });
      const id = match[1];
      if (req.method === 'GET' && !id) return json(res, 200, await list());
      if (req.method === 'POST' && !id) {
        const body = await bodyJson(req), now = new Date().toISOString(), profileId = body.id || randomUUID();
        const profile = publicProfile({ id: profileId, userId, name: body.name || 'Browser profile', createdAt: now, updatedAt: now, lastUsedAt: null, cookieDomains: body.cookieDomains || domainsFromCookies(body.cookies) });
        await writeJson(file(profileId), profile);
        if (body.bundlePath) await storeBundle(body.bundlePath, path.join(bundlesDir, profileId), stagingRoot);
        return json(res, 201, profile);
      }
      let profile; try { profile = await readJson(file(id)); } catch { return json(res, 404, { error: 'profile not found' }); }
      if (req.method === 'GET') return json(res, 200, publicProfile(profile));
      if (req.method === 'PATCH') {
        const body = await bodyJson(req), now = new Date().toISOString();
        // cookie values may arrive, but only their domains are retained in profile metadata.
        profile = publicProfile({ ...profile, ...(body.name !== undefined ? { name: body.name } : {}), updatedAt: now, lastUsedAt: body.lastUsedAt || now, cookieDomains: body.cookieDomains || (body.cookies ? domainsFromCookies(body.cookies) : profile.cookieDomains) });
        await writeJson(file(id), profile);
        if (body.bundlePath) await storeBundle(body.bundlePath, path.join(bundlesDir, id), stagingRoot);
        return json(res, 200, profile);
      }
      if (req.method === 'DELETE') { await rm(file(id)); await rm(path.join(bundlesDir, id), { recursive: true, force: true }); res.writeHead(204).end(); return; }
      return json(res, 405, { error: 'method not allowed' });
    } catch { return json(res, 400, { error: 'bad request' }); }
  }
  return createServer(handler);
}

function publicProfile(p) { return { id: p.id, userId: p.userId, name: p.name, lastUsedAt: p.lastUsedAt, createdAt: p.createdAt, updatedAt: p.updatedAt, cookieDomains: [...new Set(p.cookieDomains || [])].sort() }; }
function domainsFromCookies(cookies = []) { return [...new Set(cookies.map(c => String(c.domain || '').replace(/^\./, '')).filter(Boolean))]; }
async function secureTree(target){const info=await stat(target);if(info.isDirectory()){await chmod(target,0o700);for(const name of await readdir(target))await secureTree(path.join(target,name));}else await chmod(target,0o600);}
async function storeBundle(source, destination, stagingRoot) { const root=await realpath(stagingRoot),resolved=await realpath(path.resolve(source));if(resolved===root||!resolved.startsWith(`${root}${path.sep}`))throw new Error('bundle is outside staging');await rm(destination,{recursive:true,force:true});await cp(resolved,destination,{recursive:true});await secureTree(destination); }
async function bodyJson(req) { const chunks = []; for await (const c of req) chunks.push(c); if (!chunks.length) return {}; return JSON.parse(Buffer.concat(chunks)); }
function json(res, status, value) { const body = JSON.stringify(value); res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }); res.end(body); }

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const { flags } = parseArgs(process.argv.slice(2));
  const host=flags.host||'127.0.0.1';if(host!=='127.0.0.1'&&host!=='localhost'&&!flags['allow-network'])throw new Error('non-loopback bind requires --allow-network');
  const server = createFacade({ root: path.resolve(flags.root || '.abra-browser-profiles'), userId: flags['user-id'] || 'local', secret: flags.secret || process.env.ABRA_BROWSER_FACADE_SECRET });
  server.listen(Number(flags.port || 8787),host,()=>console.error(`Browser Use profile façade listening on ${host}:${flags.port||8787}`));
}
