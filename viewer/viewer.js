const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });
const MAX_PACK_BYTES = 64 * 1024 * 1024;
const MAX_OBJECT_BYTES = 32 * 1024 * 1024;
const MAX_TREE_ENTRIES = 100_000;
const MAX_TREE_DEPTH = 512;
const MAX_PATH_BYTES = 4096;
const SAFE_LINK_SCHEMES = new Set(["http:", "https:"]);
const SAFE_THUMBNAILS = new Set(["image/png", "image/jpeg", "image/webp"]);
const b64 = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=")), c => c.charCodeAt(0));
const hex = b => [...b].map(x => x.toString(16).padStart(2, "0")).join("");
const u64 = (b, o) => Number(new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(o));

export function parseCapabilityUrl(href) {
  const url = new URL(href);
  const fragment = url.hash.slice(1);
  const params = new URLSearchParams(fragment);
  if (params.has("u") && params.has("k")) return { url: td.decode(b64(params.get("u"))), key: b64(params.get("k")) };
  if (!fragment) throw new Error("This link has no bearer key.");
  url.hash = "";
  return { url: url.href, key: b64(fragment) };
}

export function safeLink(value, extraSchemes = []) {
  if (typeof value !== "string") return null;
  try {
    const url = new URL(value);
    const allowed = new Set([...SAFE_LINK_SCHEMES, ...extraSchemes.map(x => x.endsWith(":") ? x : `${x}:`)]);
    return allowed.has(url.protocol.toLowerCase()) ? url.href : null;
  } catch { return null; }
}

export async function decryptCapability(blob, key, now = Date.now()) {
  const b = blob instanceof Uint8Array ? blob : new Uint8Array(blob);
  if (b.length > MAX_PACK_BYTES) throw new Error("Capability blob exceeds the viewer size limit.");
  const magic = td.decode(b.slice(0, 8));
  if (magic === "ABRACAPX") throw new Error("This link was revoked.");
  if (magic !== "ABRACAP1" || b[8] !== 2 || b.length < 37) throw new Error("Invalid capability blob.");
  const expires = u64(b, 21), length = u64(b, 29);
  if (!Number.isSafeInteger(length) || length > MAX_PACK_BYTES - 37) throw new Error("Capability ciphertext exceeds the viewer size limit.");
  if (now > expires) throw new Error("This link expired.");
  if (b.length !== 37 + length) throw new Error("Damaged capability blob.");
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"]);
  let clear;
  try { clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.slice(9, 21), additionalData: b.slice(0, 29), tagLength: 128 }, cryptoKey, b.slice(37)); }
  catch { throw new Error("Wrong key or damaged capability blob."); }
  if (clear.byteLength > MAX_PACK_BYTES) throw new Error("Capability pack exceeds the viewer size limit.");
  return { pack: JSON.parse(td.decode(clear)), expires };
}

function canonical(value) {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") { if (!Number.isSafeInteger(value)) throw new Error("non-canonical number"); return String(value); }
  if (typeof value === "string") return JSON.stringify(value).replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => { const n = parseInt(h, 16); return n >= 32 ? String.fromCharCode(n) : `\\u${h.toLowerCase()}`; });
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(k => `${canonical(k)}:${canonical(value[k])}`).join(",")}}`;
}

export async function verifyManifest(raw) {
  const manifest = JSON.parse(td.decode(raw));
  const signature = fromHex(manifest.signature), publicKey = fromHex(manifest.origin.peer_id);
  delete manifest.signature;
  const payload = te.encode(canonical(manifest));
  const prefix = te.encode("abra-sig-v1\0snapshot\0");
  const message = new Uint8Array(prefix.length + payload.length); message.set(prefix); message.set(payload, prefix.length);
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return { manifest: { ...manifest, signature: hex(signature) }, verified: await crypto.subtle.verify("Ed25519", key, signature, message) };
  } catch { return { manifest: { ...manifest, signature: hex(signature) }, verified: null }; }
}
function fromHex(s) { if (typeof s !== "string" || !/^[0-9a-f]+$/i.test(s) || s.length % 2) throw new Error("invalid hex"); return Uint8Array.from(s.match(/../g), x => parseInt(x, 16)); }

function objectMap(pack) {
  if (!Array.isArray(pack.blobs) || pack.blobs.length > MAX_TREE_ENTRIES) throw new Error("Too many pack objects.");
  const objects = new Map();
  for (const object of pack.blobs) {
    const data = b64(object.data);
    if (data.length > MAX_OBJECT_BYTES) throw new Error("Pack object exceeds the size limit.");
    if (objects.has(object.digest)) throw new Error("Duplicate pack object.");
    objects.set(object.digest, data);
  }
  return objects;
}

export function treeEntries(bytes) {
  if (td.decode(bytes.slice(0, 13)) !== "abra.tree.v1\n") throw new Error("Invalid tree magic.");
  const out = []; let p = 13; let previous = null;
  while (p < bytes.length) {
    if (out.length >= MAX_TREE_ENTRIES) throw new Error("Tree entry limit exceeded.");
    const sp = bytes.indexOf(32, p);
    const nul = sp < 0 ? -1 : bytes.indexOf(0, sp + 1);
    if (sp <= p || nul <= sp + 1 || nul + 41 > bytes.length) throw new Error("Malformed tree entry.");
    const mode = td.decode(bytes.slice(p, sp));
    if (!["file", "exec", "link", "tree"].includes(mode)) throw new Error("Invalid tree mode.");
    const nameBytes = bytes.slice(sp + 1, nul), name = td.decode(nameBytes);
    if (nameBytes.length > 255 || name === "." || name === ".." || name.includes("/") || name.includes("\0")) throw new Error("Invalid tree name.");
    if (previous !== null && previous.localeCompare(name) >= 0) throw new Error("Tree entries are not strictly sorted.");
    const size = u64(bytes, nul + 33);
    if (mode === "tree" && size !== 0) throw new Error("Tree entry has nonzero size.");
    out.push({ mode, name, digest: hex(bytes.slice(nul + 1, nul + 33)), size });
    previous = name;
    const next = nul + 41;
    if (next <= p) throw new Error("Malformed tree entry.");
    p = next;
  }
  return out;
}

export function files(pack, manifest) {
  if (!manifest.files) return [];
  const objects = objectMap(pack), out = [], active = new Set(); let visited = 0;
  function walk(id, prefix, depth) {
    if (depth > MAX_TREE_DEPTH) throw new Error("Tree depth limit exceeded.");
    if (active.has(id)) throw new Error("Tree cycle detected.");
    const bytes = objects.get(id); if (!bytes) throw new Error("Tree object is missing.");
    active.add(id);
    for (const entry of treeEntries(bytes)) {
      if (++visited > MAX_TREE_ENTRIES) throw new Error("Tree entry limit exceeded.");
      const path = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (te.encode(path).length > MAX_PATH_BYTES) throw new Error("Tree path limit exceeded.");
      if (entry.mode === "tree") walk(entry.digest, path, depth + 1);
      else out.push({ ...entry, path, data: objects.get(entry.digest) });
    }
    active.delete(id);
  }
  walk(manifest.files, "", 0); return out;
}

export function activeContent(verified, manifest, rows) {
  return verified === true ? { link: safeLink(manifest.link), downloads: rows.filter(row => row.data) } : { link: null, downloads: [] };
}

function add(parent, tag, text, className) { const node = document.createElement(tag); node.textContent = text; if (className) node.className = className; parent.append(node); return node; }
function download(name, data) { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([data])); a.download = /^[A-Za-z0-9._-]{1,255}$/.test(name) ? name : "abra-download"; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); }

async function main() {
  const app = document.querySelector("#app");
  try {
    const target = parseCapabilityUrl(location.href), response = await fetch(target.url, { mode: "cors" });
    if (!response.ok) throw new Error(response.status === 404 || response.status === 410 ? "This link was revoked or removed." : `Fetch failed (${response.status}).`);
    const { pack, expires } = await decryptCapability(await response.arrayBuffer(), target.key);
    const { manifest: m, verified } = await verifyManifest(b64(pack.manifest_raw));
    const badge = verified === true ? "Integrity verified (self-signed; sender identity untrusted)" : verified === false ? "Invalid signature — active content disabled" : "Unverified — active content disabled";
    const rows = files(pack, m), active = activeContent(verified, m, rows);
    app.replaceChildren();
    add(app, "span", badge, "badge"); add(app, "h1", m.title);
    add(app, "p", `${m.kind} · ${m.origin.name || m.origin.peer_id.slice(0, 8)} · ${new Date(m.created_at).toLocaleString()}`, "meta");
    if (m.summary) add(app, "p", m.summary);
    if (m.link) { const p = document.createElement("p"); if (active.link) { const a = add(p, "a", "Open link"); a.href = active.link; a.rel = "noopener noreferrer"; } else add(p, "span", `Link (inactive): ${m.link}`); app.append(p); }
    const objects = objectMap(pack), thumb = verified === true && m.thumbnail && SAFE_THUMBNAILS.has(m.thumbnail.media_type) && objects.get(m.thumbnail.blob);
    if (thumb) { const img = document.createElement("img"); img.alt = "Thumbnail"; img.src = URL.createObjectURL(new Blob([thumb], { type: m.thumbnail.media_type })); app.append(img); }
    add(app, "p", `Expires ${new Date(expires).toLocaleString()} · ${rows.length ? "full bundle" : "floor-only bundle"}`, "meta"); add(app, "h2", "Files");
    const ul = document.createElement("ul");
    if (!rows.length) add(ul, "li", "No files included");
    for (const row of rows) { const li = add(ul, "li", row.path); if (verified === true && row.data) { const button = add(li, "button", "Download"); button.onclick = () => download(row.name, row.data); } else li.append(document.createTextNode(row.data ? " (inactive)" : " (not included)")); }
    app.append(ul);
    if (m.recipes) { add(app, "h2", "Recipes (not executed)"); add(app, "pre", JSON.stringify(m.recipes, null, 2)); }
  } catch (error) { app.replaceChildren(); add(app, "h1", "Unable to open link"); add(app, "p", error.message); }
}
if (typeof document !== "undefined") main();
