const te = new TextEncoder();
const td = new TextDecoder();
const b64 = s => Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(s.length/4)*4,"=")), c=>c.charCodeAt(0));
const hex = b => [...b].map(x=>x.toString(16).padStart(2,"0")).join("");
const u64 = (b,o) => Number(new DataView(b.buffer,b.byteOffset,b.byteLength).getBigUint64(o));

export function parseCapabilityUrl(href) {
  const url = new URL(href);
  const fragment = url.hash.slice(1);
  const params = new URLSearchParams(fragment);
  if (params.has("u") && params.has("k")) return {url:td.decode(b64(params.get("u"))),key:b64(params.get("k"))};
  if (!fragment) throw new Error("This link has no bearer key.");
  url.hash="";
  return {url:url.href,key:b64(fragment)};
}

export async function decryptCapability(blob, key, now=Date.now()) {
  const b = blob instanceof Uint8Array ? blob : new Uint8Array(blob);
  const magic=td.decode(b.slice(0,8));
  if(magic==="ABRACAPX") throw new Error("This link was revoked.");
  if(magic!=="ABRACAP1"||b[8]!==2||b.length<37) throw new Error("Invalid capability blob.");
  const expires=u64(b,21), length=u64(b,29);
  if(now>expires) throw new Error("This link expired.");
  if(b.length!==37+length) throw new Error("Damaged capability blob.");
  const cryptoKey=await crypto.subtle.importKey("raw",key,{name:"AES-GCM"},false,["decrypt"]);
  let clear;
  try { clear=await crypto.subtle.decrypt({name:"AES-GCM",iv:b.slice(9,21),additionalData:b.slice(0,29),tagLength:128},cryptoKey,b.slice(37)); }
  catch { throw new Error("Wrong key or damaged capability blob."); }
  return {pack:JSON.parse(td.decode(clear)),expires};
}

function canonical(value){
  if(value===null||typeof value==="boolean")return JSON.stringify(value);
  if(typeof value==="number"){if(!Number.isSafeInteger(value))throw new Error("non-canonical number");return String(value)}
  if(typeof value==="string")return JSON.stringify(value).replace(/\\u([0-9a-fA-F]{4})/g,(_,h)=>{const n=parseInt(h,16);return n>=32?String.fromCharCode(n):`\\u${h.toLowerCase()}`})
  if(Array.isArray(value))return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(k=>`${canonical(k)}:${canonical(value[k])}`).join(",")}}`;
}

export async function verifyManifest(raw) {
  const manifest=JSON.parse(td.decode(raw));
  const signature=b64hex(manifest.signature), publicKey=b64hex(manifest.origin.peer_id);
  delete manifest.signature;
  const payload=te.encode(canonical(manifest));
  const prefix=te.encode("abra-sig-v1\0snapshot\0");
  const message=new Uint8Array(prefix.length+payload.length);message.set(prefix);message.set(payload,prefix.length);
  try {
    const key=await crypto.subtle.importKey("raw",publicKey,{name:"Ed25519"},false,["verify"]);
    return {manifest:{...manifest,signature:hex(signature)},verified:await crypto.subtle.verify("Ed25519",key,signature,message)};
  } catch { return {manifest:{...manifest,signature:hex(signature)},verified:null}; }
}
function b64hex(s){if(!/^[0-9a-f]+$/i.test(s)||s.length%2)throw new Error("invalid hex");return Uint8Array.from(s.match(/../g),x=>parseInt(x,16))}
function esc(s){const e=document.createElement("span");e.textContent=String(s);return e.innerHTML}
function objectMap(pack){return new Map(pack.blobs.map(x=>[x.digest,b64(x.data)]))}
function treeEntries(bytes){
  const magic=td.decode(bytes.slice(0,13));if(magic!=="abra.tree.v1\n")throw new Error("invalid tree");
  const out=[];let p=13;while(p<bytes.length){let sp=bytes.indexOf(32,p),nul=bytes.indexOf(0,sp+1);const mode=td.decode(bytes.slice(p,sp)),name=td.decode(bytes.slice(sp+1,nul));const digest=hex(bytes.slice(nul+1,nul+33));out.push({mode,name,digest});p=nul+41}return out;
}
function files(pack,manifest){
  if(!manifest.files)return [];
  const objects=objectMap(pack),out=[];
  function walk(id,prefix){const bytes=objects.get(id);if(!bytes)return;for(const e of treeEntries(bytes)){const path=prefix?`${prefix}/${e.name}`:e.name;if(e.mode==="tree")walk(e.digest,path);else out.push({...e,path,data:objects.get(e.digest)})}}
  walk(manifest.files,"");return out;
}
function download(name,data){const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([data]));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}

async function main(){
  const app=document.querySelector("#app");
  try{
    const target=parseCapabilityUrl(location.href),response=await fetch(target.url,{mode:"cors"});
    if(!response.ok)throw new Error(response.status===404||response.status===410?"This link was revoked or removed.":`Fetch failed (${response.status}).`);
    const {pack,expires}=await decryptCapability(await response.arrayBuffer(),target.key);
    const {manifest:m,verified}=await verifyManifest(b64(pack.manifest_raw));
    const badge=verified===true?"signature verified":verified===false?"invalid signature":"signature unverified (browser lacks Ed25519)";
    const thumb=m.thumbnail&&objectMap(pack).get(m.thumbnail.blob);const rows=files(pack,m);
    app.innerHTML=`<span class="badge">${esc(badge)}</span><h1>${esc(m.title)}</h1><p class="meta">${esc(m.kind)} · ${esc(m.origin.name||m.origin.peer_id.slice(0,8))} · ${esc(new Date(m.created_at).toLocaleString())}</p>${m.summary?`<p>${esc(m.summary)}</p>`:""}${m.link?`<p><a rel="noopener noreferrer" href="${esc(m.link)}">Open link</a></p>`:""}${thumb?`<img alt="Thumbnail">`:""}<p class="meta">Expires ${esc(new Date(expires).toLocaleString())} · ${rows.length?"full bundle":"floor-only bundle"}</p><h2>Files</h2><ul>${rows.map((f,i)=>`<li>${esc(f.path)} ${f.data?`<button data-file="${i}">Download</button>`:"(not included)"}</li>`).join("")||"<li>No files included</li>"}</ul>${m.recipes?`<h2>Recipes (not executed)</h2><pre>${esc(JSON.stringify(m.recipes,null,2))}</pre>`:""}`;
    if(thumb)app.querySelector("img").src=URL.createObjectURL(new Blob([thumb],{type:m.thumbnail.media_type}));
    app.querySelectorAll("[data-file]").forEach(button=>button.onclick=()=>{const f=rows[Number(button.dataset.file)];download(f.name,f.data)});
  }catch(error){app.innerHTML=`<h1>Unable to open link</h1><p>${esc(error.message)}</p>`}
}
if(typeof document!=="undefined")main();
