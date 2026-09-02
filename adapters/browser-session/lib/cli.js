import { chmod, copyFile, realpath, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import { capture, install, launchLocalChrome, revoke, withLocalChrome } from './browser.js';
import { dataDir, loadBundle, loadManifest, parseList, readJson, RECEIPT_KIND, saveBundle, signObject, signingIdentity, verifyObject, writeJson } from './util.js';

const execFileAsync = promisify(execFile);
export function parseArgs(argv) { const positionals=[],flags={}; for(let i=0;i<argv.length;i++){const arg=argv[i];if(!arg.startsWith('--'))positionals.push(arg);else{const key=arg.slice(2);flags[key]=i+1<argv.length&&!argv[i+1].startsWith('--')?argv[++i]:true;}} return {positionals,flags}; }
function need(flags,name){if(!flags[name]||flags[name]===true)throw new Error(`--${name} is required`);return flags[name];}
export function summary(m){const lines=[`${m.kind} captured ${m.capture_time}`,`Signer: ${m.signature.fingerprint}`,`Source: ${m.source_browser}`,`Size: ${m.total_size} bytes`,'Domains:'];for(const d of m.domains)lines.push(`  ${d.domain}: ${d.cookie_count} cookies (${d.http_only_count} HttpOnly, ${d.secure_count} Secure)`);lines.push('Tabs:');for(const t of m.tabs)lines.push(`  ${t.title||'(untitled)'} — ${t.url}`);lines.push('Non-teleportable (heuristic; false positives/negatives possible):');if(!m.non_teleportable.length)lines.push('  none detected');for(const x of m.non_teleportable)lines.push(`  ${x.domain}: ${x.reasons.join('; ')}`);return lines.join('\n');}

async function trustedBundle(dir, flags) {
  const result = await loadBundle(dir);
  const identity = await signingIdentity();
  const requested = flags['trust-sender'];
  if (result.manifest.signature.fingerprint !== identity.fingerprint && requested !== result.manifest.signature.fingerprint) throw new Error(`untrusted sender ${result.manifest.signature.fingerprint}; rerun with --trust-sender ${result.manifest.signature.fingerprint} after verifying it out of band`);
  return result;
}
function registryFile(id){return path.join(dataDir(),'installs',`${id}.json`);}
function receiptFile(id){return path.join(dataDir(),'receipts',`${id}.json`);}
async function persistInstall(id, record){await writeJson(registryFile(id),record);}
async function safeContainedDelete(candidate, root) {
  const resolvedRoot=await realpath(root), resolved=await realpath(candidate);
  if(resolved===resolvedRoot||!resolved.startsWith(`${resolvedRoot}${path.sep}`))throw new Error('refusing to remove path outside the browser-session data directory');
  await rm(resolved,{recursive:true,force:true});
}
async function processIdentity(pid){const {stdout}=await execFileAsync('/bin/ps',['-p',String(pid),'-o','lstart=','-o','command=']);const line=stdout.trim();const match=line.match(/^(\S+\s+\S+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+([\s\S]+)$/);if(!match)throw new Error('cannot verify registered Chrome process identity');return{started_at:match[1],command:match[2]};}
async function stopRegisteredChrome(record) {
  if(!Number.isSafeInteger(record.pid)||record.pid<=0||!record.profile_dir)return;
  try { const current=await processIdentity(record.pid);if(current.started_at!==record.started_at||current.command!==record.command||!current.command.includes(`--user-data-dir=${record.profile_dir}`))throw new Error('registered Chrome process identity no longer matches');process.kill(record.pid,'SIGTERM'); } catch(error) { if(error.code!=='ESRCH')throw error; }
}

export async function run(argv,io=console){
  const {positionals,flags}=parseArgs(argv), command=positionals[0];
  if(command==='export'){
    const from=need(flags,'from'),out=path.resolve(flags.out||`browser-session-${Date.now()}`),policy={includes:parseList(flags['include-domains']),excludes:parseList(flags['exclude-domains'])};
    const state=from==='cdp'?await capture(positionals[1]||need(flags,'cdp'),policy,{browserContextId:flags['browser-context-id']}):from==='local'?await withLocalChrome(flags.profile,ws=>capture(ws,policy)):(()=>{throw new Error('--from must be local or cdp');})();
    const manifest=await saveBundle(out,state,{source:from,sourceBrowser:'Google Chrome via CDP',policy:{include_domains:policy.includes,exclude_domains:policy.excludes}});io.log(out);return{out,manifest};
  }
  if(command==='inspect'){const dir=path.resolve(positionals[1]||'.'),manifest=await loadManifest(dir);io.log(summary(manifest));return manifest;}
  if(command==='import'){
    const dir=path.resolve(positionals[1]||'.'),to=need(flags,'to'),{state,manifest}=await trustedBundle(dir,flags),policy={allows:parseList(flags['allow-domains']),denies:parseList(flags['deny-domains'])},installId=randomUUID();let local,wsUrl;
    if(to==='cdp')wsUrl=positionals[2]||need(flags,'cdp');
    else if(to==='local'){
      if(!flags.detach)throw new Error('--to local requires explicit --detach because Chrome remains running until revoke');
      const profileDir=path.join(dataDir(),'profiles',installId);local=await launchLocalChrome(undefined,{fresh:true,root:profileDir});wsUrl=local.wsUrl;
    } else throw new Error('--to must be local or cdp');
    try {
      const receipt=await install(wsUrl,state,policy,{watchMs:Number(flags['watch-ms']||0)});receipt.install_id=installId;receipt.source_bundle_sha256=manifest.state_sha256;receipt.reexportable=false;
      const localIdentity=local?await processIdentity(local.child.pid):null;
      await persistInstall(installId,{cdp_url:wsUrl,browser_context_id:receipt.browser_context_id,origins:receipt.origins,...(local?{pid:local.child.pid,profile_dir:local.tempRoot,...localIdentity}: {})});
      const identity=await signingIdentity();receipt.signature=signObject(receipt,identity,'browser-session-install-receipt');const output=flags.receipt?path.resolve(flags.receipt):receiptFile(installId);await writeJson(output,receipt);if(local)local.child.unref();io.log(output);return receipt;
    }catch(error){local?.child.kill('SIGTERM');if(local)await safeContainedDelete(local.tempRoot,path.join(dataDir(),'profiles')).catch(()=>{});throw error;}
  }
  if(command==='revoke'){
    const file=path.resolve(positionals[1]||''),receipt=await readJson(file),identity=await signingIdentity();
    if(receipt.kind!==RECEIPT_KIND||!verifyObject(receipt,{domain:'browser-session-install-receipt',publicKey:identity.publicDer,fingerprint:identity.fingerprint}))throw new Error('receipt is not signed by this browser-session installation');
    const record=await readJson(registryFile(receipt.install_id));if(record.browser_context_id!==receipt.browser_context_id)throw new Error('receipt does not match the private install registry');
    const result=await revoke(record.cdp_url,record.browser_context_id,record.origins);await stopRegisteredChrome(record);if(record.profile_dir)await safeContainedDelete(record.profile_dir,path.join(dataDir(),'profiles'));await rm(registryFile(receipt.install_id),{force:true});const output=`${file}.revoked.json`;await writeJson(output,result);io.log(output);return result;
  }
  if(command==='storage-state')return storageState(positionals.slice(1),flags,io);
  throw new Error('usage: abra-browser export|inspect|import|revoke|storage-state');
}
async function storageState(positionals,flags,io){const verb=positionals[0];if(verb==='import'){const input=path.resolve(positionals[1]||need(flags,'in')),out=path.resolve(flags.out||`browser-session-${Date.now()}`),raw=await import('node:fs/promises').then(fs=>fs.readFile(input)),storage=JSON.parse(raw),state={cookies:storage.cookies||[],origins:(storage.origins||[]).map(o=>({...o,sessionStorage:[],indexedDB:{databases:[]}})),tabs:[]};await saveBundle(out,state,{source:'playwright-storage-state',sourceBrowser:'Playwright storage_state',storageStateRaw:raw,provenance:{capture:'storage_state-import',reexportable:true}});io.log(out);return{out};}if(verb==='export'){const input=path.resolve(positionals[1]||need(flags,'in')),out=path.resolve(flags.out||'storage_state.json'),{manifest}=await trustedBundle(input,flags);if(manifest.provenance?.reexportable===false)throw new Error('received bundles are not re-exportable');await copyFile(path.join(input,'storage_state.json'),out);await chmod(out,0o600);io.log(out);return{out};}throw new Error('usage: abra-browser storage-state import <file> --out <bundle> | export <bundle> --out <file>');}
