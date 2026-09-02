import test from "node:test";
import assert from "node:assert/strict";
import { activeContent, decryptCapability, files, parseCapabilityUrl, safeLink, treeEntries } from "./viewer.js";

test("decrypts the Rust ABRACAP1 AES-GCM wire shape", async () => {
  const key = Uint8Array.from({length:32}, (_,i)=>i);
  const nonce = Uint8Array.from({length:12}, (_,i)=>20+i);
  const expires = 4_102_444_800_000n;
  const pack = {spec:"abra/0.1",type:"capability-pack",snapshot_id:"00".repeat(32),manifest_raw:"e30",blobs:[]};
  const aad = new Uint8Array(29);
  aad.set(new TextEncoder().encode("ABRACAP1")); aad[8]=2; aad.set(nonce,9);
  new DataView(aad.buffer).setBigUint64(21,expires);
  const aes = await crypto.subtle.importKey("raw",key,{name:"AES-GCM"},false,["encrypt"]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:nonce,additionalData:aad},aes,new TextEncoder().encode(JSON.stringify(pack))));
  const blob = new Uint8Array(37+ciphertext.length); blob.set(aad); new DataView(blob.buffer).setBigUint64(29,BigInt(ciphertext.length)); blob.set(ciphertext,37);
  assert.deepEqual((await decryptCapability(blob,key,0)).pack,pack);
  await assert.rejects(decryptCapability(blob,new Uint8Array(32).fill(9),0),/Wrong key/);
  await assert.rejects(decryptCapability(blob,key,Number(expires)+1),/expired/);
});

test("rejects executable link schemes and disables all active content when unverified", () => {
  assert.equal(safeLink("javascript:alert(1)"), null);
  assert.equal(safeLink("data:text/html,pwned"), null);
  assert.equal(safeLink("https://example.com/a"), "https://example.com/a");
  assert.deepEqual(activeContent(null, {link:"https://example.com"}, [{data:new Uint8Array([1])}]), {link:null, downloads:[]});
  assert.deepEqual(activeContent(false, {link:"https://example.com"}, [{data:new Uint8Array([1])}]), {link:null, downloads:[]});
});

test("malformed and cyclic trees are rejected without an unbounded walk", () => {
  assert.throws(() => treeEntries(new TextEncoder().encode("abra.tree.v1\n" + "x".repeat(80))), /Malformed/);
  const digest = "11".repeat(32);
  const head = new TextEncoder().encode("abra.tree.v1\ntree loop\0");
  const tree = new Uint8Array(head.length + 40); tree.set(head); tree.set(Buffer.from(digest, "hex"), head.length); // size stays zero
  const pack = {blobs:[{digest,data:Buffer.from(tree).toString("base64url")}]};
  assert.throws(() => files(pack, {files:digest}), /cycle/i);
});

test("viewer fragment keeps both ciphertext URL and key out of the request", () => {
  const u = Buffer.from("https://objects.example/s/cipher").toString("base64url");
  const k = Buffer.from(new Uint8Array(32).fill(7)).toString("base64url");
  const parsed = parseCapabilityUrl(`https://viewer.example/#v=1&u=${u}&k=${k}`);
  assert.equal(parsed.url,"https://objects.example/s/cipher");
  assert.deepEqual(parsed.key,new Uint8Array(32).fill(7));
});
