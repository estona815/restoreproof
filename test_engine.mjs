import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
import {File} from 'node:buffer';
import {sha256, scanFiles, validateManifest, compare, demoFiles, SCHEMA, MAX_FILE} from './web/engine.mjs';
globalThis.crypto ??= webcrypto;
globalThis.File ??= File;
const results = [];
async function test(name, fn) {await fn();results.push({name,status:'PASS'});}
await test('SHA-256 known answer',async()=>assert.equal(await sha256(new TextEncoder().encode('abc')),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'));
await test('Same-size corruption, missing, extra',async()=>{const d=demoFiles();const a=await scanFiles(d.original), b=await scanFiles(d.restored);const r=compare(a.files,b.files,b.errors);assert.equal(r.status,'attention');assert.deepEqual(Object.fromEntries(r.files.map(x=>[x.path,x.status])),{'brief.txt':'matched','extra.txt':'unexpected','mix.wav':'changed','release-notes.txt':'missing'});assert.equal(r.files.find(x=>x.path==='mix.wav').expected.bytes,r.files.find(x=>x.path==='mix.wav').observed.bytes);});
await test('Repaired fixture passes',async()=>{const d=demoFiles(true);const a=await scanFiles(d.original), b=await scanFiles(d.restored);assert.equal(compare(a.files,b.files,b.errors).status,'verified');});
await test('Read error cannot produce pass',async()=>{const d=demoFiles(true);const a=await scanFiles(d.original);const b=await scanFiles([...d.restored,{name:'unreadable',size:1,arrayBuffer:async()=>{throw Error('Synthetic read failure');}}]);assert.equal(b.errors.length,1);assert.equal(compare(a.files,b.files,b.errors).status,'attention');});
await test('Oversize file not read',async()=>{let read=false;const r=await scanFiles([{name:'big.wav',size:MAX_FILE+1,arrayBuffer:async()=>{read=true;}}]);assert.equal(read,false);assert.equal(r.errors.length,1);});
await test('Hidden file never read',async()=>{let read=false;const r=await scanFiles([{name:'.env',size:1,arrayBuffer:async()=>{read=true;}}]);assert.equal(read,false);assert.equal(r.errors.length,1);});
await test('Normalized duplicate and unsafe manifests rejected',async()=>{const f={path:'one.txt',bytes:1,sha256:'a'.repeat(64)};for(const files of [[],[f,f],[{...f,path:'../outside'}],[{...f,path:'/absolute'}],[{...f,bytes:-1}],[{...f,sha256:'not a hash'}]])assert.throws(()=>validateManifest({schema:SCHEMA,files}));});
await test('XSS filenames remain data',async()=>{const a=await scanFiles([new File(['hello'],'<img onerror=alert(1)>.txt')]);assert.equal(a.files.length,1);assert.equal(a.files[0].path,'<img onerror=alert(1)>.txt');});
if(process.argv[2]) await test('Python/browser manifest interoperability',async()=>{const golden=JSON.parse(readFileSync(process.argv[2],'utf8'));const expected=validateManifest(golden.manifest);const observed=await scanFiles(golden.restored.map(x=>new File([x.content],x.path)));const report=compare(expected,observed.files,observed.errors);assert.equal(report.status,golden.report.status);assert.deepEqual(report.files,golden.report.files);});
await test('JSON manifest digest types are rejected without coercion',async()=>{
  const file={path:'safe.txt',bytes:3,sha256:'a'.repeat(64)};
  for(const sha256 of [[file.sha256],[[file.sha256]],null,{},true,123]) {
    const manifest=JSON.parse(JSON.stringify({schema:SCHEMA,files:[{...file,sha256}]}));
    assert.throws(()=>validateManifest(manifest),/invalid file evidence/);
  }
  assert.equal(validateManifest({schema:SCHEMA,files:[file]})[0].sha256,file.sha256);
});
console.log(JSON.stringify({suite:'browser_engine',passed:results.length,results},null,2));
