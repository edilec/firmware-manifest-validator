import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {validateFirmware,TOOL_ID,LIMITS} from '../src/index.mjs';
const binary=Buffer.from('synthetic-firmware\n');
const digest=createHash('sha256').update(binary).digest('hex');
const policy=()=>({schemaVersion:'1',targetHardware:'board-a',currentVersion:'1.2.3',bootloaderVersion:'2.0.0',maxBytes:1024,fileVerification:'required'});
const manifest=()=>({schemaVersion:'1',complete:true,targetHardware:'board-a',version:'1.3.0',sizeBytes:binary.length,digestSha256:digest,compatibleFrom:['1.2.3'],minBootloaderVersion:'1.0.0',rollback:{supported:true,version:'1.2.3'},file:'firmware.bin'});
test('complete manifest and matching local artifact pass without flashing',()=>{
  const r=validateFirmware(policy(),manifest(),binary,{now:()=>0});assert.equal(TOOL_ID,'firmware-manifest-validator');assert.equal(r.status,'pass');assert.equal(r.digestVerification,'verified');assert.equal(r.summary.checked,1);assert.deepEqual(r.findings,[]);
});
test('wrong target, wrong digest and wrong size fail without echoing values',()=>{
  const m=manifest();m.targetHardware='private-other-board';let r=validateFirmware(policy(),m,binary,{now:()=>0});assert.equal(r.status,'fail');assert.equal(r.findings[0].ruleId,'target-mismatch');assert.doesNotMatch(JSON.stringify(r),/private-other-board/);
  m.targetHardware='board-a';m.digestSha256='0'.repeat(64);r=validateFirmware(policy(),m,binary,{now:()=>0});assert.equal(r.status,'fail');assert.ok(r.findings.some(x=>x.ruleId==='digest-mismatch'));
  m.digestSha256=digest;m.sizeBytes++;r=validateFirmware(policy(),m,binary,{now:()=>0});assert.equal(r.status,'fail');assert.ok(r.findings.some(x=>x.ruleId==='size-mismatch'));
});
test('missing rollback evidence is incomplete; explicit unavailable rollback fails',()=>{
  const m=manifest();delete m.rollback;let r=validateFirmware(policy(),m,binary,{now:()=>0});assert.equal(r.status,'incomplete');assert.ok(r.findings.some(x=>x.ruleId==='rollback-unknown'));m.rollback={supported:false,version:'1.2.3'};r=validateFirmware(policy(),m,binary,{now:()=>0});assert.equal(r.status,'fail');
});
test('explicit unsupported rollback needs no version, but supported rollback does',()=>{
  const m=manifest();m.rollback={supported:false};let r=validateFirmware(policy(),m,binary,{now:()=>0});assert.equal(r.status,'fail');assert.ok(r.findings.some(x=>x.ruleId==='rollback-unavailable'));
  m.rollback={supported:true};r=validateFirmware(policy(),m,binary,{now:()=>0});assert.equal(r.status,'incomplete');
});
test('compatibility and semantic version precedence are checked',()=>{
  const m=manifest();m.compatibleFrom=['1.0.0'];assert.equal(validateFirmware(policy(),m,binary,{now:()=>0}).findings[0].ruleId,'base-incompatible');m.compatibleFrom=['1.2.3'];m.version='1.2.3';assert.equal(validateFirmware(policy(),m,binary,{now:()=>0}).findings[0].ruleId,'version-not-newer');m.version='1.3.0-rc.1';assert.equal(validateFirmware(policy(),m,binary,{now:()=>0}).status,'pass');
});
test('optional file omission is explicitly unverified, required omission is incomplete',()=>{
  const m=manifest();delete m.file;const p=policy();p.fileVerification='optional';let r=validateFirmware(p,m,null,{now:()=>0});assert.equal(r.status,'pass');assert.equal(r.digestVerification,'not-supplied');p.fileVerification='required';r=validateFirmware(p,m,null,{now:()=>0});assert.equal(r.status,'incomplete');
});
test('partial and unknown semantic manifest evidence cannot pass',()=>{
  const m=manifest();m.complete=false;assert.equal(validateFirmware(policy(),m,binary,{now:()=>0}).status,'incomplete');m.complete=true;m.signingKey='private';const r=validateFirmware(policy(),m,binary,{now:()=>0});assert.equal(r.status,'incomplete');assert.doesNotMatch(JSON.stringify(r),/private/);
});
test('compatibility count, depth, artifact bytes, and deadline N/N+1',()=>{
  const m=manifest(),p=policy();m.compatibleFrom=Array.from({length:LIMITS.compatibleFrom},(_,i)=>`1.2.${i}`);assert.equal(validateFirmware(p,m,binary,{now:()=>0}).status,'pass');m.compatibleFrom.push('2.0.0');assert.equal(validateFirmware(p,m,binary,{now:()=>0}).findings[0].ruleId,'record-limit');
  const q=manifest();q.metadata={};let x=q.metadata;for(let i=1;i<LIMITS.depth;i++){x.next={};x=x.next;}assert.equal(validateFirmware(p,q,binary,{now:()=>0}).status,'pass');x.next={};assert.equal(validateFirmware(p,q,binary,{now:()=>0}).findings[0].ruleId,'depth-limit');
  const cap=Buffer.alloc(LIMITS.firmwareBytes,1),s=manifest();s.sizeBytes=cap.length;s.digestSha256=createHash('sha256').update(cap).digest('hex');p.maxBytes=LIMITS.firmwareBytes;assert.equal(validateFirmware(p,s,cap,{now:()=>0}).status,'pass');assert.equal(validateFirmware(p,s,Buffer.alloc(LIMITS.firmwareBytes+1,1),{now:()=>0}).findings[0].ruleId,'byte-limit');
  const clock=n=>{let first=true;return()=>{if(first){first=false;return 0;}return n;};};assert.equal(validateFirmware(policy(),manifest(),binary,{now:clock(5000)}).status,'pass');assert.equal(validateFirmware(policy(),manifest(),binary,{now:clock(5001)}).findings[0].ruleId,'time-limit');
});
test('policy depth and max artifact size N/N+1',()=>{
  const p=policy();p.maxBytes=LIMITS.firmwareBytes;assert.equal(validateFirmware(p,manifest(),binary,{now:()=>0}).status,'pass');p.maxBytes++;assert.equal(validateFirmware(p,manifest(),binary,{now:()=>0}).findings[0].ruleId,'input-invalid');
  const q=policy();q.metadata={};let x=q.metadata;for(let i=1;i<LIMITS.depth;i++){x.next={};x=x.next;}assert.equal(validateFirmware(q,manifest(),binary,{now:()=>0}).status,'pass');x.next={};assert.equal(validateFirmware(q,manifest(),binary,{now:()=>0}).findings[0].ruleId,'depth-limit');
});
const cli=args=>spawnSync(process.execPath,['bin/firmware-manifest-validator.mjs',...args],{cwd:path.resolve(import.meta.dirname,'..'),encoding:'utf8'});
const fixture=run=>{const root=fs.mkdtempSync(path.join(os.tmpdir(),'firmware-'));try{return run(root);}finally{fs.rmSync(root,{recursive:true,force:true});}};
test('CLI verifies local file, rejects duplicate keys/invalid UTF-8/symlink escape',()=>fixture(root=>{
  fs.writeFileSync(path.join(root,'policy.json'),JSON.stringify(policy()));fs.writeFileSync(path.join(root,'manifest.json'),JSON.stringify(manifest()));fs.writeFileSync(path.join(root,'firmware.bin'),binary);let r=cli(['--root',root,'--policy','policy.json','--manifest','manifest.json']);assert.equal(r.status,0);assert.equal(JSON.parse(r.stdout).digestVerification,'verified');
  fs.writeFileSync(path.join(root,'manifest.json'),'{"schemaVersion":"1","complete":false,"compl\\u0065te":true}');r=cli(['--root',root,'--policy','policy.json','--manifest','manifest.json']);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).status,'incomplete');
  fs.writeFileSync(path.join(root,'policy.json'),'{"schemaVersion":"1","maxBytes":1,"maxBytes":2}');r=cli(['--root',root,'--policy','policy.json','--manifest','manifest.json']);assert.equal(r.status,2);assert.equal(r.stdout,'');fs.writeFileSync(path.join(root,'policy.json'),JSON.stringify(policy()));
  fs.writeFileSync(path.join(root,'manifest.json'),Buffer.from([0xff]));r=cli(['--root',root,'--policy','policy.json','--manifest','manifest.json']);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).status,'incomplete');
  fs.writeFileSync(path.join(root,'manifest.json'),JSON.stringify(manifest()));const out=fs.mkdtempSync(path.join(os.tmpdir(),'firmware-out-'));try{fs.writeFileSync(path.join(out,'outside.bin'),binary);fs.rmSync(path.join(root,'firmware.bin'));fs.symlinkSync(path.join(out,'outside.bin'),path.join(root,'firmware.bin'));r=cli(['--root',root,'--policy','policy.json','--manifest','manifest.json']);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).status,'incomplete');}finally{fs.rmSync(out,{recursive:true,force:true});}
}));
test('CLI JSON byte bounds accept N and reject N+1; invalid root is empty',()=>fixture(root=>{
  fs.writeFileSync(path.join(root,'policy.json'),JSON.stringify(policy()));fs.writeFileSync(path.join(root,'manifest.json'),JSON.stringify(manifest()));fs.writeFileSync(path.join(root,'firmware.bin'),binary);
  for(const [name,limit,value] of [['policy.json',LIMITS.policyBytes,policy()],['manifest.json',LIMITS.manifestBytes,manifest()]]){
    const raw=JSON.stringify(value);fs.writeFileSync(path.join(root,name),raw+' '.repeat(limit-Buffer.byteLength(raw)));
    let r=cli(['--root',root,'--policy','policy.json','--manifest','manifest.json']);assert.equal(r.status,0,name);
    fs.appendFileSync(path.join(root,name),' ');r=cli(['--root',root,'--policy','policy.json','--manifest','manifest.json']);assert.equal(r.status,2);assert.equal(name==='policy.json'?r.stdout:JSON.parse(r.stdout).findings[0].ruleId,name==='policy.json'?'':'byte-limit');fs.writeFileSync(path.join(root,name),raw);
  }
  const r=cli(['--root',path.join(root,'missing'),'--policy','policy.json','--manifest','manifest.json']);assert.equal(r.status,2);assert.equal(r.stdout,'');
}));
