#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {TextDecoder} from 'node:util';
import {validateFirmware,incomplete,LIMITS} from '../src/index.mjs';
function options(argv){const result={};if(argv.length!==6)return null;for(let i=0;i<argv.length;i+=2){const k=argv[i];if(!['--root','--policy','--manifest'].includes(k)||Object.hasOwn(result,k)||!argv[i+1])return null;result[k]=argv[i+1];}return Object.keys(result).length===3?result:null;}
function duplicateKeys(text){const stack=[];for(const match of text.matchAll(/"(?:\\.|[^"\\])*"|[{}\[\],:]/gs)){const token=match[0],top=stack.at(-1);if(token==='{'){stack.push({kind:'object',key:true,seen:new Set()});continue;}if(token==='['){stack.push({kind:'array'});continue;}if(token==='}'||token===']'){stack.pop();continue;}if(token===','){if(top?.kind==='object')top.key=true;continue;}if(token===':')continue;if(top?.kind==='object'&&top.key){const key=JSON.parse(token);if(top.seen.has(key))return true;top.seen.add(key);top.key=false;}}return false;}
function target(root,relative){if(path.isAbsolute(relative))return null;try{const resolved=fs.realpathSync(path.resolve(root,relative));return resolved!==root&&resolved.startsWith(root+path.sep)&&fs.statSync(resolved).isFile()?resolved:null;}catch{return null;}}
function readJson(root,relative,limit){const file=target(root,relative);if(!file)return {error:'input-unreadable'};let raw;try{raw=fs.readFileSync(file);}catch{return {error:'input-unreadable'};}if(raw.length>limit)return {error:'byte-limit'};try{const text=new TextDecoder('utf-8',{fatal:true}).decode(raw),value=JSON.parse(text);if(duplicateKeys(text))return {error:'input-invalid'};return {value};}catch{return {error:'input-invalid'};}}
export function main(argv,now=()=>performance.now()){
  const args=options(argv);if(!args){process.stderr.write('Usage: firmware-manifest-validator --root DIR --policy FILE --manifest FILE\n');return 2;}
  let root;try{root=fs.realpathSync(args['--root']);if(!fs.statSync(root).isDirectory())throw Error();}catch{process.stderr.write('Invalid root.\n');return 2;}
  const policy=readJson(root,args['--policy'],LIMITS.policyBytes);if(policy.error){process.stderr.write('Invalid policy.\n');return 2;}
  const manifest=readJson(root,args['--manifest'],LIMITS.manifestBytes);if(manifest.error){process.stdout.write(JSON.stringify(incomplete(manifest.error,'@manifest'))+'\n');return 2;}
  let binary=null;
  if(typeof manifest.value?.file==='string'&&/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(manifest.value.file)){
    const file=target(root,manifest.value.file);if(!file){process.stdout.write(JSON.stringify(incomplete('input-unreadable','@firmware'))+'\n');return 2;}
    try{if(fs.statSync(file).size>LIMITS.firmwareBytes){process.stdout.write(JSON.stringify(incomplete('byte-limit','@firmware'))+'\n');return 2;}binary=fs.readFileSync(file);}catch{process.stdout.write(JSON.stringify(incomplete('input-unreadable','@firmware'))+'\n');return 2;}
  }
  const result=validateFirmware(policy.value,manifest.value,binary,{now});if(result.status==='incomplete'&&result.findings.some(x=>x.location.file==='@policy')){process.stderr.write('Invalid policy.\n');return 2;}
  process.stdout.write(JSON.stringify(result)+'\n');return result.status==='pass'?0:result.status==='fail'?1:2;
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(new URL(import.meta.url)))process.exitCode=main(process.argv.slice(2));
