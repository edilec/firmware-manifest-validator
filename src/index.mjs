export const TOOL_ID='firmware-manifest-validator';
export const LIMITS=Object.freeze({policyBytes:65536,manifestBytes:65536,firmwareBytes:16777216,compatibleFrom:100,depth:16,milliseconds:5000});
import {createHash} from 'node:crypto';
const SEVERITY=Object.freeze({'input-unreadable':'warning','input-invalid':'warning','export-incomplete':'warning','byte-limit':'warning','record-limit':'warning','depth-limit':'warning','time-limit':'warning','rollback-unknown':'warning','file-missing':'warning','target-mismatch':'error','digest-mismatch':'error','size-mismatch':'error','size-exceeded':'error','base-incompatible':'error','bootloader-incompatible':'error','version-not-newer':'error','rollback-unavailable':'error'});
const MESSAGE=Object.freeze({'input-unreadable':'Input could not be read, decoded, or parsed.','input-invalid':'Policy or firmware manifest structure is invalid.','export-incomplete':'Manifest does not assert complete coverage.','byte-limit':'Input or firmware artifact exceeds its byte limit.','record-limit':'Compatibility list exceeds its record limit.','depth-limit':'JSON nesting exceeds depth 16.','time-limit':'Evaluation exceeded 5000 milliseconds.','rollback-unknown':'Rollback prerequisites are not documented.','file-missing':'Required firmware artifact was not supplied.','target-mismatch':'Manifest target hardware differs from policy.','digest-mismatch':'Local firmware digest differs from manifest.','size-mismatch':'Local firmware size differs from manifest.','size-exceeded':'Firmware size exceeds policy maximum.','base-incompatible':'Current firmware is not in the compatible base set.','bootloader-incompatible':'Bootloader is below the declared minimum.','version-not-newer':'Firmware version does not advance the installed version.','rollback-unavailable':'Rollback metadata does not provide a supported current version.'});
const cmp=(a,b)=>a<b?-1:a>b?1:0;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const safe=x=>typeof x==='string'&&x.length>0&&x.length<=128&&/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(x);
const keysOnly=(x,keys)=>Object.keys(x).every(k=>keys.includes(k));
function finding(ruleId,file,pointer=''){return {ruleId,severity:SEVERITY[ruleId],message:MESSAGE[ruleId],location:{file,pointer}};}
function report(findings,verification='unknown',checked=0){findings.sort((a,b)=>cmp(a.location.file,b.location.file)||cmp(a.location.pointer,b.location.pointer)||cmp(a.ruleId,b.ruleId));const status=findings.some(x=>x.severity==='warning')?'incomplete':findings.some(x=>x.severity==='error')?'fail':'pass';return {schemaVersion:'1',tool:TOOL_ID,status,summary:{checked,errors:findings.filter(x=>x.severity==='error').length,warnings:findings.filter(x=>x.severity==='warning').length},digestVerification:status==='incomplete'?'unknown':verification,findings};}
export function incomplete(ruleId,file){return report([finding(ruleId,file)]);}
function tooDeep(value){const stack=[[value,0]];while(stack.length){const [item,depth]=stack.pop();if(depth>LIMITS.depth)return true;if(item&&typeof item==='object')for(const child of Object.values(item))stack.push([child,depth+1]);}return false;}
function semver(text){if(typeof text!=='string')return null;const m=/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.exec(text);if(!m)return null;const core=[Number(m[1]),Number(m[2]),Number(m[3])];if(core.some(x=>!Number.isSafeInteger(x)||x>999999))return null;const pre=m[4]?m[4].split('.'):[];if(pre.some(x=>/^\d+$/.test(x)&&x.length>1&&x[0]==='0'))return null;return {core,pre};}
function compareVersion(a,b){for(let i=0;i<3;i++)if(a.core[i]!==b.core[i])return a.core[i]-b.core[i];if(!a.pre.length&&!b.pre.length)return 0;if(!a.pre.length)return 1;if(!b.pre.length)return -1;for(let i=0;i<Math.min(a.pre.length,b.pre.length);i++){const x=a.pre[i],y=b.pre[i],xn=/^\d+$/.test(x),yn=/^\d+$/.test(y);if(x===y)continue;if(xn&&yn){const xx=BigInt(x),yy=BigInt(y);return xx<yy?-1:1;}if(xn!==yn)return xn?-1:1;return cmp(x,y);}return a.pre.length-b.pre.length;}
export function validateFirmware(policy,manifest,binary=null,{now=()=>performance.now()}={}){
  const start=now(),timed=()=>now()-start>LIMITS.milliseconds,findings=[];
  if(tooDeep(policy))findings.push(finding('depth-limit','@policy'));
  if(tooDeep(manifest))findings.push(finding('depth-limit','@manifest'));
  if(findings.length)return report(findings);
  if(!object(policy)||!keysOnly(policy,['schemaVersion','targetHardware','currentVersion','bootloaderVersion','maxBytes','fileVerification','metadata'])||policy.schemaVersion!=='1'||!safe(policy.targetHardware)||!semver(policy.currentVersion)||!semver(policy.bootloaderVersion)||!Number.isInteger(policy.maxBytes)||policy.maxBytes<1||policy.maxBytes>LIMITS.firmwareBytes||!['required','optional'].includes(policy.fileVerification)){findings.push(finding('input-invalid','@policy'));return report(findings);}
  if(!object(manifest)||!keysOnly(manifest,['schemaVersion','complete','targetHardware','version','sizeBytes','digestSha256','compatibleFrom','minBootloaderVersion','rollback','file','metadata'])||manifest.schemaVersion!=='1'||!safe(manifest.targetHardware)||!semver(manifest.version)||!Number.isInteger(manifest.sizeBytes)||manifest.sizeBytes<1||!/^([a-fA-F0-9]{64})$/.test(manifest.digestSha256)||!Array.isArray(manifest.compatibleFrom)||!semver(manifest.minBootloaderVersion)||manifest.file!==undefined&&(!safe(manifest.file,512)||manifest.file.startsWith('/'))){findings.push(finding('input-invalid','@manifest'));return report(findings);}
  if(manifest.complete!==true){findings.push(finding('export-incomplete','@manifest','/complete'));return report(findings);}
  if(manifest.compatibleFrom.length>LIMITS.compatibleFrom){findings.push(finding('record-limit','@manifest','/compatibleFrom'));return report(findings);}
  if(manifest.compatibleFrom.length===0||manifest.compatibleFrom.some(x=>!semver(x))){findings.push(finding('input-invalid','@manifest','/compatibleFrom'));return report(findings);}
  if(manifest.rollback===undefined){findings.push(finding('rollback-unknown','@manifest','/rollback'));return report(findings);}
  if(!object(manifest.rollback)||!keysOnly(manifest.rollback,['supported','version'])||typeof manifest.rollback.supported!=='boolean'||manifest.rollback.supported&& !semver(manifest.rollback.version)||!manifest.rollback.supported&&manifest.rollback.version!==undefined&&!semver(manifest.rollback.version)){findings.push(finding('input-invalid','@manifest','/rollback'));return report(findings);}
  if(binary!==null&&!Buffer.isBuffer(binary)){findings.push(finding('input-invalid','@firmware'));return report(findings);}
  if(binary&&binary.length>LIMITS.firmwareBytes){findings.push(finding('byte-limit','@firmware'));return report(findings);}
  if(manifest.file!==undefined&&binary===null){findings.push(finding('file-missing','@firmware'));return report(findings);}
  if(manifest.file===undefined&&binary!==null){findings.push(finding('input-invalid','@firmware'));return report(findings);}
  if(timed())return incomplete('time-limit','@manifest');
  if(manifest.targetHardware!==policy.targetHardware)findings.push(finding('target-mismatch','@manifest','/targetHardware'));
  if(compareVersion(semver(manifest.version),semver(policy.currentVersion))<=0)findings.push(finding('version-not-newer','@manifest','/version'));
  if(!manifest.compatibleFrom.some(x=>compareVersion(semver(x),semver(policy.currentVersion))===0))findings.push(finding('base-incompatible','@manifest','/compatibleFrom'));
  if(compareVersion(semver(policy.bootloaderVersion),semver(manifest.minBootloaderVersion))<0)findings.push(finding('bootloader-incompatible','@manifest','/minBootloaderVersion'));
  if(!manifest.rollback.supported||compareVersion(semver(manifest.rollback.version),semver(policy.currentVersion))!==0)findings.push(finding('rollback-unavailable','@manifest','/rollback'));
  if(manifest.sizeBytes>policy.maxBytes)findings.push(finding('size-exceeded','@manifest','/sizeBytes'));
  let verification='not-supplied';
  if(binary){verification='verified';if(binary.length!==manifest.sizeBytes)findings.push(finding('size-mismatch','@firmware'));if(createHash('sha256').update(binary).digest('hex')!==manifest.digestSha256.toLowerCase())findings.push(finding('digest-mismatch','@firmware'));}
  else if(policy.fileVerification==='required')findings.push(finding('file-missing','@firmware'));
  if(timed())return incomplete('time-limit','@firmware');
  return report(findings,verification,1);
}
