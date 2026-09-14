import {AGENT_IDS,rejectAgentLikePersonId} from './identity-model.mjs';

export const ArtifactType = Object.freeze({
  export:'export', screenshot:'screenshot', log_query:'log_query',
  attestation:'attestation', config_snapshot:'config_snapshot'
});
export const ArtifactVerificationStatus = Object.freeze({unverified:'unverified',verified:'verified'});
export const CollectorType = Object.freeze({agent:'agent',person:'person'});
export const IdentityBasis = Object.freeze({self_reported:'self_reported'});

const required=(v,k)=>{if(typeof v!=='string'||!v.trim())throw Error(k+' is required');return v.trim();};
const calendarDate=match=>{
  const year=Number(match[1]),month=Number(match[2]),day=Number(match[3]);
  const leap=year%4===0&&(year%100!==0||year%400===0);
  const days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
  return month>=1&&month<=12&&day>=1&&day<=days[month-1];
};
const utc=(v,k)=>{
  required(v,k);
  const match=/^(\d{4})-(\d{2})-(\d{2})T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/.exec(v);
  if(!match||!calendarDate(match)||!Number.isFinite(Date.parse(v)))throw Error(k+' must be a UTC timestamp');
  return v;
};
const freezeEvidence=e=>Object.freeze({...e,
  collected_by:Object.freeze({...e.collected_by}),
  artifact_ref:Object.freeze({...e.artifact_ref,content_hash:Object.freeze({...e.artifact_ref.content_hash})})
});
const collector=input=>{
  if(!input||Object.keys(input).some(k=>!['type','id','identity_basis'].includes(k)))throw Error('Malformed collected_by');
  if(!Object.values(CollectorType).includes(input.type))throw Error('Invalid collected_by type');
  required(input.id,'collected_by.id');
  const id=input.id;
  if(input.type==='agent'){
    if(input.identity_basis!==undefined)throw Error('identity_basis is only permitted for person collectors');
    if(!AGENT_IDS.includes(id))throw Error('Unknown collecting agent');
    return {type:input.type,id};
  }
  rejectAgentLikePersonId(id,'Person collector ID cannot identify an agent');
  if(input.identity_basis===undefined)throw Error('identity_basis is required for person collectors');
  if(input.identity_basis!==IdentityBasis.self_reported)throw Error('Only self_reported identity_basis is currently accepted');
  return {type:input.type,id,identity_basis:input.identity_basis};
};
const artifact=input=>{
  if(!input||Object.keys(input).some(k=>!['type','locator','content_hash','verification_status'].includes(k)))throw Error('Malformed artifact_ref');
  if(!Object.values(ArtifactType).includes(input.type))throw Error('Invalid artifact_ref type');
  const locator=required(input.locator,'artifact_ref.locator');
  if(!input.content_hash||Object.keys(input.content_hash).some(k=>!['algorithm','value'].includes(k)))throw Error('Malformed artifact_ref.content_hash');
  if(input.content_hash.algorithm!=='sha256'||typeof input.content_hash.value!=='string'||!/^[0-9a-f]{64}$/.test(input.content_hash.value))throw Error('artifact_ref.content_hash must be a lowercase SHA-256 value');
  const verification_status=input.verification_status??ArtifactVerificationStatus.unverified;
  if(verification_status===ArtifactVerificationStatus.verified)throw Error('Artifact cannot be marked verified because no artifact resolver exists');
  if(verification_status!==ArtifactVerificationStatus.unverified)throw Error('Invalid artifact_ref verification_status');
  return {type:input.type,locator,content_hash:{algorithm:'sha256',value:input.content_hash.value},verification_status};
};

export class EvidenceRecord {
  #record;
  constructor(input){
    if(!input||Object.keys(input).some(k=>!['evidence_id','source','collected_by','collected_at','artifact_ref'].includes(k)))throw Error('Unexpected evidence field');
    this.#record=freezeEvidence({
      evidence_id:required(input.evidence_id,'evidence_id'),
      source:required(input.source,'source'),
      collected_by:collector(input.collected_by),
      collected_at:utc(input.collected_at,'collected_at'),
      artifact_ref:artifact(input.artifact_ref)
    });
    Object.freeze(this);
  }
  get record(){return freezeEvidence(this.#record);}
}

// Synchronous SHA-256 keeps the model API portable between Node and the browser.
const sha256=value=>{
  const bytes=new TextEncoder().encode(value),words=[],bitLength=bytes.length*8;
  for(const byte of bytes)words.push(byte);
  words.push(128);while(words.length%64!==56)words.push(0);
  for(let i=7;i>=0;i--)words.push(Math.floor(bitLength/2**(i*8))&255);
  const rotr=(x,n)=>(x>>>n)|(x<<(32-n));
  const primes=[],initial=[];
  for(let n=2;primes.length<64;n++){
    if(primes.every(p=>n%p)){primes.push(n);if(initial.length<8)initial.push((Math.sqrt(n)%1)*2**32>>>0);}
  }
  const constants=primes.map(n=>(Math.cbrt(n)%1)*2**32>>>0),hash=initial.slice();
  for(let offset=0;offset<words.length;offset+=64){
    const w=new Array(64);
    for(let i=0;i<16;i++)w[i]=(words[offset+i*4]<<24)|(words[offset+i*4+1]<<16)|(words[offset+i*4+2]<<8)|words[offset+i*4+3];
    for(let i=16;i<64;i++){
      const s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>>3),s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>>10);
      w[i]=(w[i-16]+s0+w[i-7]+s1)|0;
    }
    let [a,b,c,d,e,f,g,h]=hash;
    for(let i=0;i<64;i++){
      const s1=rotr(e,6)^rotr(e,11)^rotr(e,25),choice=(e&f)^(~e&g),t1=(h+s1+choice+constants[i]+w[i])|0;
      const s0=rotr(a,2)^rotr(a,13)^rotr(a,22),majority=(a&b)^(a&c)^(b&c),t2=(s0+majority)|0;
      h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;
    }
    [a,b,c,d,e,f,g,h].forEach((v,i)=>hash[i]=(hash[i]+v)|0);
  }
  return hash.map(v=>(v>>>0).toString(16).padStart(8,'0')).join('');
};
const canonical=evidence=>[...evidence]
  .sort((a,b)=>a.evidence_id.localeCompare(b.evidence_id))
  .map(({evidence_id,source,collected_by,collected_at,artifact_ref})=>({
    evidence_id,source,
    collected_by:{type:collected_by.type,id:collected_by.id,...(collected_by.identity_basis?{identity_basis:collected_by.identity_basis}:{})},
    collected_at,
    artifact_ref:{
      type:artifact_ref.type,locator:artifact_ref.locator,
      content_hash:{algorithm:artifact_ref.content_hash.algorithm,value:artifact_ref.content_hash.value},
      verification_status:artifact_ref.verification_status
    }
  }));

export function createEvidenceRepository(){
  const records=new Map();
  const get=evidence_id=>{
    const record=records.get(evidence_id);
    if(!record)throw Error('Unknown evidence');
    return freezeEvidence(record);
  };
  return Object.freeze({
    add(input){
      const record=new EvidenceRecord(input).record,existing=records.get(record.evidence_id);
      if(existing){
        if(JSON.stringify(existing)!==JSON.stringify(record))throw Error('Conflicting evidence record');
        return freezeEvidence(existing);
      }
      records.set(record.evidence_id,record);
      return freezeEvidence(record);
    },
    get,
    list:()=>Object.freeze([...records.values()].map(freezeEvidence)),
    digest:evidence_ids=>{
      if(!Array.isArray(evidence_ids)||!evidence_ids.length)throw Error('Evidence references required');
      return sha256(JSON.stringify(canonical(evidence_ids.map(get))));
    }
  });
}
