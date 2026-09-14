import {AGENT_IDS} from './action-model.mjs';

export const ControlStatus = Object.freeze({
  not_assessed:'not_assessed', evidence_collected:'evidence_collected',
  tested_pass:'tested_pass', tested_fail:'tested_fail', exception_approved:'exception_approved'
});
export const SupersedeReason = Object.freeze({
  recorded_in_error:'recorded_in_error', evidence_reinterpreted:'evidence_reinterpreted',
  scope_corrected:'scope_corrected', other:'other'
});
export const ArtifactType = Object.freeze({
  export:'export', screenshot:'screenshot', log_query:'log_query',
  attestation:'attestation', config_snapshot:'config_snapshot'
});
export const ArtifactVerificationStatus = Object.freeze({unverified:'unverified',verified:'verified'});
export const CollectorType = Object.freeze({agent:'agent',person:'person'});
export const IdentityBasis = Object.freeze({self_reported:'self_reported'});
const humanCapability=Symbol('human-review');
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
const conclusions=['tested_pass','tested_fail','exception_approved'];
const freezeEvidence=e=>Object.freeze({...e,
  collected_by:Object.freeze({...e.collected_by}),
  artifact_ref:Object.freeze({...e.artifact_ref,content_hash:Object.freeze({...e.artifact_ref.content_hash})})
});
const freezeRecord=r=>Object.freeze({...r,
  evidence:Object.freeze(r.evidence.map(freezeEvidence)),
  assessments:Object.freeze(r.assessments.map(a=>Object.freeze({...a})))
});
const currentAssessment=r=>r.assessments.find(a=>a.assessment_id===r.current_assessment_id)||null;
const snapshot=r=>{
  const current=currentAssessment(r);
  return freezeRecord({...r,
    status:current?.status||(r.evidence.length?ControlStatus.evidence_collected:ControlStatus.not_assessed),
    assessor:current?.assessor||null,
    assessed_at:current?.assessed_at||null,
    assessment_rationale:current?.assessment_rationale||null
  });
};

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
const evidenceDigest=evidence=>sha256(JSON.stringify([...evidence]
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
  }))));

const collector=input=>{
  if(!input||Object.keys(input).some(k=>!['type','id','identity_basis'].includes(k)))throw Error('Malformed collected_by');
  if(!Object.values(CollectorType).includes(input.type))throw Error('Invalid collected_by type');
  const id=required(input.id,'collected_by.id');
  if(input.type==='agent'){
    if(input.identity_basis!==undefined)throw Error('identity_basis is only permitted for person collectors');
    if(!AGENT_IDS.includes(id))throw Error('Unknown collecting agent');
    return {type:input.type,id};
  }
  if(AGENT_IDS.some(agentId=>agentId.toLowerCase()===id.toLowerCase())||/agent/i.test(id))throw Error('Person collector ID cannot identify an agent');
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

export class Control {
  #record;
  constructor(input){
    if(!input||Object.keys(input).some(k=>!['control_id','name','cycle_id','cycle_start','cycle_end'].includes(k)))throw Error('Unexpected control field');
    const record={};
    for(const k of ['control_id','name','cycle_id'])record[k]=required(input[k],k);
    record.cycle_start=utc(input.cycle_start,'cycle_start');record.cycle_end=utc(input.cycle_end,'cycle_end');
    if(Date.parse(record.cycle_start)>=Date.parse(record.cycle_end))throw Error('Invalid cycle');
    this.#record=freezeRecord({...record,evidence:[],assessments:[],current_assessment_id:null});
    Object.freeze(this);
  }
  get record(){return snapshot(this.#record);}
  collect(input){
    if(!input||Object.keys(input).some(k=>!['evidence_id','source','collected_by','collected_at','artifact_ref'].includes(k)))throw Error('Unexpected evidence field');
    const evidence={
      evidence_id:required(input.evidence_id,'evidence_id'),
      source:required(input.source,'source'),
      collected_by:collector(input.collected_by),
      collected_at:utc(input.collected_at,'collected_at'),
      artifact_ref:artifact(input.artifact_ref)
    };
    this.#inCycle(evidence.collected_at);
    if(this.#record.evidence.some(e=>e.evidence_id===evidence.evidence_id))throw Error('Duplicate evidence');
    // New evidence invalidates the current assessment but preserves its history.
    this.#record=freezeRecord({...this.#record,evidence:[...this.#record.evidence,evidence],current_assessment_id:null});
    return this.record;
  }
  #inCycle(time){if(Date.parse(time)<Date.parse(this.#record.cycle_start)||Date.parse(time)>=Date.parse(this.#record.cycle_end))throw Error('Timestamp outside assessment cycle');}
  #assessment(status,metadata,transition={}){
    if(!conclusions.includes(status))throw Error('Invalid assessment status');
    const allowed=['assessor','assessed_at','assessment_rationale',...(transition.isSupersede?['supersede_reason','supersede_reason_text']:[])];
    if(!metadata||Object.keys(metadata).some(k=>!allowed.includes(k)))throw Error('Unexpected assessment field');
    const entry={
      assessment_id:this.#record.assessments.length+1,
      status,
      assessor:required(metadata.assessor,'assessor'),
      assessed_at:utc(metadata.assessed_at,'assessed_at'),
      assessment_rationale:required(metadata.assessment_rationale,'assessment_rationale'),
      evidence_digest:evidenceDigest(this.#record.evidence),
      supersedes_assessment_id:transition.supersedes_assessment_id??null,
      supersede_reason:transition.supersede_reason??null,
      supersede_reason_text:transition.supersede_reason_text??null
    };
    this.#inCycle(entry.assessed_at);
    if(this.#record.evidence.some(e=>Date.parse(e.collected_at)>Date.parse(entry.assessed_at)))throw Error('Assessment precedes evidence');
    return entry;
  }
  assess(status,metadata,capability){
    if(capability!==humanCapability)throw Error('Human review capability required');
    if(this.#record.current_assessment_id!==null||!this.#record.evidence.length)throw Error('Evidence collection required before assessment');
    const entry=this.#assessment(status,metadata);
    this.#record=freezeRecord({...this.#record,assessments:[...this.#record.assessments,entry],current_assessment_id:entry.assessment_id});
    return this.record;
  }
  supersede(status,metadata,capability){
    if(capability!==humanCapability)throw Error('Human review capability required');
    const current=currentAssessment(this.#record);
    if(!current)throw Error('Current assessment required before supersede');
    if(!metadata||!Object.values(SupersedeReason).includes(metadata.supersede_reason))throw Error('Valid supersede_reason is required');
    const suppliedText=metadata.supersede_reason_text;
    const reasonText=metadata.supersede_reason==='other'
      ?required(suppliedText,'supersede_reason_text')
      :(suppliedText==null||(typeof suppliedText==='string'&&!suppliedText.trim())?null:required(suppliedText,'supersede_reason_text'));
    const entry=this.#assessment(status,metadata,{
      isSupersede:true,
      supersedes_assessment_id:current.assessment_id,
      supersede_reason:metadata.supersede_reason,
      supersede_reason_text:reasonText
    });
    if(Date.parse(entry.assessed_at)<Date.parse(current.assessed_at))throw Error('Supersede precedes current assessment');
    this.#record=freezeRecord({...this.#record,assessments:[...this.#record.assessments,entry],current_assessment_id:entry.assessment_id});
    return this.record;
  }
}
export function createControlRepository(){
  const records=new Map();
  const find=id=>{if(!records.has(id))throw Error('Unknown control');return records.get(id);};
  const get=id=>find(id).record;
  const list=()=>Object.freeze([...records.values()].map(r=>r.record));
  return Object.freeze({
    add(input){if(records.has(input.control_id))throw Error('Duplicate control');const c=new Control(input);records.set(input.control_id,c);return c.record;},
    agent:Object.freeze({get,list,collect:(id,e)=>find(id).collect(e)}),
    reviewer:Object.freeze({
      get,list,
      assess:(id,status,metadata)=>find(id).assess(status,metadata,humanCapability),
      supersede:(id,status,metadata)=>find(id).supersede(status,metadata,humanCapability)
    })
  });
}
export function conclusionFor(record){
  if(!conclusions.includes(record.status)||!record.assessor?.trim()||!record.assessed_at||!Number.isFinite(Date.parse(record.assessed_at)))return null;
  return {status:record.status,assessor:record.assessor,assessed_at:record.assessed_at};
}
export function effectiveStatus(record){return conclusions.includes(record.status)&&!conclusionFor(record)?'not_assessed':record.status;}
export function coverage(records,cycle_id){
  const scoped=records.filter(r=>r.cycle_id===cycle_id);
  const passed=scoped.filter(r=>effectiveStatus(r)==='tested_pass').length;
  const failed=scoped.filter(r=>effectiveStatus(r)==='tested_fail').length;
  // "not yet tested" includes collected evidence and exceptions, neither is a test.
  return {in_scope:scoped.length,tested:passed+failed,passed,failed,not_assessed:scoped.length-passed-failed};
}
export function coverageStatement(c){return `${c.in_scope} controls in scope. ${c.tested} tested this cycle, ${c.passed} passed, ${c.failed} failed, ${c.not_assessed} not yet tested.`;}
export function sortControls(records){
  const rank={not_assessed:0,evidence_collected:1,tested_fail:2,exception_approved:3,tested_pass:4};
  return [...records].sort((a,b)=>rank[effectiveStatus(a)]-rank[effectiveStatus(b)]||a.control_id.localeCompare(b.control_id));
}
