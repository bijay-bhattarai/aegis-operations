import {EvidenceRecord,createEvidenceRepository} from './evidence-model.mjs';
export {ArtifactType,ArtifactVerificationStatus,CollectorType,IdentityBasis} from './evidence-model.mjs';

export const ControlStatus = Object.freeze({
  not_assessed:'not_assessed', evidence_collected:'evidence_collected',
  tested_pass:'tested_pass', tested_fail:'tested_fail', exception_approved:'exception_approved'
});
export const SupersedeReason = Object.freeze({
  recorded_in_error:'recorded_in_error', evidence_reinterpreted:'evidence_reinterpreted',
  scope_corrected:'scope_corrected', other:'other'
});
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
const freezeRecord=r=>Object.freeze({...r,
  evidence_ids:Object.freeze([...r.evidence_ids]),
  assessments:Object.freeze(r.assessments.map(a=>Object.freeze({...a})))
});
const currentAssessment=r=>r.assessments.find(a=>a.assessment_id===r.current_assessment_id)||null;
const snapshot=(r,evidenceRepository)=>{
  const current=currentAssessment(r);
  const {evidence_ids,...record}=r;
  return Object.freeze({...record,
    evidence:Object.freeze(evidence_ids.map(evidenceRepository.get)),
    status:current?.status||(evidence_ids.length?ControlStatus.evidence_collected:ControlStatus.not_assessed),
    assessor:current?.assessor||null,
    assessed_at:current?.assessed_at||null,
    assessment_rationale:current?.assessment_rationale||null
  });
};

export class Control {
  #record;
  #evidenceRepository;
  constructor(input,evidenceRepository=createEvidenceRepository()){
    if(!input||Object.keys(input).some(k=>!['control_id','name','cycle_id','cycle_start','cycle_end'].includes(k)))throw Error('Unexpected control field');
    const record={};
    for(const k of ['control_id','name','cycle_id'])record[k]=required(input[k],k);
    record.cycle_start=utc(input.cycle_start,'cycle_start');record.cycle_end=utc(input.cycle_end,'cycle_end');
    if(Date.parse(record.cycle_start)>=Date.parse(record.cycle_end))throw Error('Invalid cycle');
    this.#evidenceRepository=evidenceRepository;
    this.#record=freezeRecord({...record,evidence_ids:[],assessments:[],current_assessment_id:null});
    Object.freeze(this);
  }
  get record(){return snapshot(this.#record,this.#evidenceRepository);}
  collect(input){
    const evidence=new EvidenceRecord(input).record;
    this.#inCycle(evidence.collected_at);
    if(this.#record.evidence_ids.includes(evidence.evidence_id))throw Error('Duplicate evidence');
    this.#evidenceRepository.add(evidence);
    // New evidence invalidates the current assessment but preserves its history.
    this.#record=freezeRecord({...this.#record,evidence_ids:[...this.#record.evidence_ids,evidence.evidence_id],current_assessment_id:null});
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
      evidence_digest:this.#evidenceRepository.digest(this.#record.evidence_ids),
      supersedes_assessment_id:transition.supersedes_assessment_id??null,
      supersede_reason:transition.supersede_reason??null,
      supersede_reason_text:transition.supersede_reason_text??null
    };
    this.#inCycle(entry.assessed_at);
    if(this.#record.evidence_ids.some(id=>Date.parse(this.#evidenceRepository.get(id).collected_at)>Date.parse(entry.assessed_at)))throw Error('Assessment precedes evidence');
    return entry;
  }
  assess(status,metadata,capability){
    if(capability!==humanCapability)throw Error('Human review capability required');
    if(this.#record.current_assessment_id!==null||!this.#record.evidence_ids.length)throw Error('Evidence collection required before assessment');
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
export function createControlRepository({evidenceRepository=createEvidenceRepository()}={}){
  const records=new Map();
  const find=id=>{if(!records.has(id))throw Error('Unknown control');return records.get(id);};
  const get=id=>find(id).record;
  const list=()=>Object.freeze([...records.values()].map(r=>r.record));
  return Object.freeze({
    add(input){if(records.has(input.control_id))throw Error('Duplicate control');const c=new Control(input,evidenceRepository);records.set(input.control_id,c);return c.record;},
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
