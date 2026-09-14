export const ControlStatus = Object.freeze({
  not_assessed:'not_assessed', evidence_collected:'evidence_collected',
  tested_pass:'tested_pass', tested_fail:'tested_fail', exception_approved:'exception_approved'
});
const humanCapability=Symbol('human-review');
const required=(v,k)=>{if(typeof v!=='string'||!v.trim())throw Error(k+' is required');return v.trim();};
const utc=(v,k)=>{required(v,k);if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/.test(v)||!Number.isFinite(Date.parse(v)))throw Error(k+' must be a UTC timestamp');return v;};
const copy=r=>Object.freeze({...r,evidence:Object.freeze(r.evidence.map(e=>Object.freeze({...e})))});
const conclusions=['tested_pass','tested_fail','exception_approved'];
export class Control {
  #record;
  constructor(input){
    if(!input||Object.keys(input).some(k=>!['control_id','name','cycle_id','cycle_start','cycle_end'].includes(k)))throw Error('Unexpected control field');
    const record={};
    for(const k of ['control_id','name','cycle_id'])record[k]=required(input[k],k);
    record.cycle_start=utc(input.cycle_start,'cycle_start');record.cycle_end=utc(input.cycle_end,'cycle_end');
    if(Date.parse(record.cycle_start)>=Date.parse(record.cycle_end))throw Error('Invalid cycle');
    this.#record=copy({...record,status:ControlStatus.not_assessed,evidence:[],assessor:null,assessed_at:null,assessment_rationale:null});
    Object.freeze(this);
  }
  get record(){return copy(this.#record);}
  collect(input){
    if(!input||Object.keys(input).some(k=>!['evidence_id','source','collected_at'].includes(k)))throw Error('Unexpected evidence field');
    const evidence={evidence_id:required(input.evidence_id,'evidence_id'),source:required(input.source,'source'),collected_at:utc(input.collected_at,'collected_at')};
    this.#inCycle(evidence.collected_at);
    if(this.#record.evidence.some(e=>e.evidence_id===evidence.evidence_id))throw Error('Duplicate evidence');
    // New evidence invalidates the current assessment; no implicit carry-forward.
    this.#record=copy({...this.#record,evidence:[...this.#record.evidence,evidence],status:ControlStatus.evidence_collected,assessor:null,assessed_at:null,assessment_rationale:null});
    return this.record;
  }
  #inCycle(time){if(Date.parse(time)<Date.parse(this.#record.cycle_start)||Date.parse(time)>=Date.parse(this.#record.cycle_end))throw Error('Timestamp outside assessment cycle');}
  assess(status,metadata,capability){
    if(capability!==humanCapability)throw Error('Human review capability required');
    if(!conclusions.includes(status))throw Error('Invalid assessment status');
    if(this.#record.status!=='evidence_collected'||!this.#record.evidence.length)throw Error('Evidence collection required before assessment');
    if(!metadata||Object.keys(metadata).some(k=>!['assessor','assessed_at','assessment_rationale'].includes(k)))throw Error('Unexpected assessment field');
    const change={status,assessor:required(metadata.assessor,'assessor'),assessed_at:utc(metadata.assessed_at,'assessed_at'),assessment_rationale:required(metadata.assessment_rationale,'assessment_rationale')};
    this.#inCycle(change.assessed_at);
    if(this.#record.evidence.some(e=>Date.parse(e.collected_at)>Date.parse(change.assessed_at)))throw Error('Assessment precedes evidence');
    this.#record=copy({...this.#record,...change});return this.record;
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
    reviewer:Object.freeze({get,list,assess:(id,status,metadata)=>find(id).assess(status,metadata,humanCapability)})
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
