export const ACTION_STATUSES = Object.freeze(['proposed','pending_approval','approved','rejected','expired','executed']);
export const AGENT_IDS = Object.freeze(['soc','vuln','identity','compliance','engineering']);
const edges = Object.freeze({ proposed:['pending_approval','expired'], pending_approval:['approved','rejected','expired'], approved:['executed','expired'], rejected:[], expired:[], executed:[] });
const text = (value, field) => { if (typeof value !== 'string' || !value.trim()) throw new Error(`${field} is required`); return value.trim(); };
const timestamp = (value, field) => { text(value,field); if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(value) || !Number.isFinite(Date.parse(value))) throw new Error(`${field} must be a UTC timestamp`); return value; };
const snapshot = value => Object.freeze({...value,control_refs:Object.freeze([...value.control_refs])});

// Pure domain entity: private state, immutable snapshots, no I/O or executor.
export class AgentAction {
  #record;
  constructor(input) {
    const allowed=['action_id','agent_id','action_type','target','justification','rule_id','control_refs','severity','proposed_at','rollback_procedure','status'];
    if (!input || Object.keys(input).some(k=>!allowed.includes(k))) throw new Error('Unknown or decision fields in proposal');
    if (input.status !== undefined && input.status !== 'proposed') throw new Error('New actions must be proposed');
    if (!AGENT_IDS.includes(input.agent_id)) throw new Error('Unknown agent');
    if (!['low','medium','high','critical'].includes(input.severity)) throw new Error('Invalid severity');
    if (!Array.isArray(input.control_refs) || !input.control_refs.length) throw new Error('control_refs required');
    const record={};
    for (const key of ['action_id','agent_id','action_type','target','justification','rule_id','severity','rollback_procedure']) record[key]=text(input[key],key);
    record.control_refs=input.control_refs.map(v=>text(v,'control_ref'));
    record.proposed_at=timestamp(input.proposed_at,'proposed_at');
    this.#record=snapshot({...record,status:'proposed',approver:null,decided_at:null,decision_rationale:null,executed_at:null});
    Object.freeze(this);
  }
  get record() { return snapshot(this.#record); }
  // Approval metadata records a human decision; it is not authorization to perform a response.
  transition(next, metadata={}) {
    const current=this.#record;
    if (!edges[current.status].includes(next)) throw new Error(`Invalid transition: ${current.status} → ${next}`);
    const keys = next==='approved'||next==='rejected' ? ['approver','decided_at','decision_rationale'] : next==='executed' ? ['executed_at'] : [];
    if (!metadata || Object.keys(metadata).some(k=>!keys.includes(k))) throw new Error('Unexpected transition metadata');
    const change={status:next};
    if (next==='approved'||next==='rejected') {
      change.approver=text(metadata.approver,'approver');
      change.decided_at=timestamp(metadata.decided_at,'decided_at');
      change.decision_rationale=text(metadata.decision_rationale,'decision_rationale');
      if (Date.parse(change.decided_at)<Date.parse(current.proposed_at)) throw new Error('Decision precedes proposal');
    }
    if (next==='executed') {
      if (!current.approver || !current.decided_at) throw new Error('Approval metadata required');
      change.executed_at=timestamp(metadata.executed_at,'executed_at');
      if (Date.parse(change.executed_at)<Date.parse(current.decided_at)) throw new Error('Execution record precedes approval');
    }
    this.#record=snapshot({...current,...change});
    return this.record;
  }
}

// No arbitrary update/import API. All inserts and changes pass through the entity.
export function createActionRepository() {
  const actions=new Map();
  const read=id=>{const a=actions.get(id);if(!a)throw new Error('Unknown action');return a;};
  const propose=input=>{if(actions.has(input.action_id))throw new Error('Duplicate action');const a=new AgentAction(input);actions.set(a.record.action_id,a);return a.record;};
  const get=id=>read(id).record;
  const list=()=>Object.freeze([...actions.values()].map(a=>a.record));
  // This restricted port is the ONLY port supplied to agents.
  const agent=Object.freeze({propose,get,list,submit:id=>read(id).transition('pending_approval')});
  // Keep this port inside the human review controller; never register it as an agent tool.
  const review=Object.freeze({get,list,decide:(id,status,metadata)=>{
    if(!['approved','rejected'].includes(status))throw new Error('Invalid decision');
    return read(id).transition(status,metadata);
  },expire:id=>read(id).transition('expired'),recordExecution:(id,executed_at)=>read(id).transition('executed',{executed_at})});
  return Object.freeze({agent,review});
}
