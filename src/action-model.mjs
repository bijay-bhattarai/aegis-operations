import {AGENT_IDS,rejectAgentLikePersonId} from './identity-model.mjs';

export {AGENT_IDS};
export const ACTION_STATUSES = Object.freeze(['proposed','pending_approval','approved','rejected','expired','executed']);
export const ACTION_EVENT_TYPES = Object.freeze(['proposed','submitted','approved','rejected','expired','external_execution_attested']);
export const ACTION_ACTOR_TYPES = Object.freeze(['agent','person','system']);

const edges = Object.freeze({ proposed:['pending_approval','expired'], pending_approval:['approved','rejected','expired'], approved:['executed','expired'], rejected:[], expired:[], executed:[] });
const eventTypeForStatus=Object.freeze({proposed:'proposed',pending_approval:'submitted',approved:'approved',rejected:'rejected',expired:'expired',executed:'external_execution_attested'});
const statusForEventType=Object.freeze(Object.fromEntries(Object.entries(eventTypeForStatus).map(([status,type])=>[type,status])));
const humanCapability=Symbol('human-review');
const text = (value, field) => { if (typeof value !== 'string' || !value.trim()) throw new Error(`${field} is required`); return value.trim(); };
const calendarDate = match => {
  const year=Number(match[1]),month=Number(match[2]),day=Number(match[3]);
  const leap=year%4===0&&(year%100!==0||year%400===0);
  const days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
  return month>=1&&month<=12&&day>=1&&day<=days[month-1];
};
const timestamp = (value, field) => {
  text(value,field);
  const match=/^(\d{4})-(\d{2})-(\d{2})T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.exec(value);
  if (!match || !calendarDate(match) || !Number.isFinite(Date.parse(value))) throw new Error(`${field} must be a UTC timestamp`);
  return value;
};
const immutable=value=>{
  if(Array.isArray(value))return Object.freeze(value.map(immutable));
  if(value&&typeof value==='object')return Object.freeze(Object.fromEntries(Object.entries(value).map(([key,item])=>[key,immutable(item)])));
  return value;
};
const actor=(type,id)=>{
  if(!ACTION_ACTOR_TYPES.includes(type))throw Error('Invalid action actor type');
  const actor_id=text(id,'actor id');
  if(type==='agent'&&!AGENT_IDS.includes(actor_id))throw Error('Unknown agent');
  if(type==='person')rejectAgentLikePersonId(actor_id,'Person action actor ID cannot identify an agent');
  return immutable({type,id:actor_id});
};
const proposalPayload=input=>{
  if (!AGENT_IDS.includes(input.agent_id)) throw new Error('Unknown agent');
  if (!['low','medium','high','critical'].includes(input.severity)) throw new Error('Invalid severity');
  if (!Array.isArray(input.control_refs) || !input.control_refs.length) throw new Error('control_refs required');
  const payload={};
  for (const key of ['action_id','agent_id','action_type','target','justification','rule_id','severity','rollback_procedure']) payload[key]=text(input[key],key);
  payload.control_refs=input.control_refs.map(value=>text(value,'control_ref'));
  return immutable(payload);
};
const visibleEvents=(events,as_of)=>events.filter(event=>Date.parse(event.occurred_at)<=Date.parse(as_of));
const activeEvents=events=>{
  const superseded=new Set(events.map(event=>event.supersedes_event_id).filter(id=>id!==null));
  const byId=new Map(events.map(event=>[event.event_id,event]));
  const rootId=event=>{let current=event;while(current.supersedes_event_id!==null)current=byId.get(current.supersedes_event_id);return current.event_id;};
  return events.filter(event=>!superseded.has(event.event_id)).sort((left,right)=>rootId(left)-rootId(right));
};

// Pure domain entity: append-only private event state, immutable projections, no I/O or executor.
export class AgentAction {
  #events;
  constructor(input) {
    const allowed=['action_id','agent_id','action_type','target','justification','rule_id','control_refs','severity','proposed_at','rollback_procedure','status'];
    if (!input || Object.keys(input).some(key=>!allowed.includes(key))) throw new Error('Unknown or decision fields in proposal');
    if (input.status !== undefined && input.status !== 'proposed') throw new Error('New actions must be proposed');
    const payload=proposalPayload(input),occurred_at=timestamp(input.proposed_at,'proposed_at');
    this.#events=immutable([{event_id:1,type:'proposed',actor:actor('agent',payload.agent_id),occurred_at,reason:'Action proposed',supersedes_event_id:null,...payload}]);
    Object.freeze(this);
  }
  get createdAt(){return this.#events[0].occurred_at;}
  #append(type,payload,eventActor,occurred_at,reason,supersedes_event_id=null){
    const time=timestamp(occurred_at,'occurred_at'),prior=this.#events.at(-1);
    if(Date.parse(time)<Date.parse(prior.occurred_at))throw Error('Action event order must be chronological');
    const event=immutable({event_id:prior.event_id+1,type,actor:eventActor,occurred_at:time,reason:text(reason,'reason'),supersedes_event_id,...payload});
    this.#events=immutable([...this.#events,event]);
    return event;
  }
  project(as_of){
    const time=timestamp(as_of,'as_of');
    if(Date.parse(time)<Date.parse(this.createdAt))throw Error('as_of precedes action');
    const visible=visibleEvents(this.#events,time),active=activeEvents(visible),proposal=active.filter(event=>event.type==='proposed').at(-1);
    if(!proposal)throw Error('Action has no current proposal event');
    const stateEvent=active.filter(event=>statusForEventType[event.type]).at(-1),decision=active.filter(event=>event.type==='approved'||event.type==='rejected').at(-1);
    const execution=stateEvent.type==='external_execution_attested'?stateEvent:null,expiry=stateEvent.type==='expired'?stateEvent:null;
    return immutable({
      action_id:proposal.action_id,agent_id:proposal.agent_id,action_type:proposal.action_type,target:proposal.target,justification:proposal.justification,
      rule_id:proposal.rule_id,severity:proposal.severity,rollback_procedure:proposal.rollback_procedure,control_refs:proposal.control_refs,proposed_at:proposal.occurred_at,
      status:statusForEventType[stateEvent.type],approver:decision?.approver??null,decided_at:decision?.occurred_at??null,
      decision_rationale:decision?.decision_rationale??null,executed_at:execution?.occurred_at??null,
      executor:execution?.executor??null,expired_at:expiry?.occurred_at??null,expiry_actor:expiry?.actor??null
    });
  }
  history(as_of){
    const time=timestamp(as_of,'as_of');
    if(Date.parse(time)<Date.parse(this.createdAt))throw Error('as_of precedes action');
    return immutable(visibleEvents(this.#events,time));
  }
  transition(next,metadata={}){
    if(!ACTION_STATUSES.includes(next))throw Error('Invalid action status');
    let occurred_at,eventActor,payload={},reason;
    if(next==='pending_approval'){
      const allowed=['submitted_at'];if(!metadata||Object.keys(metadata).some(key=>!allowed.includes(key)))throw Error('Unexpected transition metadata');
      occurred_at=timestamp(metadata.submitted_at,'submitted_at');const current=this.project(occurred_at);eventActor=actor('agent',current.agent_id);reason='Action submitted for approval';
    }else if(next==='approved'||next==='rejected'){
      const allowed=['approver','decided_at','decision_rationale'];if(!metadata||Object.keys(metadata).some(key=>!allowed.includes(key)))throw Error('Unexpected transition metadata');
      occurred_at=timestamp(metadata.decided_at,'decided_at');eventActor=actor('person',metadata.approver);reason=next==='approved'?'Action approved':'Action rejected';payload={approver:eventActor.id,decision_rationale:text(metadata.decision_rationale,'decision_rationale')};
    }else if(next==='expired'){
      const allowed=['actor','expired_at','reason'];if(!metadata||Object.keys(metadata).some(key=>!allowed.includes(key)))throw Error('Unexpected transition metadata');
      if(!metadata.actor||Object.keys(metadata.actor).some(key=>!['type','id'].includes(key)))throw Error('Expiry actor is required');
      occurred_at=timestamp(metadata.expired_at,'expired_at');eventActor=actor(metadata.actor.type,metadata.actor.id);reason=text(metadata.reason,'reason');
    }else if(next==='executed'){
      const allowed=['executor','executed_at'];if(!metadata||Object.keys(metadata).some(key=>!allowed.includes(key)))throw Error('Unexpected transition metadata');
      occurred_at=timestamp(metadata.executed_at,'executed_at');eventActor=actor('person',metadata.executor);reason='External execution attested';payload={executor:eventActor.id};
    }else throw Error('A proposed action is created through the constructor');
    if((next==='approved'||next==='rejected')&&Date.parse(occurred_at)<Date.parse(this.createdAt))throw Error('Decision precedes proposal');
    const current=this.project(occurred_at);
    if(!edges[current.status].includes(next))throw new Error(`Invalid transition: ${current.status} → ${next}`);
    if((next==='approved'||next==='rejected')&&Date.parse(occurred_at)<Date.parse(current.proposed_at))throw Error('Decision precedes proposal');
    if(next==='executed'&&(!current.approver||!current.decided_at))throw Error('Approval metadata required');
    if(next==='executed'&&Date.parse(occurred_at)<Date.parse(current.decided_at))throw Error('Execution record precedes approval');
    this.#append(eventTypeForStatus[next],payload,eventActor,occurred_at,reason);
    return this.project(occurred_at);
  }
  supersede(event_id,replacement,metadata,capability){
    if(capability!==humanCapability)throw Error('Human review capability required');
    const original=this.#events.find(event=>event.event_id===event_id);if(!original)throw Error('Unknown action event');
    if(this.#events.some(event=>event.supersedes_event_id===event_id))throw Error('Action event already superseded');
    if(!replacement||replacement.type!==original.type)throw Error('Replacement event type must match');
    if(!metadata||Object.keys(metadata).some(key=>!['actor_id','occurred_at','reason'].includes(key)))throw Error('Unexpected supersede metadata');
    const eventActor=actor('person',metadata.actor_id);let payload={};
    if(original.type==='proposed'){
      const allowed=['type','action_id','agent_id','action_type','target','justification','rule_id','control_refs','severity','rollback_procedure'];
      if(Object.keys(replacement).some(key=>!allowed.includes(key)))throw Error('Unexpected replacement event field');
      payload=proposalPayload(replacement);
      if(payload.action_id!==original.action_id)throw Error('action_id cannot change');
    }else if(original.type==='approved'||original.type==='rejected'){
      if(Object.keys(replacement).some(key=>!['type','approver','decision_rationale'].includes(key)))throw Error('Unexpected replacement event field');
      const approver=text(replacement.approver,'approver');rejectAgentLikePersonId(approver,'Person action actor ID cannot identify an agent');
      payload={approver,decision_rationale:text(replacement.decision_rationale,'decision_rationale')};
    }else if(original.type==='external_execution_attested'){
      if(Object.keys(replacement).some(key=>!['type','executor'].includes(key)))throw Error('Unexpected replacement event field');
      const executor=text(replacement.executor,'executor');rejectAgentLikePersonId(executor,'Person action actor ID cannot identify an agent');payload={executor};
    }
    else if(Object.keys(replacement).some(key=>key!=='type'))throw Error('Unexpected replacement event field');
    this.#append(original.type,payload,eventActor,metadata.occurred_at,metadata.reason,event_id);
    return this.project(metadata.occurred_at);
  }
}

// No arbitrary update/import API. All inserts and changes pass through the entity.
export function createActionRepository() {
  const actions=new Map();
  const read=id=>{const action=actions.get(id);if(!action)throw new Error('Unknown action');return action;};
  const propose=input=>{if(actions.has(input.action_id))throw new Error('Duplicate action');const action=new AgentAction(input);actions.set(input.action_id,action);return action.project(input.proposed_at);};
  const get=(id,as_of)=>read(id).project(as_of);
  const list=as_of=>{timestamp(as_of,'as_of');return immutable([...actions.values()].filter(action=>Date.parse(action.createdAt)<=Date.parse(as_of)).map(action=>action.project(as_of)));};
  const history=(id,as_of)=>read(id).history(as_of);
  const agent=Object.freeze({propose,get,list,history,submit:(id,metadata)=>read(id).transition('pending_approval',metadata)});
  const review=Object.freeze({get,list,history,decide:(id,status,metadata)=>{
    if(!['approved','rejected'].includes(status))throw new Error('Invalid decision');
    return read(id).transition(status,metadata);
  },expire:(id,metadata)=>read(id).transition('expired',metadata),recordExecution:(id,metadata)=>read(id).transition('executed',metadata),
  supersede:(id,event_id,replacement,metadata)=>read(id).supersede(event_id,replacement,metadata,humanCapability)});
  return Object.freeze({agent,review});
}
