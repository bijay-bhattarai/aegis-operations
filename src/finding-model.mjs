import {AGENT_IDS} from './action-model.mjs';
import {createEvidenceRepository} from './evidence-model.mjs';

export const FindingType=Object.freeze({
  vulnerability:'vulnerability',incident:'incident',identity:'identity',compliance:'compliance',configuration:'configuration',other:'other'
});
export const FindingState=Object.freeze({open:'open',closed:'closed'});
export const FindingDisposition=Object.freeze({
  remediated:'remediated',false_positive:'false_positive',risk_accepted:'risk_accepted',duplicate:'duplicate',reopened:'reopened'
});
export const FindingEventType=Object.freeze({
  identified:'identified',evidence_linked:'evidence_linked',owner_assigned:'owner_assigned',severity_changed:'severity_changed',action_linked:'action_linked',disposition:'disposition'
});
export const FindingActorType=Object.freeze({agent:'agent',person:'person',system:'system'});
export const FindingOwnerType=Object.freeze({queue:'queue',person:'person'});
export const Severity=Object.freeze({low:'low',medium:'medium',high:'high',critical:'critical'});

const severityOrder=Object.freeze(['low','medium','high','critical']);
const reviewCapability=Symbol('finding-human-review');
const required=(value,field)=>{if(typeof value!=='string'||!value.trim())throw Error(field+' is required');return value.trim();};
const calendarDate=match=>{
  const year=Number(match[1]),month=Number(match[2]),day=Number(match[3]);
  const leap=year%4===0&&(year%100!==0||year%400===0),days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
  return month>=1&&month<=12&&day>=1&&day<=days[month-1];
};
const utc=(value,field)=>{
  required(value,field);
  const match=/^(\d{4})-(\d{2})-(\d{2})T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/.exec(value);
  if(!match||!calendarDate(match)||!Number.isFinite(Date.parse(value)))throw Error(field+' must be a UTC timestamp');
  return value;
};
const stringList=(value,field,{allowEmpty=false}={})=>{
  if(!Array.isArray(value)||(!allowEmpty&&!value.length))throw Error(field+' required');
  const result=value.map(item=>required(item,field.slice(0,-1)));
  if(new Set(result).size!==result.length)throw Error(field+' must be unique');
  return result;
};
const clone=value=>value===undefined?undefined:JSON.parse(JSON.stringify(value));
const deepFreeze=value=>{
  if(value&&typeof value==='object'&&!Object.isFrozen(value)){
    for(const child of Object.values(value))deepFreeze(child);
    Object.freeze(value);
  }
  return value;
};
const immutable=value=>deepFreeze(clone(value));
const actor=(type,id)=>{
  if(!Object.values(FindingActorType).includes(type))throw Error('Invalid actor type');
  if(type==='agent'&&!AGENT_IDS.includes(id))throw Error('Unknown agent');
  return {type,id:required(id,'actor.id')};
};
const personMetadata=metadata=>{
  if(!metadata||Object.keys(metadata).some(key=>!['actor_id','occurred_at','reason'].includes(key)))throw Error('Unexpected human event metadata');
  return {actor:actor('person',metadata.actor_id),occurred_at:utc(metadata.occurred_at,'occurred_at'),reason:required(metadata.reason,'reason')};
};
const agentMetadata=metadata=>{
  if(!metadata||Object.keys(metadata).some(key=>!['agent_id','occurred_at','reason'].includes(key)))throw Error('Unexpected agent event metadata');
  return {actor:actor('agent',metadata.agent_id),occurred_at:utc(metadata.occurred_at,'occurred_at'),reason:required(metadata.reason,'reason')};
};
const validateModifiers=(value,policy)=>{
  if(value===undefined)return [];
  if(!Array.isArray(value)||new Set(value).size!==value.length||value.some(item=>!Object.hasOwn(policy.modifiers,item)))throw Error('Invalid severity modifier');
  return [...value];
};
const controlPassedAt=(controlRepository,evidenceRepository,control_id,as_of)=>{
  if(!controlRepository?.reviewer?.get)throw Error('Control repository required for compensating_control');
  let control;try{control=controlRepository.reviewer.get(control_id);}catch{throw Error('Unknown compensating control');}
  const assessments=control.assessments.filter(item=>Date.parse(item.assessed_at)<=Date.parse(as_of))
    .sort((a,b)=>Date.parse(a.assessed_at)-Date.parse(b.assessed_at)||a.assessment_id-b.assessment_id);
  const current=assessments.at(-1);if(!current||current.status!=='tested_pass')return false;
  const evidenceIds=control.evidence.filter(item=>Date.parse(item.collected_at)<=Date.parse(as_of)).map(item=>item.evidence_id);
  return evidenceIds.length>0&&current.evidence_digest===evidenceRepository.digest(evidenceIds);
};
const shiftSeverity=(base,modifiers,policy)=>{
  const shift=modifiers.reduce((total,item)=>total+policy.modifiers[item],0);
  return severityOrder[Math.max(0,Math.min(severityOrder.length-1,severityOrder.indexOf(base)+shift))];
};
const ssvcDecisionRows=[
 ['none','no','partial','low','track'],['none','no','partial','medium','track'],['none','no','partial','high','track'],
 ['none','no','total','low','track'],['none','no','total','medium','track'],['none','no','total','high','track_star'],
 ['none','yes','partial','low','track'],['none','yes','partial','medium','track'],['none','yes','partial','high','attend'],
 ['none','yes','total','low','track'],['none','yes','total','medium','track'],['none','yes','total','high','attend'],
 ['poc','no','partial','low','track'],['poc','no','partial','medium','track'],['poc','no','partial','high','track_star'],
 ['poc','no','total','low','track'],['poc','no','total','medium','track_star'],['poc','no','total','high','attend'],
 ['poc','yes','partial','low','track'],['poc','yes','partial','medium','track'],['poc','yes','partial','high','attend'],
 ['poc','yes','total','low','track'],['poc','yes','total','medium','track_star'],['poc','yes','total','high','attend'],
 ['active','no','partial','low','track'],['active','no','partial','medium','track'],['active','no','partial','high','attend'],
 ['active','no','total','low','track'],['active','no','total','medium','attend'],['active','no','total','high','act'],
 ['active','yes','partial','low','attend'],['active','yes','partial','medium','attend'],['active','yes','partial','high','act'],
 ['active','yes','total','low','attend'],['active','yes','total','medium','act'],['active','yes','total','high','act']
];
const ssvcDecisionTable=new Map(ssvcDecisionRows.map(row=>[row.slice(0,4).join('|'),row[4]]));
const ssvcOutcome=points=>{
  const missionWellbeing=points.mission_prevalence==='essential'||points.public_wellbeing_impact==='irreversible'?'high'
    :points.mission_prevalence==='minimal'&&points.public_wellbeing_impact==='minimal'?'low':'medium';
  return ssvcDecisionTable.get([points.exploitation,points.automatable,points.technical_impact,missionWellbeing].join('|'));
};

export const DEFAULT_SEVERITY_POLICIES=immutable([
  {
    policy_id:'aegis-vulnerability-ssvc',version:'1',finding_type:'vulnerability',method:'ssvc',
    ssvc_decision_tree_version:'CISA Coordinator v2.0.3',application_mapping_version:'aegis-ssvc-severity-1',
    permitted_decision_points:{
      exploitation:['none','poc','active'],automatable:['no','yes'],technical_impact:['partial','total'],
      mission_prevalence:['minimal','support','essential'],public_wellbeing_impact:['minimal','material','irreversible']
    },
    outcome_mapping:{track:'low',track_star:'medium',attend:'high',act:'critical'},
    modifiers:{regulated_data:1,broad_scope:1,compensating_control:-1,isolated_nonproduction:-1}
  },
  {
    policy_id:'aegis-general-risk-matrix',version:'1',finding_type:'*',method:'risk_matrix',application_mapping_version:'aegis-risk-matrix-severity-1',
    permitted_decision_points:{likelihood:['low','medium','high'],impact:['low','medium','high']},
    score_mapping:{'2':'low','3':'medium','4':'medium','5':'high','6':'critical'},
    modifiers:{regulated_data:1,broad_scope:1,compensating_control:-1,isolated_nonproduction:-1}
  }
]);
export const DEFAULT_SLA_POLICIES=immutable([
  {policy_id:'aegis-default-sla',version:'1',rule_id:'*',bands:{critical:7,high:15,medium:30,low:90}}
]);

const validateSeverityPolicy=policy=>{
  const copy=clone(policy);
  for(const field of ['policy_id','version','finding_type','method','application_mapping_version'])required(copy[field],field);
  if(!['ssvc','risk_matrix'].includes(copy.method))throw Error('Invalid severity policy method');
  if(copy.method==='ssvc')required(copy.ssvc_decision_tree_version,'ssvc_decision_tree_version');
  if(!copy.permitted_decision_points||!copy.modifiers)throw Error('Incomplete severity policy');
  return immutable(copy);
};
const validateSlaPolicy=policy=>{
  const copy=clone(policy);
  for(const field of ['policy_id','version','rule_id'])required(copy[field],field);
  if(!copy.bands||Object.values(Severity).some(level=>!Number.isInteger(copy.bands[level])||copy.bands[level]<=0))throw Error('Invalid SLA bands');
  return immutable(copy);
};
const policyFor=(policies,findingType)=>policies.find(policy=>policy.finding_type===findingType)||policies.find(policy=>policy.finding_type==='*');
const slaFor=(policies,ruleId)=>policies.find(policy=>policy.rule_id===ruleId)||policies.find(policy=>policy.rule_id==='*');
const computeSeverity=(findingType,input,policy,context={})=>{
  if(!input||typeof input!=='object'||Array.isArray(input))throw Error('severity_input is required');
  if(input.ssvc!==undefined&&input.risk_matrix!==undefined)throw Error('SSVC and risk matrix inputs cannot both appear');
  const allowed=['ssvc','risk_matrix','modifiers','modifier_support'];
  if(Object.keys(input).some(key=>!allowed.includes(key)))throw Error('Unexpected severity input');
  const modifiers=validateModifiers(input.modifiers,policy),reducing=modifiers.filter(item=>policy.modifiers[item]<0);
  const support=clone(input.modifier_support??{});
  if(!support||typeof support!=='object'||Array.isArray(support)||Object.keys(support).some(key=>!modifiers.includes(key)))throw Error('Invalid modifier_support');
  if(reducing.length&&context.capability!==reviewCapability)throw Error('Human review capability required for severity-reducing modifiers');
  for(const modifier of reducing){
    const cited=support[modifier];
    if(!cited||Object.keys(cited).some(key=>!['evidence_ids','control_refs'].includes(key)))throw Error('Evidence required for severity-reducing modifier');
    cited.evidence_ids=stringList(cited.evidence_ids,'evidence_ids');
    for(const evidence_id of cited.evidence_ids)context.evidenceRepository.get(evidence_id);
    if(modifier==='compensating_control'){
      cited.control_refs=stringList(cited.control_refs,'control_refs');
      for(const control_id of cited.control_refs){
        if(!context.findingControlRefs.includes(control_id))throw Error('Compensating control must be referenced by the finding');
        if(!controlPassedAt(context.controlRepository,context.evidenceRepository,control_id,context.occurredAt))throw Error('Compensating control must have a current human-recorded tested_pass');
      }
    }else if(cited.control_refs!==undefined)throw Error('control_refs are only valid for compensating_control');
  }
  if(Object.keys(support).some(modifier=>policy.modifiers[modifier]>=0))throw Error('modifier_support is only valid for severity-reducing modifiers');
  let basis,base;
  if(findingType==='vulnerability'){
    if(policy.method!=='ssvc'||!input.ssvc||input.risk_matrix!==undefined)throw Error('Vulnerability findings require SSVC inputs exclusively');
    const permitted=policy.permitted_decision_points,keys=Object.keys(permitted);
    if(Object.keys(input.ssvc).length!==keys.length||keys.some(key=>!permitted[key].includes(input.ssvc[key])))throw Error('Invalid SSVC decision points');
    const outcome=ssvcOutcome(input.ssvc);base=policy.outcome_mapping[outcome];basis={method:'ssvc',decision_points:clone(input.ssvc),outcome};
  }else{
    if(policy.method!=='risk_matrix'||!input.risk_matrix||input.ssvc!==undefined)throw Error('Non-vulnerability findings require risk matrix inputs exclusively');
    const permitted=policy.permitted_decision_points,keys=Object.keys(permitted);
    if(Object.keys(input.risk_matrix).length!==keys.length||keys.some(key=>!permitted[key].includes(input.risk_matrix[key])))throw Error('Invalid risk matrix decision points');
    const rank={low:1,medium:2,high:3},score=rank[input.risk_matrix.likelihood]+rank[input.risk_matrix.impact];
    base=policy.score_mapping[String(score)];basis={method:'risk_matrix',decision_points:clone(input.risk_matrix),score};
  }
  return immutable({severity:shiftSeverity(base,modifiers,policy),base_severity:base,basis,modifiers,modifier_support:clone(support),policy});
};
const validateOwner=owner=>{
  if(!owner||Object.keys(owner).some(key=>!['type','id'].includes(key))||!Object.values(FindingOwnerType).includes(owner.type))throw Error('Invalid owner');
  return {type:owner.type,id:required(owner.id,'owner.id')};
};
const addDays=(timestamp,days)=>new Date(Date.parse(timestamp)+days*86400000).toISOString();

class Finding{
  #record;#evidenceRepository;#controlRepository;#queueRules;
  constructor(input,context){
    const allowed=['finding_id','rule_id','finding_type','title','control_refs','evidence_id','created_at','severity_input','agent_id'];
    if(!input||Object.keys(input).some(key=>!allowed.includes(key)))throw Error('Unexpected finding field');
    const finding_id=required(input.finding_id,'finding_id'),rule_id=required(input.rule_id,'rule_id'),finding_type=required(input.finding_type,'finding_type');
    if(!Object.values(FindingType).includes(finding_type))throw Error('Invalid finding_type');
    const created_at=utc(input.created_at,'created_at'),evidence_id=required(input.evidence_id,'evidence_id');
    context.evidenceRepository.get(evidence_id);
    const severityPolicy=policyFor(context.severityPolicies,finding_type),slaPolicy=slaFor(context.slaPolicies,rule_id);
    if(!severityPolicy||!slaPolicy)throw Error('Applicable severity and SLA policies required');
    const control_refs=stringList(input.control_refs,'control_refs');
    const severity=computeSeverity(finding_type,input.severity_input,severityPolicy,{evidenceRepository:context.evidenceRepository,controlRepository:context.controlRepository,findingControlRefs:control_refs,occurredAt:created_at});
    this.#evidenceRepository=context.evidenceRepository;this.#controlRepository=context.controlRepository;this.#queueRules=context.queueRules;
    const identified={event_id:1,type:'identified',actor:actor('agent',input.agent_id),occurred_at:created_at,reason:'Finding identified',supersedes_event_id:null,evidence_id,severity};
    const queue=this.#queueRules[rule_id];if(!queue)throw Error('Rule-defined queue assignment required');
    const assigned={event_id:2,type:'owner_assigned',actor:actor('system','rule-queue-assignment'),occurred_at:created_at,reason:'Rule-defined queue assignment',supersedes_event_id:null,owner:{type:'queue',id:queue}};
    this.#record=immutable({finding_id,rule_id,finding_type,title:required(input.title,'title'),control_refs,created_at,severity_policy:severityPolicy,sla_policy:slaPolicy,events:[identified,assigned]});
    Object.freeze(this);
  }
  get createdAt(){return this.#record.created_at;}
  #append(type,payload,metadata,supersedes_event_id=null){
    if(Date.parse(metadata.occurred_at)<Date.parse(this.#record.created_at))throw Error('Event precedes finding');
    const prior=this.#record.events.at(-1);if(Date.parse(metadata.occurred_at)<Date.parse(prior.occurred_at))throw Error('Event order must be chronological');
    const event={event_id:prior.event_id+1,type,...metadata,supersedes_event_id,...payload};
    this.#record=immutable({...this.#record,events:[...this.#record.events,event]});return event;
  }
  linkEvidence(evidence_id,metadata){
    const id=required(evidence_id,'evidence_id');this.#evidenceRepository.get(id);
    this.#append('evidence_linked',{evidence_id:id},metadata);return this.project(metadata.occurred_at);
  }
  changeSeverity(input,metadata,capability){
    const severity=computeSeverity(this.#record.finding_type,input,this.#record.severity_policy,{capability,evidenceRepository:this.#evidenceRepository,controlRepository:this.#controlRepository,findingControlRefs:this.#record.control_refs,occurredAt:metadata.occurred_at});
    this.#append('severity_changed',{severity},metadata);return this.project(metadata.occurred_at);
  }
  linkAction(action_id,metadata){this.#append('action_linked',{action_id:required(action_id,'action_id')},metadata);return this.project(metadata.occurred_at);}
  assignOwner(owner,metadata,capability){
    const value=validateOwner(owner);
    if(metadata.actor.type==='system'){
      if(capability!==undefined||value.type!=='queue'||value.id!==this.#queueRules[this.#record.rule_id])throw Error('System may assign only the rule-defined queue');
    }else if(capability!==reviewCapability)throw Error('Human review capability required');
    this.#append('owner_assigned',{owner:value},metadata);return this.project(metadata.occurred_at);
  }
  dispose(disposition,details,metadata,capability){
    if(capability!==reviewCapability)throw Error('Human review capability required');
    if(!Object.values(FindingDisposition).includes(disposition))throw Error('Invalid disposition');
    const currentState=this.project(metadata.occurred_at).current_state;
    if(disposition==='reopened'&&currentState!==FindingState.closed)throw Error('Closed finding required before reopen');
    if(disposition!=='reopened'&&currentState!==FindingState.open)throw Error('Open finding required before disposition');
    const allowed=disposition==='risk_accepted'?['acceptance_expires_at']:disposition==='duplicate'?['canonical_finding_id']:[];
    if(!details||Object.keys(details).some(key=>!allowed.includes(key)))throw Error('Unexpected disposition details');
    const payload={disposition,acceptance_expires_at:null,canonical_finding_id:null};
    if(disposition==='risk_accepted'){
      payload.acceptance_expires_at=utc(details.acceptance_expires_at,'acceptance_expires_at');
      if(Date.parse(payload.acceptance_expires_at)<=Date.parse(metadata.occurred_at))throw Error('Risk acceptance expiry must follow disposition');
    }
    if(disposition==='duplicate')payload.canonical_finding_id=required(details.canonical_finding_id,'canonical_finding_id');
    this.#append('disposition',payload,metadata);return this.project(metadata.occurred_at);
  }
  supersede(event_id,replacement,metadata,capability){
    if(capability!==reviewCapability)throw Error('Human review capability required');
    const original=this.#record.events.find(event=>event.event_id===event_id);if(!original)throw Error('Unknown finding event');
    if(this.#record.events.some(event=>event.supersedes_event_id===event_id))throw Error('Finding event already superseded');
    if(!replacement||replacement.type!==original.type)throw Error('Replacement event type must match');
    const allowed={identified:['type','evidence_id','severity_input'],evidence_linked:['type','evidence_id'],owner_assigned:['type','owner'],severity_changed:['type','severity_input'],action_linked:['type','action_id'],disposition:['type','disposition','acceptance_expires_at','canonical_finding_id']}[original.type];
    if(Object.keys(replacement).some(key=>!allowed.includes(key)))throw Error('Unexpected replacement event field');
    let payload;
    if(original.type==='evidence_linked'){
      const evidence_id=required(replacement.evidence_id,'evidence_id');this.#evidenceRepository.get(evidence_id);payload={evidence_id};
    }else if(original.type==='identified'){
      const evidence_id=required(replacement.evidence_id,'evidence_id');this.#evidenceRepository.get(evidence_id);
      payload={evidence_id,severity:computeSeverity(this.#record.finding_type,replacement.severity_input,this.#record.severity_policy,{capability,evidenceRepository:this.#evidenceRepository,controlRepository:this.#controlRepository,findingControlRefs:this.#record.control_refs,occurredAt:metadata.occurred_at})};
    }else if(original.type==='owner_assigned')payload={owner:validateOwner(replacement.owner)};
    else if(original.type==='severity_changed')payload={severity:computeSeverity(this.#record.finding_type,replacement.severity_input,this.#record.severity_policy,{capability,evidenceRepository:this.#evidenceRepository,controlRepository:this.#controlRepository,findingControlRefs:this.#record.control_refs,occurredAt:metadata.occurred_at})};
    else if(original.type==='action_linked')payload={action_id:required(replacement.action_id,'action_id')};
    else{
      if(!Object.values(FindingDisposition).includes(replacement.disposition))throw Error('Invalid disposition');
      payload={disposition:replacement.disposition,acceptance_expires_at:null,canonical_finding_id:null};
      if(replacement.disposition==='risk_accepted'){
        payload.acceptance_expires_at=utc(replacement.acceptance_expires_at,'acceptance_expires_at');
        if(Date.parse(payload.acceptance_expires_at)<=Date.parse(metadata.occurred_at))throw Error('Risk acceptance expiry must follow disposition');
        if(replacement.canonical_finding_id!==undefined)throw Error('Unexpected replacement event field');
      }else if(replacement.disposition==='duplicate'){
        payload.canonical_finding_id=required(replacement.canonical_finding_id,'canonical_finding_id');
        if(replacement.acceptance_expires_at!==undefined)throw Error('Unexpected replacement event field');
      }else if(replacement.acceptance_expires_at!==undefined||replacement.canonical_finding_id!==undefined)throw Error('Unexpected replacement event field');
    }
    this.#append(original.type,payload,metadata,event_id);return this.project(metadata.occurred_at);
  }
  project(as_of){
    utc(as_of,'as_of');if(Date.parse(as_of)<Date.parse(this.#record.created_at))throw Error('as_of precedes finding');
    const visible=this.#record.events.filter(event=>Date.parse(event.occurred_at)<=Date.parse(as_of));
    const superseded=new Set(visible.map(event=>event.supersedes_event_id).filter(id=>id!==null));
    const active=visible.filter(event=>!superseded.has(event.event_id));
    const last=type=>active.filter(event=>event.type===type).at(-1)||null;
    const severityEvent=active.filter(event=>event.type==='identified'||event.type==='severity_changed').at(-1);
    const ownerEvent=last('owner_assigned'),dispositionEvent=last('disposition');
    let state=FindingState.open,disposition=null;
    if(dispositionEvent){
      disposition=dispositionEvent.disposition;
      if(disposition!=='reopened'&&(disposition!=='risk_accepted'||Date.parse(as_of)<Date.parse(dispositionEvent.acceptance_expires_at)))state=FindingState.closed;
    }
    const severity=severityEvent.severity.severity,remediate_by=addDays(this.#record.created_at,this.#record.sla_policy.bands[severity]);
    const evidence_ids=[...new Set(active.flatMap(event=>[
      ...('evidence_id'in event?[event.evidence_id]:[]),
      ...Object.values(event.severity?.modifier_support??{}).flatMap(item=>item.evidence_ids??[])
    ]))];
    const action_refs=[...new Set(active.filter(event=>event.type==='action_linked').map(event=>event.action_id))];
    return immutable({...this.#record,events:visible,as_of,current_state:state,owner:ownerEvent?.owner??null,severity,remediate_by,
      disposition,acceptance_expires_at:dispositionEvent?.acceptance_expires_at??null,canonical_finding_id:dispositionEvent?.canonical_finding_id??null,
      evidence_ids,action_refs,
      sla_status:state==='open'&&Date.parse(as_of)>Date.parse(remediate_by)?'overdue':state==='open'?'within_sla':'closed'
    });
  }
}

export function createFindingRepository({evidenceRepository=createEvidenceRepository(),controlRepository=null,severityPolicies=DEFAULT_SEVERITY_POLICIES,slaPolicies=DEFAULT_SLA_POLICIES,queueRules={}}={}){
  const findings=new Map(),policies=severityPolicies.map(validateSeverityPolicy),slas=slaPolicies.map(validateSlaPolicy),rules=immutable(queueRules);
  const find=id=>{const finding=findings.get(id);if(!finding)throw Error('Unknown finding');return finding;};
  const identify=input=>{if(findings.has(input.finding_id))throw Error('Duplicate finding');const finding=new Finding(input,{evidenceRepository,controlRepository,severityPolicies:policies,slaPolicies:slas,queueRules:rules});findings.set(input.finding_id,finding);return finding.project(input.created_at);};
  const get=(id,as_of)=>find(id).project(as_of),list=as_of=>{
    utc(as_of,'as_of');
    return immutable([...findings.values()].filter(finding=>Date.parse(finding.createdAt)<=Date.parse(as_of)).map(finding=>finding.project(as_of)));
  };
  const agent=Object.freeze({identify,get,list,
    linkEvidence:(id,evidence_id,metadata)=>find(id).linkEvidence(evidence_id,agentMetadata(metadata)),
    changeSeverity:(id,input,metadata)=>find(id).changeSeverity(input,agentMetadata(metadata)),
    linkAction:(id,action_id,metadata)=>find(id).linkAction(action_id,agentMetadata(metadata))
  });
  const review=Object.freeze({get,list,
    linkEvidence:(id,evidence_id,metadata)=>find(id).linkEvidence(evidence_id,personMetadata(metadata)),
    changeSeverity:(id,input,metadata)=>find(id).changeSeverity(input,personMetadata(metadata),reviewCapability),
    linkAction:(id,action_id,metadata)=>find(id).linkAction(action_id,personMetadata(metadata)),
    assignOwner:(id,owner,metadata)=>find(id).assignOwner(owner,personMetadata(metadata),reviewCapability),
    dispose:(id,disposition,details,metadata)=>find(id).dispose(disposition,details,personMetadata(metadata),reviewCapability),
    supersede:(id,event_id,replacement,metadata)=>find(id).supersede(event_id,replacement,personMetadata(metadata),reviewCapability)
  });
  const system=Object.freeze({get,list,assignQueue:(id,metadata)=>{
    if(!metadata||Object.keys(metadata).some(key=>!['occurred_at','reason'].includes(key)))throw Error('Unexpected system event metadata');
    const finding=find(id),record=finding.project(metadata.occurred_at),owner={type:'queue',id:rules[record.rule_id]};
    return finding.assignOwner(owner,{actor:actor('system','rule-queue-assignment'),occurred_at:utc(metadata.occurred_at,'occurred_at'),reason:required(metadata.reason,'reason')});
  }});
  return Object.freeze({agent,review,system,indicators:as_of=>findingIndicators(list(as_of),as_of)});
}

export function findingIndicators(projectedFindings,as_of){
  utc(as_of,'as_of');if(!Array.isArray(projectedFindings))throw Error('Projected findings required');
  const open=Object.fromEntries(severityOrder.map(level=>[level,0])),overdue=Object.fromEntries(severityOrder.map(level=>[level,0]));
  for(const finding of projectedFindings){
    if(finding.as_of!==as_of)throw Error('Finding projection as_of mismatch');
    if(finding.current_state==='open'){
      open[finding.severity]++;
      if(Date.parse(as_of)>Date.parse(finding.remediate_by))overdue[finding.severity]++;
    }
  }
  return immutable({as_of,open_findings_by_severity:open,overdue_findings_by_severity:overdue});
}
