const immutable=value=>{
  if(Array.isArray(value))return Object.freeze(value.map(immutable));
  if(value&&typeof value==='object')return Object.freeze(Object.fromEntries(Object.entries(value).map(([key,item])=>[key,immutable(item)])));
  return value;
};
const utc=value=>{
  if(typeof value!=='string'||!Number.isFinite(Date.parse(value))||!value.endsWith('Z'))throw Error('as_of must be a UTC timestamp');
  return value;
};
const titleCase=value=>String(value).replace(/_/g,' ').replace(/^./,letter=>letter.toUpperCase());
const actor=(type,id)=>immutable({type,id});
const suffix=event=>event.supersedes_event_id===null?'':` Corrects event #${event.supersedes_event_id}.`;

const findingSummary=(record,event)=>{
  let summary;
  if(event.type==='identified')summary=`${record.title} identified at ${event.severity.severity} severity.`;
  else if(event.type==='evidence_linked')summary=`Evidence ${event.evidence_id} linked.`;
  else if(event.type==='owner_assigned')summary=`Owner assigned to ${event.owner.type}: ${event.owner.id}.`;
  else if(event.type==='severity_changed')summary=`Severity changed to ${event.severity.severity}.`;
  else if(event.type==='action_linked')summary=`Action ${event.action_id} linked.`;
  else if(event.type==='disposition')summary=`Disposition recorded as ${titleCase(event.disposition)}.`;
  else throw Error('Unknown finding event type');
  return summary+suffix(event);
};

const actionSummary=event=>{
  let summary;
  if(event.type==='proposed')summary=`${event.action_type} proposed for ${event.target}.`;
  else if(event.type==='submitted')summary='Submitted for human decision.';
  else if(event.type==='approved')summary=`Approved by ${event.approver}.`;
  else if(event.type==='rejected')summary=`Rejected by ${event.approver}.`;
  else if(event.type==='expired')summary='Review record expired.';
  else if(event.type==='external_execution_attested')summary=`External execution attested by ${event.executor}.`;
  else throw Error('Unknown action event type');
  return summary+suffix(event);
};

const decorateSupersession=rows=>{
  const bySourceKey=new Map(rows.map(row=>[row.source_key,row]));
  const replacedBy=new Map(rows.filter(row=>row.supersedes_source_key).map(row=>[row.supersedes_source_key,row.audit_id]));
  return rows.map(row=>immutable({...row,
    supersedes_audit_id:row.supersedes_source_key?bySourceKey.get(row.supersedes_source_key)?.audit_id??null:null,
    superseded_by_audit_id:replacedBy.get(row.source_key)??null
  }));
};

export function buildAuditLog({findingRepo,controlRepo,actionRepo},as_of){
  const snapshot=utc(as_of),rows=[];
  for(const record of findingRepo.agent.list(snapshot))for(const event of record.events){
    const source_key=`finding:${record.finding_id}:${event.event_id}`;
    rows.push({audit_id:source_key,source_key,supersedes_source_key:event.supersedes_event_id===null?null:`finding:${record.finding_id}:${event.supersedes_event_id}`,
      timestamp:event.occurred_at,actor:event.actor,event_type:event.type,record_type:'finding',record_id:record.finding_id,summary:findingSummary(record,event),payload:event});
  }
  for(const record of controlRepo.agent.list()){
    for(const evidence of record.evidence.filter(item=>Date.parse(item.collected_at)<=Date.parse(snapshot))){
      const source_key=`control:${record.control_id}:evidence:${evidence.evidence_id}`;
      rows.push({audit_id:source_key,source_key,supersedes_source_key:null,timestamp:evidence.collected_at,actor:evidence.collected_by,
        event_type:'evidence_collected',record_type:'control',record_id:record.control_id,summary:`Evidence ${evidence.evidence_id} collected from ${evidence.source}.`,payload:evidence});
    }
    for(const assessment of record.assessments.filter(item=>Date.parse(item.assessed_at)<=Date.parse(snapshot))){
      const source_key=`control:${record.control_id}:assessment:${assessment.assessment_id}`,supersedes=assessment.supersedes_assessment_id;
      rows.push({audit_id:source_key,source_key,supersedes_source_key:supersedes===null?null:`control:${record.control_id}:assessment:${supersedes}`,
        timestamp:assessment.assessed_at,actor:actor('person',assessment.assessor),event_type:supersedes===null?'assessed':'superseded',record_type:'control',record_id:record.control_id,
        summary:supersedes===null?`Assessment recorded as ${titleCase(assessment.status)}.`:`Assessment #${supersedes} superseded with ${titleCase(assessment.status)}.`,payload:assessment});
    }
  }
  for(const action of actionRepo.agent.list(snapshot))for(const event of actionRepo.agent.history(action.action_id,snapshot)){
    const source_key=`action:${action.action_id}:${event.event_id}`;
    rows.push({audit_id:source_key,source_key,supersedes_source_key:event.supersedes_event_id===null?null:`action:${action.action_id}:${event.supersedes_event_id}`,
      timestamp:event.occurred_at,actor:event.actor,event_type:event.type,record_type:'action',record_id:action.action_id,summary:actionSummary(event),payload:event});
  }
  return immutable(decorateSupersession(rows).sort((left,right)=>Date.parse(right.timestamp)-Date.parse(left.timestamp)||right.audit_id.localeCompare(left.audit_id)));
}
