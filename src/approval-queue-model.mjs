const queueStatuses=Object.freeze(new Set(['proposed','pending_approval']));
const severityRank=Object.freeze({critical:4,high:3,medium:2,low:1});
const immutable=value=>Object.freeze({...value,control_refs:Object.freeze([...value.control_refs]),linked_finding_ids:Object.freeze([...value.linked_finding_ids])});

export function approvalQueue(actions,projectedFindings){
  if(!Array.isArray(actions)||!Array.isArray(projectedFindings))throw Error('Actions and projected findings required');
  const findingIdsByAction=new Map();
  for(const finding of projectedFindings){
    if(!Array.isArray(finding.action_refs))throw Error('Projected finding action_refs required');
    for(const actionId of finding.action_refs){
      const ids=findingIdsByAction.get(actionId)??[];
      ids.push(finding.finding_id);findingIdsByAction.set(actionId,ids);
    }
  }
  return Object.freeze(actions.filter(action=>queueStatuses.has(action.status)).map(action=>immutable({
    ...action,linked_finding_ids:[...(findingIdsByAction.get(action.action_id)??[])].sort()
  })).sort((left,right)=>severityRank[right.severity]-severityRank[left.severity]||Date.parse(left.proposed_at)-Date.parse(right.proposed_at)||left.action_id.localeCompare(right.action_id)));
}
