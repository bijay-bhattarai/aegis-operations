const ROUTE_PATTERN=/^#(overview|approvals|findings|controls|audit)(?:\/(action|finding|control|event)\/([^/]*))?$/;

const LABELS={action:'Action',finding:'Finding',control:'Control',event:'Audit event'};

export function resolveAppRoute(hash,recordIds={}){
  const match=String(hash).match(ROUTE_PATTERN);
  if(!match)return {parent:'overview',redirect:true};
  const [,parent,recordType,id]=match;
  if(!recordType)return {parent,redirect:false};
  const knownIds=recordIds[recordType]??[];
  if(!id||!knownIds.includes(id)){
    return {parent,redirect:true,notice:`${LABELS[recordType]} record was not found.`};
  }
  return {parent,recordType,id,redirect:false};
}
