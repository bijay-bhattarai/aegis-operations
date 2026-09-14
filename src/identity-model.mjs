export const AGENT_IDS = Object.freeze(['soc','vuln','identity','compliance','engineering']);

export function rejectAgentLikePersonId(id,message='Person ID cannot identify an agent'){
  const normalizedId=id.normalize('NFKC').replace(/[\u200B-\u200D\uFEFF]/g,'');
  // NFKC does not fold Cyrillic а; this narrow skeleton catches the documented casual homoglyph case.
  const agentCheckId=normalizedId.replace(/[Аа]/g,'a');
  if(AGENT_IDS.some(agentId=>agentId.toLowerCase()===agentCheckId.toLowerCase())||/agent/i.test(agentCheckId))throw Error(message);
}
