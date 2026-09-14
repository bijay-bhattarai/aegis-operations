import {createControlRepository} from './control-model.mjs';
import {createEvidenceRepository} from './evidence-model.mjs';
import {createFindingRepository} from './finding-model.mjs';
import {ENTRA_FINDING_SEEDS,ENTRA_QUEUE_RULES,ENTRA_SNAPSHOT} from './entra-finding-seeds.mjs';

export const OVERVIEW_AS_OF='2026-09-14T23:00:00Z';
export const OVERVIEW_CYCLE=Object.freeze({cycle_id:'2026-09',cycle_start:'2026-09-01T00:00:00Z',cycle_end:'2026-10-01T00:00:00Z'});
const severityRank=Object.freeze({critical:4,high:3,medium:2,low:1});

export function sortOverviewFindings(findings){
  return [...findings].sort((left,right)=>
    Number(right.sla_status==='overdue')-Number(left.sla_status==='overdue')||
    severityRank[right.severity]-severityRank[left.severity]||
    left.finding_id.localeCompare(right.finding_id)
  );
}

export function createDemoOverview(){
  const evidenceRepo=createEvidenceRepository(),controlRepo=createControlRepository({evidenceRepository:evidenceRepo});
  for(const [control_id,name] of [['CTRL-01','Sign-in review'],['CTRL-02','Exposure review'],['CTRL-03','Access review'],['CTRL-04','SOC 2 CC6.1 evidence'],['CTRL-05','Detection review']])controlRepo.add({control_id,name,...OVERVIEW_CYCLE});
  for(const id of ['CTRL-01','CTRL-04']){
    const identityControl=id==='CTRL-01';
    controlRepo.agent.collect(id,{
      evidence_id:id+'-E1',source:identityControl?'Entra ID':'GRC',
      collected_by:{type:'agent',id:identityControl?'identity':'compliance'},collected_at:'2026-09-13T20:00:00Z',
      artifact_ref:{type:identityControl?'log_query':'config_snapshot',locator:'artifact://session/demo/'+id.toLowerCase(),content_hash:{algorithm:'sha256',value:identityControl?'a'.repeat(64):'b'.repeat(64)}}
    });
  }
  controlRepo.agent.collect('CTRL-02',{
    evidence_id:'CTRL-02-E1',source:'Demo inventory',collected_by:{type:'agent',id:'vuln'},collected_at:'2026-09-13T20:00:00Z',
    artifact_ref:{type:'export',locator:'artifact://session/demo/ctrl-02',content_hash:{algorithm:'sha256',value:'d'.repeat(64)}}
  });
  controlRepo.reviewer.assess('CTRL-01','tested_pass',{assessor:'Demo reviewer',assessed_at:'2026-09-14T12:00:00Z',assessment_rationale:'Human-recorded demo test result'});
  controlRepo.reviewer.assess('CTRL-04','tested_fail',{assessor:'Demo reviewer',assessed_at:'2026-09-14T12:00:00Z',assessment_rationale:'Human-recorded demo test result'});
  evidenceRepo.add(ENTRA_SNAPSHOT);
  const findingRepo=createFindingRepository({
    evidenceRepository:evidenceRepo,controlRepository:controlRepo,
    queueRules:ENTRA_QUEUE_RULES
  });
  for(const seed of ENTRA_FINDING_SEEDS)findingRepo.agent.identify(seed);
  for(const [finding_id,action_id,agent_id] of [
    ['IAM-0008','ACT-ID-001','identity'],['IAM-0004','ACT-ID-002','identity']
  ])findingRepo.agent.linkAction(finding_id,action_id,{agent_id,occurred_at:'2026-09-13T20:30:00Z',reason:'Identity proposal linked to finding'});
  return Object.freeze({evidenceRepo,controlRepo,findingRepo,cycle:OVERVIEW_CYCLE,as_of:OVERVIEW_AS_OF,snapshot:ENTRA_SNAPSHOT});
}
