import {createControlRepository} from './control-model.mjs';
import {createEvidenceRepository} from './evidence-model.mjs';
import {createFindingRepository} from './finding-model.mjs';

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
  evidenceRepo.add({
    evidence_id:'FINDING-DEMO-E1',source:'Demo inventory',collected_by:{type:'agent',id:'vuln'},collected_at:'2026-08-01T00:00:00Z',
    artifact_ref:{type:'export',locator:'artifact://session/demo/finding-inventory',content_hash:{algorithm:'sha256',value:'c'.repeat(64)}}
  });
  const findingRepo=createFindingRepository({
    evidenceRepository:evidenceRepo,controlRepository:controlRepo,
    queueRules:{'DEMO-CRITICAL':'priority-review','DEMO-HIGH':'standard-review','DEMO-MEDIUM':'standard-review','DEMO-LOW':'standard-review','DEMO-CLOSED':'standard-review'}
  });
  const ssvc=(exploitation,automatable,technical_impact,mission_prevalence,public_wellbeing_impact)=>({ssvc:{exploitation,automatable,technical_impact,mission_prevalence,public_wellbeing_impact},modifiers:[]});
  const findingSeeds=[
    {finding_id:'F-DEMO-CRITICAL',rule_id:'DEMO-CRITICAL',finding_type:'vulnerability',title:'Critical-priority demo observation',control_refs:['CTRL-02'],evidence_id:'FINDING-DEMO-E1',created_at:'2026-09-01T00:00:00Z',severity_input:ssvc('active','yes','total','essential','material'),agent_id:'vuln'},
    {finding_id:'F-DEMO-HIGH',rule_id:'DEMO-HIGH',finding_type:'vulnerability',title:'High-priority demo observation',control_refs:['CTRL-02'],evidence_id:'FINDING-DEMO-E1',created_at:'2026-08-20T00:00:00Z',severity_input:ssvc('active','no','total','support','material'),agent_id:'vuln'},
    {finding_id:'F-DEMO-MEDIUM',rule_id:'DEMO-MEDIUM',finding_type:'vulnerability',title:'Expired acceptance demo observation',control_refs:['CTRL-02'],evidence_id:'FINDING-DEMO-E1',created_at:'2026-08-01T01:00:00Z',severity_input:ssvc('poc','no','total','support','minimal'),agent_id:'vuln'},
    {finding_id:'F-DEMO-LOW',rule_id:'DEMO-LOW',finding_type:'vulnerability',title:'Low-priority demo observation',control_refs:['CTRL-02'],evidence_id:'FINDING-DEMO-E1',created_at:'2026-09-01T00:00:00Z',severity_input:ssvc('none','no','partial','minimal','minimal'),agent_id:'vuln'},
    {finding_id:'F-DEMO-CLOSED',rule_id:'DEMO-CLOSED',finding_type:'identity',title:'Human-closed demo observation',control_refs:['CTRL-03'],evidence_id:'FINDING-DEMO-E1',created_at:'2026-09-01T00:00:00Z',severity_input:{risk_matrix:{likelihood:'high',impact:'medium'},modifiers:[]},agent_id:'identity'}
  ];
  for(const seed of findingSeeds)findingRepo.agent.identify(seed);
  findingRepo.review.dispose('F-DEMO-MEDIUM','risk_accepted',{acceptance_expires_at:'2026-09-10T00:00:00Z'},{actor_id:'demo-reviewer',occurred_at:'2026-08-02T00:00:00Z',reason:'Time-limited demo acceptance'});
  findingRepo.review.dispose('F-DEMO-CLOSED','remediated',{},{actor_id:'demo-reviewer',occurred_at:'2026-09-02T00:00:00Z',reason:'Human-recorded demo disposition'});
  for(const [finding_id,action_id,agent_id] of [
    ['F-DEMO-CRITICAL','ACT-VUL-001','vuln'],['F-DEMO-CRITICAL','ACT-SE-001','engineering'],
    ['F-DEMO-HIGH','ACT-SOC-001','soc'],['F-DEMO-MEDIUM','ACT-ID-001','identity']
  ])findingRepo.agent.linkAction(finding_id,action_id,{agent_id,occurred_at:'2026-09-13T20:30:00Z',reason:'Demo proposal linked to finding'});
  return Object.freeze({evidenceRepo,controlRepo,findingRepo,cycle:OVERVIEW_CYCLE,as_of:OVERVIEW_AS_OF});
}
