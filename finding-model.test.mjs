import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  FindingType,FindingState,FindingDisposition,FindingEventType,FindingActorType,Severity,
  DEFAULT_SEVERITY_POLICIES,DEFAULT_SLA_POLICIES,createFindingRepository,findingIndicators
} from './src/finding-model.mjs';
import {createEvidenceRepository} from './src/evidence-model.mjs';
import {createControlRepository,coverage,coverageStatement} from './src/control-model.mjs';
import {createDemoOverview,OVERVIEW_AS_OF} from './src/demo-overview-model.mjs';

const artifact=value=>({type:'log_query',locator:'artifact://session/finding/'+value,content_hash:{algorithm:'sha256',value:value.repeat(64)}});
const evidence=id=>({evidence_id:id,source:'Defender',collected_by:{type:'agent',id:'vuln'},collected_at:'2026-09-01T00:00:00Z',artifact_ref:artifact(id==='E1'?'a':'b')});
const ssvc=(overrides={})=>({ssvc:{exploitation:'active',automatable:'yes',technical_impact:'total',mission_prevalence:'essential',public_wellbeing_impact:'material',...overrides},modifiers:[]});
const matrix=(likelihood='medium',impact='medium',modifiers=[])=>({risk_matrix:{likelihood,impact},modifiers});
const createSetup=options=>{
 const evidenceRepository=createEvidenceRepository();evidenceRepository.add(evidence('E1'));evidenceRepository.add(evidence('E2'));
 const findings=createFindingRepository({evidenceRepository,queueRules:{'VUL-1':'vulnerability-review','GEN-1':'general-review'},...options});
 return {evidenceRepository,findings};
};
const vulnerability={finding_id:'F-1',rule_id:'VUL-1',finding_type:'vulnerability',title:'Gateway package observation',control_refs:['C-1'],evidence_id:'E1',created_at:'2026-09-01T00:00:00Z',severity_input:ssvc(),agent_id:'vuln'};
const human=(occurred_at='2026-09-02T00:00:00Z')=>({actor_id:'reviewer-1',occurred_at,reason:'Reviewed evidence'});
const agent=(occurred_at='2026-09-02T00:00:00Z')=>({agent_id:'vuln',occurred_at,reason:'Additional observation'});

test('finding enums and initial projection come only from the ordered event log',()=>{
 const {findings}=createSetup(),record=findings.agent.identify(vulnerability);
 assert.deepEqual(Object.values(FindingType),['vulnerability','incident','identity','compliance','configuration','other']);
 assert.deepEqual(Object.values(FindingState),['open','closed']);
 assert.deepEqual(Object.values(FindingDisposition),['remediated','false_positive','risk_accepted','duplicate','reopened']);
 assert.deepEqual(Object.values(FindingEventType),['identified','evidence_linked','owner_assigned','severity_changed','action_linked','disposition']);
 assert.deepEqual(Object.values(FindingActorType),['agent','person','system']);
 assert.deepEqual(Object.values(Severity),['low','medium','high','critical']);
 assert.equal(record.current_state,'open');assert.deepEqual(record.owner,{type:'queue',id:'vulnerability-review'});
 assert.equal(record.severity,'critical');assert.equal(record.remediate_by,'2026-09-08T00:00:00.000Z');
 assert.deepEqual(record.events.map(event=>event.type),['identified','owner_assigned']);
 assert.deepEqual(record.events.map(event=>event.event_id),[1,2]);
 assert.throws(()=>{record.events.push({});},TypeError);assert.throws(()=>{record.owner.id='changed';},TypeError);
});

test('vulnerability severity policy pins the SSVC tree, decision points and mapping version',()=>{
 const policy=DEFAULT_SEVERITY_POLICIES.find(item=>item.finding_type==='vulnerability');
 assert.equal(policy.method,'ssvc');assert.equal(policy.ssvc_decision_tree_version,'CISA Coordinator v2.0.3');
 assert.equal(policy.application_mapping_version,'aegis-ssvc-severity-1');
 assert.deepEqual(Object.keys(policy.permitted_decision_points),['exploitation','automatable','technical_impact','mission_prevalence','public_wellbeing_impact']);
 const {findings}=createSetup(),record=findings.agent.identify(vulnerability);
 assert.deepEqual(record.severity_policy,policy);
});

test('vulnerabilities use SSVC exclusively and other findings use the risk matrix exclusively',()=>{
 const {findings}=createSetup();
 assert.throws(()=>findings.agent.identify({...vulnerability,severity_input:matrix()}),/SSVC inputs exclusively/);
 assert.throws(()=>findings.agent.identify({...vulnerability,severity_input:{...ssvc(),risk_matrix:{likelihood:'high',impact:'high'}}}),/cannot both appear/);
 const general={...vulnerability,finding_id:'F-2',rule_id:'GEN-1',finding_type:'identity',severity_input:matrix('high','medium',['regulated_data']),agent_id:'identity'};
 const record=findings.agent.identify(general);assert.equal(record.severity,'critical');
 assert.throws(()=>findings.agent.identify({...general,finding_id:'F-3',severity_input:ssvc()}),/risk matrix inputs exclusively/);
 assert.throws(()=>findings.agent.identify({...general,finding_id:'F-4',severity_input:{...matrix(),ssvc:ssvc().ssvc}}),/cannot both appear/);
});

test('every repository projection and indicator calculation requires an explicit as_of',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);
 assert.throws(()=>findings.agent.get('F-1'),/as_of is required/);
 assert.throws(()=>findings.agent.list(),/as_of is required/);
 assert.throws(()=>findings.indicators(),/as_of is required/);
 assert.throws(()=>findingIndicators(findings.agent.list('2026-09-02T00:00:00Z')),/as_of is required/);
 assert.doesNotMatch(fs.readFileSync('src/finding-model.mjs','utf8'),/Date\.now\s*\(|new Date\s*\(\s*\)/);
});

test('evidence is linked by global ID and unknown evidence is rejected atomically',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);
 const before=findings.agent.get('F-1','2026-09-02T00:00:00Z');
 assert.throws(()=>findings.agent.linkEvidence('F-1','missing',agent()),/Unknown evidence/);
 assert.deepEqual(findings.agent.get('F-1','2026-09-02T00:00:00Z'),before);
 const after=findings.agent.linkEvidence('F-1','E2',agent());
 assert.deepEqual(after.evidence_ids,['E1','E2']);assert.equal('evidence' in after,false);
});

test('system cannot assign a person owner',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);
 assert.equal(findings.system.assignOwner,undefined);
 assert.deepEqual(findings.system.assignQueue('F-1',{occurred_at:'2026-09-02T00:00:00Z',reason:'Apply rule queue'},{type:'person',id:'intruder'}).owner,{type:'queue',id:'vulnerability-review'});
});
test('system cannot record a disposition',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);assert.equal(findings.system.dispose,undefined);
});
test('system cannot supersede any event',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);assert.equal(findings.system.supersede,undefined);
});
test('system cannot link evidence',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);assert.equal(findings.system.linkEvidence,undefined);
});

test('human ownership, disposition and supersede capabilities are absent from the agent port',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);
 for(const method of ['assignOwner','dispose','supersede'])assert.equal(findings.agent[method],undefined);
 const assigned=findings.review.assignOwner('F-1',{type:'person',id:'owner-1'},human());assert.deepEqual(assigned.owner,{type:'person',id:'owner-1'});
});

test('agents cannot apply severity-reducing modifiers even when they cite evidence',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);
 const reduction={...ssvc(),modifiers:['isolated_nonproduction'],modifier_support:{isolated_nonproduction:{evidence_ids:['E2']}}};
 assert.throws(()=>findings.agent.changeSeverity('F-1',reduction,agent()),/Human review capability required for severity-reducing modifiers/);
 assert.equal(findings.agent.get('F-1','2026-09-02T00:00:00Z').severity,'critical');
});

test('human severity reductions require cited evidence for every reducing modifier',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);
 const unsupported={...ssvc(),modifiers:['compensating_control','isolated_nonproduction']};
 assert.throws(()=>findings.review.changeSeverity('F-1',unsupported,human()),/Evidence required for severity-reducing modifier/);
 const supported={...ssvc(),modifiers:['isolated_nonproduction'],modifier_support:{isolated_nonproduction:{evidence_ids:['E2']}}};
 const record=findings.review.changeSeverity('F-1',supported,human());
 assert.equal(record.severity,'high');assert.deepEqual(record.evidence_ids,['E1','E2']);
});

test('compensating_control requires a referenced control with tested_pass current at occurred_at',()=>{
 const evidenceRepository=createEvidenceRepository();evidenceRepository.add(evidence('E1'));evidenceRepository.add(evidence('E2'));
 const controls=createControlRepository({evidenceRepository});
 controls.add({control_id:'C-1',name:'Compensating control',cycle_id:'2026-09',cycle_start:'2026-09-01T00:00:00Z',cycle_end:'2026-10-01T00:00:00Z'});
 controls.agent.collect('C-1',evidence('E1'));
 const findings=createFindingRepository({evidenceRepository,controlRepository:controls,queueRules:{'VUL-1':'vulnerability-review'}});
 findings.agent.identify(vulnerability);
 const reduction={...ssvc(),modifiers:['compensating_control'],modifier_support:{compensating_control:{evidence_ids:['E2'],control_refs:['C-1']}}};
 assert.throws(()=>findings.review.changeSeverity('F-1',reduction,human('2026-09-01T12:00:00Z')),/current human-recorded tested_pass/);
 controls.reviewer.assess('C-1','tested_pass',{assessor:'reviewer-1',assessed_at:'2026-09-02T00:00:00Z',assessment_rationale:'Observed test result'});
 const record=findings.review.changeSeverity('F-1',reduction,human('2026-09-03T00:00:00Z'));
 assert.equal(record.severity,'high');assert.deepEqual(record.events.at(-1).severity.modifier_support.compensating_control.control_refs,['C-1']);
});

test('compensating_control rejects controls outside the finding control references',()=>{
 const evidenceRepository=createEvidenceRepository();evidenceRepository.add(evidence('E1'));evidenceRepository.add(evidence('E2'));
 const controls=createControlRepository({evidenceRepository});
 controls.add({control_id:'C-2',name:'Other control',cycle_id:'2026-09',cycle_start:'2026-09-01T00:00:00Z',cycle_end:'2026-10-01T00:00:00Z'});
 controls.agent.collect('C-2',evidence('E1'));controls.reviewer.assess('C-2','tested_pass',{assessor:'reviewer-1',assessed_at:'2026-09-02T00:00:00Z',assessment_rationale:'Observed test result'});
 const findings=createFindingRepository({evidenceRepository,controlRepository:controls,queueRules:{'VUL-1':'vulnerability-review'}});findings.agent.identify(vulnerability);
 const reduction={...ssvc(),modifiers:['compensating_control'],modifier_support:{compensating_control:{evidence_ids:['E2'],control_refs:['C-2']}}};
 assert.throws(()=>findings.review.changeSeverity('F-1',reduction,human('2026-09-03T00:00:00Z')),/must be referenced by the finding/);
});

test('supersede appends a replacement and retains the original event byte-identically',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);
 findings.agent.changeSeverity('F-1',ssvc({exploitation:'none',automatable:'no',technical_impact:'partial',mission_prevalence:'minimal',public_wellbeing_impact:'minimal'}),agent());
 const before=findings.agent.get('F-1','2026-09-02T00:00:00Z'),originalBytes=JSON.stringify(before.events[2]);
 const after=findings.review.supersede('F-1',3,{type:'severity_changed',severity_input:ssvc({exploitation:'poc',automatable:'no',technical_impact:'total',mission_prevalence:'support',public_wellbeing_impact:'minimal'})},human('2026-09-03T00:00:00Z'));
 assert.equal(JSON.stringify(after.events[2]),originalBytes);assert.equal(after.events[3].supersedes_event_id,3);
 assert.equal(after.severity,'medium');assert.equal(after.events.length,4);
});

test('supersede rejects replacement attempts that inject event identity or actor metadata',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);
 findings.agent.changeSeverity('F-1',ssvc({exploitation:'none'}),agent());
 const before=findings.agent.get('F-1','2026-09-03T00:00:00Z');
 assert.throws(()=>findings.review.supersede('F-1',3,{type:'severity_changed',severity_input:ssvc(),actor:{type:'system',id:'rule-queue-assignment'},event_id:99},human('2026-09-03T00:00:00Z')),/Unexpected replacement event field/);
 assert.deepEqual(findings.agent.get('F-1','2026-09-03T00:00:00Z'),before);
});

test('risk acceptance expiry returns a finding to open and overdue counts during replay',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);
 findings.review.dispose('F-1','risk_accepted',{acceptance_expires_at:'2026-09-20T00:00:00Z'},human());
 const accepted=findings.agent.get('F-1','2026-09-10T00:00:00Z'),atExpiry=findings.agent.get('F-1','2026-09-20T00:00:00Z'),expired=findings.agent.get('F-1','2026-09-21T00:00:00Z');
 assert.equal(accepted.current_state,'closed');assert.equal(accepted.sla_status,'closed');
 assert.equal(atExpiry.current_state,'open');
 assert.equal(expired.current_state,'open');assert.equal(expired.sla_status,'overdue');assert.equal(expired.events.length,3);
 assert.deepEqual(findings.indicators('2026-09-21T00:00:00Z').overdue_findings_by_severity,{low:0,medium:0,high:0,critical:1});
});

test('a human can reopen a closed finding with a reason',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);
 findings.review.dispose('F-1','remediated',{},human());
 assert.throws(()=>findings.review.dispose('F-1','reopened',{}, {actor_id:'reviewer-1',occurred_at:'2026-09-03T00:00:00Z'}),/reason is required/);
 const reopened=findings.review.dispose('F-1','reopened',{},human('2026-09-03T00:00:00Z'));
 assert.equal(reopened.current_state,'open');assert.equal(reopened.disposition,'reopened');
 assert.equal(reopened.events.at(-1).reason,'Reviewed evidence');
});

test('a replacement event can itself be superseded in a human-recorded chain',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);
 findings.agent.changeSeverity('F-1',ssvc({exploitation:'none'}),agent());
 findings.review.supersede('F-1',3,{type:'severity_changed',severity_input:ssvc({exploitation:'poc',automatable:'no',technical_impact:'total',mission_prevalence:'support',public_wellbeing_impact:'minimal'})},human('2026-09-03T00:00:00Z'));
 const record=findings.review.supersede('F-1',4,{type:'severity_changed',severity_input:ssvc()},human('2026-09-04T00:00:00Z'));
 assert.deepEqual(record.events.slice(2).map(event=>event.supersedes_event_id),[null,3,4]);assert.equal(record.severity,'critical');
});

test('current evidence and action references both derive only from active events',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);
 findings.review.supersede('F-1',1,{type:'identified',evidence_id:'E2',severity_input:ssvc()},human());
 findings.agent.linkAction('F-1','ACT-OLD',agent('2026-09-03T00:00:00Z'));
 const record=findings.review.supersede('F-1',4,{type:'action_linked',action_id:'ACT-NEW'},human('2026-09-04T00:00:00Z'));
 assert.deepEqual(record.evidence_ids,['E2']);assert.deepEqual(record.action_refs,['ACT-NEW']);
 assert.equal(record.events[0].evidence_id,'E1');assert.equal(record.events[2].evidence_id,'E2');
});

test('duplicate is a canonical link on a normal closed disposition',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);
 const record=findings.review.dispose('F-1','duplicate',{canonical_finding_id:'F-0'},human());
 assert.equal(record.current_state,'closed');assert.equal(record.disposition,'duplicate');assert.equal(record.canonical_finding_id,'F-0');
 assert.throws(()=>findings.review.dispose('F-1','remediated',{},human('2026-09-03T00:00:00Z')),/Open finding required/);
 assert.equal(findings.agent.get('F-1','2026-09-03T00:00:00Z').events.length,3);
});

test('SLA stays anchored to created_at and uses severity effective at as_of',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);
 findings.agent.changeSeverity('F-1',ssvc({exploitation:'none',automatable:'no',technical_impact:'partial',mission_prevalence:'minimal',public_wellbeing_impact:'minimal'}),agent('2026-09-05T00:00:00Z'));
 const before=findings.agent.get('F-1','2026-09-04T00:00:00Z'),after=findings.agent.get('F-1','2026-09-05T00:00:00Z');
 assert.equal(before.severity,'critical');assert.equal(before.remediate_by,'2026-09-08T00:00:00.000Z');
 assert.equal(after.severity,'low');assert.equal(after.remediate_by,'2026-11-30T00:00:00.000Z');
 assert.equal(after.created_at,'2026-09-01T00:00:00Z');
});

test('rule-specific SLA overrides are versioned and pinned into the record',()=>{
 const slaPolicies=[{policy_id:'vul-override',version:'7',rule_id:'VUL-1',bands:{critical:3,high:10,medium:20,low:60}},...DEFAULT_SLA_POLICIES];
 const {findings}=createSetup({slaPolicies});const record=findings.agent.identify(vulnerability);
 assert.equal(record.sla_policy.policy_id,'vul-override');assert.equal(record.sla_policy.version,'7');
 assert.equal(record.remediate_by,'2026-09-04T00:00:00.000Z');
});

test('one finding can retain zero or many action references without changing actions',()=>{
 const {findings}=createSetup();let record=findings.agent.identify(vulnerability);assert.deepEqual(record.action_refs,[]);
 record=findings.agent.linkAction('F-1','ACT-1',agent());record=findings.review.linkAction('F-1','ACT-2',human('2026-09-03T00:00:00Z'));
 assert.deepEqual(record.action_refs,['ACT-1','ACT-2']);
});

test('historical lists omit findings that did not yet exist',()=>{
 const {findings}=createSetup();findings.agent.identify(vulnerability);
 findings.agent.identify({...vulnerability,finding_id:'F-2',created_at:'2026-09-10T00:00:00Z'});
 assert.deepEqual(findings.agent.list('2026-09-05T00:00:00Z').map(item=>item.finding_id),['F-1']);
});

test('the fabricated 24-hour SLA label is absent from authored application source',()=>{
 assert.doesNotMatch(fs.readFileSync('src/index.html','utf8'),/VUL-SLA-001 · 24-hour remediation/);
});

test('dashboard indicators share one explicit as_of and are computed from repository records',()=>{
 const html=fs.readFileSync('src/index.html','utf8'),demo=fs.readFileSync('src/demo-overview-model.mjs','utf8');
 assert.equal((demo.match(/export const OVERVIEW_AS_OF=/g)||[]).length,1);
 assert.match(html,/OVERVIEW_AS_OF as overviewAsOf/);
 assert.match(html,/const findingCounts=findingIndicators\(findingRepo\.agent\.list\(overviewAsOf\),overviewAsOf\)/);
 assert.match(html,/const controlCounts=coverage\(records,cycle\.cycle_id\),statement=coverageStatement\(controlCounts\)/);
 for(const indicator of ['control-coverage','open-findings','overdue-findings'])assert.match(html,new RegExp('data-indicator="'+indicator+'"'));
 assert.equal((html.match(/<div class="metric-label">As of /g)||[]).length,3);
 assert.doesNotMatch(html,/id="coverage-metrics"/);
});

test('dashboard demo findings cover every severity, closure, overdue state and expired acceptance',()=>{
 const {controlRepo,findingRepo,cycle,as_of}=createDemoOverview();
 assert.equal(as_of,OVERVIEW_AS_OF);
 assert.equal(coverageStatement(coverage(controlRepo.agent.list(),cycle.cycle_id)),'5 controls in scope. 2 tested this cycle, 1 passed, 1 failed, 3 not yet tested.');
 assert.equal(controlRepo.agent.get('CTRL-01').status,'tested_pass');assert.equal(controlRepo.agent.get('CTRL-01').assessor,'Demo reviewer');
 assert.equal(controlRepo.agent.get('CTRL-04').status,'tested_fail');assert.equal(controlRepo.agent.get('CTRL-04').assessor,'Demo reviewer');
 assert.equal(controlRepo.agent.get('CTRL-02').status,'evidence_collected');
 const indicators=findingIndicators(findingRepo.agent.list(as_of),as_of);
 assert.deepEqual(indicators.open_findings_by_severity,{low:1,medium:1,high:1,critical:1});
 assert.deepEqual(indicators.overdue_findings_by_severity,{low:0,medium:1,high:1,critical:1});
 const expired=findingRepo.agent.get('F-DEMO-MEDIUM',as_of),closed=findingRepo.agent.get('F-DEMO-CLOSED',as_of);
 assert.equal(expired.disposition,'risk_accepted');assert.equal(expired.current_state,'open');
 assert.equal(closed.current_state,'closed');
});

test('dashboard prominence ranks not_assessed above overdue and overdue above open',()=>{
 const html=fs.readFileSync('src/index.html','utf8');
 assert.match(html,/\.metric\.open-findings\{border-width:1px\}/);
 assert.match(html,/\.metric\.overdue-findings\{border:2px solid var\(--red\);[^}]*padding:17px/);
 assert.match(html,/\.metric\.unknown\{[^}]*padding:20px;border:3px solid/);
 assert.match(html,/#control-list button\[data-status=not_assessed\]\{[^}]*border:3px solid/);
});

test('overview headline greets and orients without duplicating the coverage statement',()=>{
 const html=fs.readFileSync('src/index.html','utf8');
 assert.match(html,/<h2 id="overview-title">Welcome back, Bijay\.<\/h2>/);
 assert.match(html,/Review control coverage, open findings, and overdue work at the shared snapshot below\./);
 assert.doesNotMatch(html,/#overview-title'\)\.textContent=statement/);
});

test('agent tiles describe roles with readable statuses and avoid repeated overview dates',()=>{
 const html=fs.readFileSync('src/index.html','utf8'),tiles=html.slice(html.indexOf('<div class="agent-list"'),html.indexOf('<div class="agent-detail"'));
 for(const copy of ['Correlates identity, endpoint, cloud, and network evidence','Prioritizes exposure evidence with SSVC','Reviews sign-ins, privileges, and access evidence','Maps collected evidence to control criteria','Drafts detection changes with rollback guidance'])assert.match(tiles,new RegExp(copy));
 assert.match(tiles,/Ready for review/);assert.match(tiles,/Awaiting approval/);
 assert.doesNotMatch(tiles,/Observed rule proposal|September 2026 UTC/);
 assert.doesNotMatch(html,/<h3>Control records · September 2026 UTC<\/h3>|cycle September 2026 UTC<\/small>/);
});
