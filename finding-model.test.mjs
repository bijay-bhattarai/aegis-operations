import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {
  FindingType,FindingState,FindingDisposition,FindingEventType,FindingActorType,FindingSubjectType,Severity,
  DEFAULT_SEVERITY_POLICIES,DEFAULT_SLA_POLICIES,createFindingRepository,findingIndicators
} from './src/finding-model.mjs';
import {createEvidenceRepository} from './src/evidence-model.mjs';
import {createControlRepository,coverage,coverageStatement} from './src/control-model.mjs';
import {createDemoOverview,OVERVIEW_AS_OF,sortOverviewFindings} from './src/demo-overview-model.mjs';
import {ENTRA_FINDING_SEEDS,ENTRA_QUEUE_RULES,ENTRA_SNAPSHOT} from './src/entra-finding-seeds.mjs';
import {resolveAppRoute} from './src/route-model.mjs';
import {buildAuditLog} from './src/audit-model.mjs';
import {createActionRepository} from './src/action-model.mjs';

const artifact=value=>({type:'log_query',locator:'artifact://session/finding/'+value,content_hash:{algorithm:'sha256',value:value.repeat(64)}});
const evidence=id=>({evidence_id:id,source:'Defender',collected_by:{type:'agent',id:'vuln'},collected_at:'2026-09-01T00:00:00Z',artifact_ref:artifact(id==='E1'?'a':'b')});
const ssvc=(overrides={})=>({ssvc:{exploitation:'active',automatable:'yes',technical_impact:'total',mission_prevalence:'essential',public_wellbeing_impact:'material',...overrides},modifiers:[]});
const matrix=(likelihood='medium',impact='medium',modifiers=[])=>({risk_matrix:{likelihood,impact},modifiers});
const assetSubject={type:'asset',id:{namespace:'inventory',value:'gateway-1'},label:'Internet gateway',details:{}};
const userSubject={type:'user',id:{namespace:'microsoft_entra_id',value:'user-1'},label:'Example User',details:{principal_name:'user@example.test',department:'IT',job_title:'Engineer',privileged:false}};
const observed=[{key:'package',value:'gateway-runtime'}];
const createSetup=options=>{
 const evidenceRepository=createEvidenceRepository();evidenceRepository.add(evidence('E1'));evidenceRepository.add(evidence('E2'));
 const findings=createFindingRepository({evidenceRepository,queueRules:{'VUL-1':'vulnerability-review','GEN-1':'general-review'},...options});
 return {evidenceRepository,findings};
};
const vulnerability={finding_id:'F-1',rule_id:'VUL-1',finding_type:'vulnerability',title:'Gateway package observation',subject:assetSubject,evidence_lines:observed,control_refs:['C-1'],evidence_id:'E1',created_at:'2026-09-01T00:00:00Z',severity_input:ssvc(),agent_id:'vuln'};
const human=(occurred_at='2026-09-02T00:00:00Z')=>({actor_id:'reviewer-1',occurred_at,reason:'Reviewed evidence'});
const agent=(occurred_at='2026-09-02T00:00:00Z')=>({agent_id:'vuln',occurred_at,reason:'Additional observation'});

test('finding enums and initial projection come only from the ordered event log',()=>{
 const {findings}=createSetup(),record=findings.agent.identify(vulnerability);
 assert.deepEqual(Object.values(FindingType),['vulnerability','incident','identity','compliance','configuration','other']);
 assert.deepEqual(Object.values(FindingState),['open','closed']);
 assert.deepEqual(Object.values(FindingDisposition),['remediated','false_positive','risk_accepted','duplicate','reopened']);
 assert.deepEqual(Object.values(FindingEventType),['identified','evidence_linked','owner_assigned','severity_changed','action_linked','disposition']);
 assert.deepEqual(Object.values(FindingActorType),['agent','person','system']);
 assert.deepEqual(Object.values(FindingSubjectType),['user','asset']);
 assert.deepEqual(Object.values(Severity),['low','medium','high','critical']);
 assert.equal(record.current_state,'open');assert.deepEqual(record.owner,{type:'queue',id:'vulnerability-review'});
 assert.equal(record.severity,'critical');assert.equal(record.remediate_by,'2026-09-08T00:00:00.000Z');
 assert.deepEqual(record.events.map(event=>event.type),['identified','owner_assigned']);
 assert.deepEqual(record.events.map(event=>event.event_id),[1,2]);
 assert.deepEqual(record.subject,assetSubject);assert.deepEqual(record.evidence_lines,observed);
 assert.deepEqual(record.events[0].subject,assetSubject);assert.deepEqual(record.events[0].evidence_lines,observed);
 assert.throws(()=>{record.events.push({});},TypeError);assert.throws(()=>{record.owner.id='changed';},TypeError);
 assert.throws(()=>{record.subject.label='changed';},TypeError);assert.throws(()=>{record.evidence_lines[0].value='changed';},TypeError);
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
 const general={...vulnerability,finding_id:'F-2',rule_id:'GEN-1',finding_type:'identity',subject:userSubject,evidence_lines:[{key:'group',value:'ROLE-IT'}],severity_input:matrix('high','medium',['regulated_data']),agent_id:'identity'};
 const record=findings.agent.identify(general);assert.equal(record.severity,'critical');
 assert.throws(()=>findings.agent.identify({...general,finding_id:'F-3',severity_input:ssvc()}),/risk matrix inputs exclusively/);
 assert.throws(()=>findings.agent.identify({...general,finding_id:'F-4',severity_input:{...matrix(),ssvc:ssvc().ssvc}}),/cannot both appear/);
});

test('subjects are required and only identity-user and vulnerability-asset mappings exist',()=>{
 const {findings}=createSetup();
 assert.throws(()=>findings.agent.identify({...vulnerability,subject:undefined}),/Invalid subject/);
 assert.throws(()=>findings.agent.identify({...vulnerability,subject:userSubject}),/Subject type user is not defined for finding_type vulnerability/);
 const agents={incident:'soc',compliance:'compliance',configuration:'engineering',other:'soc'};
 for(const [finding_type,agent_id] of Object.entries(agents))assert.throws(()=>findings.agent.identify({...vulnerability,finding_id:'F-'+finding_type,rule_id:'GEN-1',finding_type,subject:assetSubject,severity_input:matrix(),agent_id}),new RegExp('Subject mapping is undefined for finding_type '+finding_type));
});

test('evidence lines are structured rule facts and cannot duplicate subject identity attributes',()=>{
 const {findings}=createSetup();
 assert.throws(()=>findings.agent.identify({...vulnerability,evidence_lines:undefined}),/evidence_lines required/);
 assert.throws(()=>findings.agent.identify({...vulnerability,evidence_lines:[]}),/evidence_lines required/);
 assert.throws(()=>findings.agent.identify({...vulnerability,evidence_lines:['package=gateway-runtime']}),/Invalid evidence line/);
 const identity={...vulnerability,finding_id:'F-2',rule_id:'GEN-1',finding_type:'identity',subject:userSubject,severity_input:matrix(),agent_id:'identity'};
 assert.throws(()=>findings.agent.identify({...identity,evidence_lines:[{key:'job_title',value:'Engineer'}]}),/duplicates a subject identity attribute/);
 assert.throws(()=>findings.agent.identify({...identity,evidence_lines:[{key:'owning_department',value:'IT'}]}),/Invalid identity evidence line key/);
 assert.doesNotThrow(()=>findings.agent.identify({...identity,evidence_lines:[{key:'account_enabled',value:false},{key:'group',value:'ROLE-IT'}]}));
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

test('subject and structured evidence facts change only through human supersede',()=>{
 const {findings}=createSetup(),initial=findings.agent.identify(vulnerability),originalBytes=JSON.stringify(initial.events[0]);
 assert.equal(findings.agent.changeSubject,undefined);assert.equal(findings.review.changeSubject,undefined);
 const replacementSubject={...assetSubject,id:{...assetSubject.id,value:'gateway-2'},label:'Replacement gateway'};
 const after=findings.review.supersede('F-1',1,{type:'identified',evidence_id:'E1',subject:replacementSubject,evidence_lines:[{key:'package',value:'replacement-runtime'}],severity_input:ssvc()},human());
 assert.equal(JSON.stringify(after.events[0]),originalBytes);assert.deepEqual(after.subject,replacementSubject);
 assert.deepEqual(after.evidence_lines,[{key:'package',value:'replacement-runtime'}]);assert.equal(after.events.at(-1).supersedes_event_id,1);
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
 findings.review.supersede('F-1',1,{type:'identified',evidence_id:'E2',subject:{...assetSubject,label:'Replacement gateway'},evidence_lines:[{key:'package',value:'replacement-runtime'}],severity_input:ssvc()},human());
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
 assert.match(html,/<time id="overview-as-of" data-as-of><\/time>/);
 assert.match(html,/querySelectorAll\('\[data-as-of\]'\)\.forEach\(node=>\{node\.textContent=overviewAsOf;\}\)/);
 assert.doesNotMatch(html,/<div class="metric-label">As of /);
 assert.doesNotMatch(html,/id="coverage-metrics"/);
});

test('sidebar exposes five hash-routed views and removes dead navigation',()=>{
 const html=fs.readFileSync('src/index.html','utf8'),nav=html.slice(html.indexOf('<nav class="nav">'),html.indexOf('</nav>'));
 assert.equal((nav.match(/<button data-route=/g)||[]).length,5);
 for(const route of ['overview','approvals','findings','controls','audit']){
   assert.match(nav,new RegExp('data-route="'+route+'"'));assert.match(html,new RegExp('data-view="'+route+'"'));
 }
 assert.match(nav,/data-route="controls"[\s\S]*data-route="audit"/);
 assert.doesNotMatch(nav,/AI workforce|Incidents|Exposure|Identity|Governance|data-scroll/);
 assert.match(html,/import \{ resolveAppRoute \} from "\.\/route-model\.mjs"/);
 assert.match(fs.readFileSync('src/route-model.mjs','utf8'),/\^#\(overview\|approvals\|findings\|controls\|audit\)/);
 assert.match(html,/window\.addEventListener\('hashchange',navigateRoute\);navigateRoute\(\)/);
});

test('overview uses a compact priority list while Findings owns the complete filtered table',()=>{
 const html=fs.readFileSync('src/index.html','utf8');
 assert.match(html,/data-view="overview"[\s\S]*id="overview-indicators"[\s\S]*id="agents"[\s\S]*id="overview-finding-list"/);
 assert.match(html,/findings\.filter\(finding=>finding\.current_state==='open'\)\.slice\(0,4\)/);
 assert.match(html,/data-view="findings"[\s\S]*id="filter-severity"[\s\S]*id="filter-state"[\s\S]*id="filter-sla"[\s\S]*id="filter-type"[\s\S]*id="finding-list"/);
 for(const expression of ['finding.severity===filters.severity','finding.current_state===filters.state','finding.sla_status===filters.sla','finding.finding_type===filters.type'])assert.match(html,new RegExp(expression.replaceAll('.','\\.')));
 assert.doesNotMatch(html,/id="action-feed"|id="control-panel"/);
});

test('drawer routes retain their parent view and use the shared snapshot',()=>{
 const html=fs.readFileSync('src/index.html','utf8');
 assert.match(html,/currentRoute\+'\/finding\/'\+id/);assert.match(html,/currentRoute\+'\/action\/'\+row\.dataset\.approvalId/);assert.match(html,/currentRoute\+'\/control\/'\+b\.dataset\.controlId/);
 assert.match(html,/if\(route\.recordType==='action'\)showAction\(route\.id\)[\s\S]*route\.recordType==='finding'[\s\S]*route\.recordType==='control'/);
 assert.match(html,/findingRepo\.agent\.list\(overviewAsOf\)/);assert.match(html,/findingRepo\.agent\.get\(id,overviewAsOf\)/);
});

test('audit log unifies model history newest first at the explicit snapshot',()=>{
 const {findingRepo,controlRepo,as_of}=createDemoOverview(),actionRepo=createActionRepository();
 const action=actionRepo.agent.propose({action_id:'ACT-AUDIT',agent_id:'identity',action_type:'Proposed access review',target:'user:1',justification:'Observed entitlement',rule_id:'R01',control_refs:['AC-6'],severity:'high',proposed_at:'2026-09-13T20:00:00Z',rollback_procedure:'Human recovery'});
 actionRepo.agent.submit(action.action_id,{submitted_at:'2026-09-13T20:05:00Z'});
 const log=buildAuditLog({findingRepo,controlRepo,actionRepo},as_of);
 assert.equal(log.length,29);assert.ok(log.every((row,index)=>index===0||Date.parse(log[index-1].timestamp)>=Date.parse(row.timestamp)));
 assert.deepEqual(new Set(log.map(row=>row.record_type)),new Set(['finding','control','action']));
 assert.deepEqual(new Set(log.map(row=>row.actor.type)),new Set(['agent','person','system']));
 const actionEvent=log.find(row=>row.audit_id==='action:ACT-AUDIT:2');assert.deepEqual(actionEvent.payload,actionRepo.agent.history(action.action_id,as_of)[1]);
 assert.throws(()=>log.push({}));assert.throws(()=>{actionEvent.payload.actor.id='changed';});
});

test('audit supersession keeps originals visible and links both directions',()=>{
 const actionRepo=createActionRepository(),as_of='2026-09-14T23:00:00Z';
 const action=actionRepo.agent.propose({action_id:'ACT-SUP',agent_id:'soc',action_type:'Proposed review',target:'case:1',justification:'Observed event',rule_id:'R1',control_refs:['C1'],severity:'medium',proposed_at:'2026-09-13T20:00:00Z',rollback_procedure:'Human recovery'});
 actionRepo.agent.submit(action.action_id,{submitted_at:'2026-09-13T20:05:00Z'});
 actionRepo.review.supersede(action.action_id,2,{type:'submitted'},{actor_id:'reviewer',occurred_at:'2026-09-13T20:10:00Z',reason:'Corrected submission record'});
 const controlRepo={agent:{list:()=>[{control_id:'C1',evidence:[],assessments:[{assessment_id:1,status:'tested_fail',assessor:'reviewer',assessed_at:'2026-09-13T21:00:00Z',supersedes_assessment_id:null},{assessment_id:2,status:'tested_pass',assessor:'reviewer',assessed_at:'2026-09-13T22:00:00Z',supersedes_assessment_id:1}]}]}};
 const findingRepo={agent:{list:()=>[]}},log=buildAuditLog({findingRepo,controlRepo,actionRepo},as_of);
 for(const [originalId,replacementId] of [['action:ACT-SUP:2','action:ACT-SUP:3'],['control:C1:assessment:1','control:C1:assessment:2']]){
   const original=log.find(row=>row.audit_id===originalId),replacement=log.find(row=>row.audit_id===replacementId);
   assert.equal(original.superseded_by_audit_id,replacementId);assert.equal(replacement.supersedes_audit_id,originalId);
 }
 assert.equal(log.find(row=>row.audit_id==='control:C1:assessment:2').event_type,'superseded');
});

test('audit view exposes filters, human emphasis, payload drawer, and record links',()=>{
 const html=fs.readFileSync('src/index.html','utf8');
 assert.match(html,/data-view="audit"[\s\S]*Session-only log; this browser record is not tamper-evident[\s\S]*id="audit-actor-filter"[\s\S]*id="audit-record-filter"[\s\S]*id="audit-list"/);
 assert.match(html,/\.audit-event-button\.actor-person \{ border-left-color:var\(--amber\);background:/);
 assert.match(html,/Full event payload[\s\S]*id="audit-event-payload"/);
 assert.match(html,/data-audit-record-type[\s\S]*data-audit-record-id/);
 assert.match(html,/location\.hash='audit\/'\+recordLink\.dataset\.auditRecordType\+'\/'\+recordLink\.dataset\.auditRecordId/);
 assert.match(html,/buildAuditLog\(\{findingRepo,controlRepo,actionRepo:\{agent:agentPort\}\},overviewAsOf\)/);
 assert.match(html,/row\.actor\.type===actorFilter[\s\S]*row\.record_type===recordFilter/);
 assert.deepEqual(resolveAppRoute('#audit/event/action:ACT-1:2',{event:['action:ACT-1:2']}),{parent:'audit',recordType:'event',id:'action:ACT-1:2',redirect:false});
});

test('unknown drawer ids return to their parent route with a visible notice',()=>{
 const recordIds={action:['ACT-ID-001'],finding:['IAM-0001'],control:['CTRL-01']};
 assert.deepEqual(resolveAppRoute('#findings/finding/DOES-NOT-EXIST',recordIds),{parent:'findings',redirect:true,notice:'Finding record was not found.'});
 assert.deepEqual(resolveAppRoute('#approvals/action/NOPE-123',recordIds),{parent:'approvals',redirect:true,notice:'Action record was not found.'});
 assert.deepEqual(resolveAppRoute('#controls/control/NOPE-456',recordIds),{parent:'controls',redirect:true,notice:'Control record was not found.'});
});

test('a drawer route with a trailing empty id returns to its parent with a notice',()=>{
 assert.deepEqual(resolveAppRoute('#findings/finding/',{finding:['IAM-0001']}),{parent:'findings',redirect:true,notice:'Finding record was not found.'});
 const html=fs.readFileSync('src/index.html','utf8');
 assert.match(html,/if\(route\.redirect\)\{location\.hash=route\.parent;if\(route\.notice\)notify\(route\.notice\);return;\}/);
});

test('finding table projects repository records and sorts overdue before severity',()=>{
 const html=fs.readFileSync('src/index.html','utf8'),{findingRepo,as_of}=createDemoOverview();
 const ordered=sortOverviewFindings(findingRepo.agent.list(as_of));
 assert.deepEqual(ordered.map(finding=>finding.finding_id),['IAM-0004','IAM-0006','IAM-0008','IAM-0009','IAM-0001','IAM-0002','IAM-0003','IAM-0005','IAM-0007','IAM-0010']);
 assert.deepEqual(ordered.slice(0,4).map(finding=>finding.sla_status),['overdue','overdue','overdue','overdue']);
 for(const finding of ordered)for(const field of ['finding_id','subject','evidence_lines','title','severity','current_state','owner','sla_status'])assert.ok(finding[field]);
 assert.match(html,/<span>Finding<\/span><span>Subject<\/span><span>Title<\/span><span>Severity<\/span><span>State<\/span><span>Owner<\/span><span>SLA status<\/span>/);
 assert.match(html,/sortOverviewFindings\(findingRepo\.agent\.list\(overviewAsOf\)\)/);
 assert.match(html,/within_sla:'Within SLA'/);
 assert.match(html,/finding\.finding_id[\s\S]*finding\.subject\.label[\s\S]*finding\.title[\s\S]*finding\.severity[\s\S]*finding\.current_state[\s\S]*finding\.owner[\s\S]*finding\.sla_status/);
 assert.doesNotMatch(html,/INC-2841|VUL-9912|IAM-2204|<span>Assessment<\/span>|<span>Window<\/span>|Current window/);
});

test('dashboard findings use the verified Entra snapshot and expected real SLA behavior',()=>{
 const {controlRepo,evidenceRepo,findingRepo,cycle,as_of,snapshot}=createDemoOverview();
 assert.equal(as_of,OVERVIEW_AS_OF);
 assert.equal(coverageStatement(coverage(controlRepo.agent.list(),cycle.cycle_id)),'5 controls in scope. 2 tested this cycle, 1 passed, 1 failed, 3 not yet tested.');
 assert.equal(controlRepo.agent.get('CTRL-01').status,'tested_pass');assert.equal(controlRepo.agent.get('CTRL-01').assessor,'Demo reviewer');
 assert.equal(controlRepo.agent.get('CTRL-04').status,'tested_fail');assert.equal(controlRepo.agent.get('CTRL-04').assessor,'Demo reviewer');
 assert.equal(controlRepo.agent.get('CTRL-02').status,'evidence_collected');
 const indicators=findingIndicators(findingRepo.agent.list(as_of),as_of);
 assert.deepEqual(indicators.open_findings_by_severity,{low:0,medium:6,high:3,critical:1});
 assert.deepEqual(indicators.overdue_findings_by_severity,{low:0,medium:0,high:3,critical:1});
 assert.deepEqual(evidenceRepo.get(ENTRA_SNAPSHOT.evidence_id),snapshot);
 assert.deepEqual(findingRepo.agent.get('IAM-0008',as_of).action_refs,['ACT-ID-001']);
 assert.deepEqual(findingRepo.agent.get('IAM-0004',as_of).action_refs,['ACT-ID-002']);
});

test('Entra finding seeds preserve supplied IDs, titles and NIST references while computing severity',()=>{
 const source=JSON.parse(fs.readFileSync('data/entra-findings.json','utf8')).findings,{findingRepo,as_of}=createDemoOverview();
 assert.equal(source.length,10);assert.equal(ENTRA_FINDING_SEEDS.length,10);
 const sourceById=new Map(source.map(item=>[item.finding_id,item]));
 for(const seed of ENTRA_FINDING_SEEDS){
   const supplied=sourceById.get(seed.finding_id),projected=findingRepo.agent.get(seed.finding_id,as_of);
   assert.ok(supplied);assert.equal(seed.title,supplied.title);assert.deepEqual(seed.control_refs,supplied.control_refs);
   assert.deepEqual(seed.subject,supplied.subject);assert.deepEqual(seed.evidence_lines,supplied.evidence_lines);
   assert.equal(projected.severity,seed.finding_id==='IAM-0004'?'critical':(['IAM-0006','IAM-0008','IAM-0009'].includes(seed.finding_id)?'high':'medium'));
   assert.equal(projected.created_at,'2026-08-23T20:40:22Z');
   assert.deepEqual(projected.evidence_ids,['ENTRA-SNAPSHOT-2026-08-23']);assert.equal(projected.finding_type,'identity');
   assert.equal(Object.hasOwn(seed.severity_input,'modifiers'),false);
 }
 assert.deepEqual(ENTRA_QUEUE_RULES,{R01:'priority-review',R02:'standard-review',R03:'priority-review',R04:'standard-review',R05:'standard-review'});
});

test('Entra subjects use snapshot object IDs and keep identity attributes out of rule facts',()=>{
 const rows=fs.readFileSync('data/entitlement-snapshot.csv','utf8').split(/\r?\n/),header=rows[0].replace(/^\uFEFF?"|"$/g,'').split('\",\"');
 const index=Object.fromEntries(header.map((name,position)=>[name,position])),idByUpn=new Map();
 for(const row of rows.slice(1)){
   if(!row)continue;
   const values=row.replace(/^"|"$/g,'').split('\",\"');idByUpn.set(values[index.UserPrincipalName],values[index.UserId]);
 }
 for(const seed of ENTRA_FINDING_SEEDS){
   assert.equal(seed.subject.type,'user');assert.equal(seed.subject.id.namespace,'microsoft_entra_id');
   assert.equal(seed.subject.id.value,idByUpn.get(seed.subject.details.principal_name));
   for(const line of seed.evidence_lines){assert.deepEqual(Object.keys(line),['key','value']);assert.doesNotMatch(line.key,/^(principal_name|department|job_title|privileged)$/);}
 }
 assert.deepEqual(ENTRA_FINDING_SEEDS.find(seed=>seed.finding_id==='IAM-0002').subject.label,'Bea Lindqvist');
 assert.deepEqual(ENTRA_FINDING_SEEDS.find(seed=>seed.finding_id==='IAM-0010').subject.label,'Tomas Njoku');
 assert.deepEqual(ENTRA_FINDING_SEEDS.find(seed=>seed.finding_id==='IAM-0008').evidence_lines,[{key:'account_enabled',value:false},{key:'group',value:'DEPT-Store-Operations'},{key:'group',value:'ROLE-Store-Associate'}]);
});

test('finding drawer renders subject identity and structured evidence keys and values separately',()=>{
 const html=fs.readFileSync('src/index.html','utf8');
 for(const id of ['finding-subject','finding-subject-type','finding-subject-id','finding-subject-namespace','subject-details','finding-evidence-lines'])assert.match(html,new RegExp('id="'+id+'"'));
 assert.match(html,/finding\.evidence_lines\.map\(line=>[\s\S]*line\.key[\s\S]*line\.value/);
});

test('Entra snapshot evidence records the supplied artifact hash byte-for-byte',()=>{
 const actual=crypto.createHash('sha256').update(fs.readFileSync('data/entitlement-snapshot.csv')).digest('hex');
 assert.equal(actual,ENTRA_SNAPSHOT.artifact_ref.content_hash.value);
 assert.equal(ENTRA_SNAPSHOT.collected_at,'2026-08-23T20:40:22Z');
 assert.equal(ENTRA_SNAPSHOT.source,'Microsoft Entra ID');
 assert.deepEqual(ENTRA_SNAPSHOT.collected_by,{type:'agent',id:'identity'});
 assert.equal(ENTRA_SNAPSHOT.artifact_ref.verification_status,'unverified');
});

test('generated Entra artifacts cannot drift from the verified snapshot pipeline',()=>{
 const candidates=[
   process.env.PYTHON,
   path.join(process.cwd(),'.venv',process.platform==='win32'?'Scripts/python.exe':'bin/python'),
   'python3','python','py',
   process.env.USERPROFILE&&path.join(process.env.USERPROFILE,'.cache','codex-runtimes','codex-primary-runtime','dependencies','python','python.exe')
 ].filter(Boolean);
 let result;
 for(const command of candidates){
   const args=/^py(?:\.exe)?$/i.test(path.basename(command))?['-3','identity_pipeline.py','--check']:['identity_pipeline.py','--check'];
   result=spawnSync(command,args,{cwd:process.cwd(),encoding:'utf8'});
   if(!result.error||result.error.code!=='ENOENT')break;
 }
 assert.ok(result&&!result.error,'Python 3 is required to verify generated Entra artifacts');
 assert.equal(result.status,0,`${result.stdout||''}${result.stderr||''}`);
 assert.match(result.stdout,/Identity pipeline check passed/);
});

test('identity pipeline reports answer-key and perturbation evidence separately',()=>{
 const results=JSON.parse(fs.readFileSync('data/identity-pipeline-results.json','utf8'));
 assert.deepEqual(results.answer_key.recall,{value:1,matched:10,total:10});
 assert.deepEqual(results.answer_key.precision,{value:1,matched:10,total:10});
 assert.deepEqual(results.answer_key.severity_accuracy,{value:1,matched:10,total:10});
 assert.deepEqual(results.answer_key.control_cases,{result:'pass',passed:2,total:2,unexpected_findings:[]});
 assert.equal(results.perturbation.injected_defects.result,'pass');
 assert.equal(results.perturbation.injected_defects.detected,5);
 assert.deepEqual(results.perturbation.known_defect_removal,{result:'pass',removed_finding_id:'IAM-0004',cleared:true,side_effects:[]});
 const generated=fs.readFileSync('src/entra-finding-seeds.mjs','utf8');
 assert.match(generated,/^\/\/ GENERATED FILE\. DO NOT EDIT\./);
 assert.match(generated,/\/\/ Source: data\/entitlement-snapshot\.csv/);
 assert.match(generated,new RegExp(`// SHA-256: ${ENTRA_SNAPSHOT.artifact_ref.content_hash.value}`));
});

test('finding provenance is rendered from the shared evidence record',()=>{
 const html=fs.readFileSync('src/index.html','utf8');
 assert.match(html,/id="finding-provenance"/);
 assert.match(html,/snapshot\.collected_at/);assert.match(html,/snapshot\.artifact_ref\.content_hash\.value/);
 assert.match(html,/SHA-256 '.*hash\.slice\(0,12\).*hash\.slice\(-8\)/s);
 assert.doesNotMatch(html,/F-DEMO|FINDING-DEMO/);
 assert.doesNotMatch(html,/ACT-SOC-001|ACT-VUL-001|ACT-SE-001|user:demo-(?:admin|standard|dormant)/);
 assert.match(html,/ACT-ID-001[\s\S]*user:rmalik@contoso\.onmicrosoft\.com[\s\S]*R04/);
 assert.match(html,/ACT-ID-002[\s\S]*user:dreyes@contoso\.onmicrosoft\.com[\s\S]*R01/);
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
