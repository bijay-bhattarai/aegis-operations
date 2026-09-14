import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {Control,ControlStatus,SupersedeReason,ArtifactType,ArtifactVerificationStatus,CollectorType,IdentityBasis,createControlRepository,conclusionFor,coverage,coverageStatement,sortControls,effectiveStatus} from './src/control-model.mjs';
const input={control_id:'C1',name:'Control',cycle_id:'2026-09',cycle_start:'2026-09-01T00:00:00Z',cycle_end:'2026-10-01T00:00:00Z'};
const artifact_ref={type:'log_query',locator:'artifact://session/entra/query-1842',content_hash:{algorithm:'sha256',value:'a'.repeat(64)}};
const evidence={evidence_id:'E1',source:'Entra ID',collected_by:{type:'agent',id:'identity'},collected_at:'2026-09-13T20:00:00Z',artifact_ref};
const assessment={assessor:'Demo reviewer',assessed_at:'2026-09-13T21:00:00Z',assessment_rationale:'Test observation'};
const setup=()=>{const r=createControlRepository();r.add(input);return r;};
const canonicalEvidence=e=>({
 evidence_id:e.evidence_id,source:e.source,collected_by:{...e.collected_by},collected_at:e.collected_at,
 artifact_ref:{...e.artifact_ref,content_hash:{...e.artifact_ref.content_hash},verification_status:e.artifact_ref.verification_status??'unverified'}
});
test('exact enum and no implicit pass',()=>{
 assert.deepEqual(Object.keys(ControlStatus),['not_assessed','evidence_collected','tested_pass','tested_fail','exception_approved']);
 const r=setup();assert.equal(r.agent.get('C1').status,'not_assessed');
 assert.throws(()=>r.add({...input,control_id:'C2',status:'tested_pass'}));
 assert.throws(()=>{r.agent.get('C1').status='tested_pass';});
});
for(const status of ['tested_pass','tested_fail','exception_approved']){
 test(status+': only reviewer capability and required evidence/identity/time',()=>{
  const r=setup();assert.throws(()=>r.reviewer.assess('C1',status,assessment));r.agent.collect('C1',evidence);
  assert.equal(r.agent.assess,undefined);
  const c=new Control(input);c.collect(evidence);assert.throws(()=>c.assess(status,assessment));assert.throws(()=>c.assess(status,assessment,{role:'human'}));
  for(const bad of [{},{...assessment,assessor:''},{...assessment,assessed_at:''},{...assessment,assessed_at:'bad'},{...assessment,assessed_at:'2026-08-13T21:00:00Z'},{...assessment,assessed_at:'2026-09-13T19:00:00Z'}]){
   assert.throws(()=>r.reviewer.assess('C1',status,bad));assert.equal(r.agent.get('C1').status,'evidence_collected');
  }
  r.reviewer.assess('C1',status,assessment);
  assert.deepEqual(conclusionFor(r.agent.get('C1')),{status,assessor:assessment.assessor,assessed_at:assessment.assessed_at});
 });
}
test('new evidence clears prior conclusion and metadata',()=>{
 const r=setup();r.agent.collect('C1',evidence);r.reviewer.assess('C1','tested_pass',assessment);
 r.agent.collect('C1',{...evidence,evidence_id:'E2',collected_at:'2026-09-14T20:00:00Z'});
 assert.equal(r.agent.get('C1').status,'evidence_collected');assert.equal(r.agent.get('C1').assessor,null);
 assert.equal(conclusionFor(r.agent.get('C1')),null);
 assert.equal(r.agent.get('C1').assessments.length,1);
});

test('supersede retains the byte-identical original and changes the current conclusion without new evidence',()=>{
 const r=setup();r.agent.collect('C1',evidence);r.reviewer.assess('C1','tested_fail',assessment);
 const before=r.agent.get('C1'),originalBytes=JSON.stringify(before.assessments[0]);
 const expectedDigest=createHash('sha256').update(JSON.stringify([canonicalEvidence(evidence)])).digest('hex');
 assert.equal(before.assessments[0].evidence_digest,expectedDigest);
 const corrected={assessor:'Second demo reviewer',assessed_at:'2026-09-13T22:00:00Z',assessment_rationale:'Corrected interpretation',supersede_reason:'evidence_reinterpreted'};
 const after=r.reviewer.supersede('C1','tested_pass',corrected);
 assert.equal(JSON.stringify(after.assessments[0]),originalBytes);
 assert.equal(after.assessments.length,2);assert.equal(after.current_assessment_id,2);
 assert.deepEqual(after.assessments[1],{
  assessment_id:2,status:'tested_pass',assessor:corrected.assessor,assessed_at:corrected.assessed_at,
  assessment_rationale:corrected.assessment_rationale,evidence_digest:expectedDigest,
  supersedes_assessment_id:1,supersede_reason:'evidence_reinterpreted',supersede_reason_text:null
 });
 assert.equal(after.status,after.assessments[1].status);assert.equal(after.assessor,after.assessments[1].assessor);
 assert.equal(after.assessed_at,after.assessments[1].assessed_at);assert.equal(after.assessment_rationale,after.assessments[1].assessment_rationale);
 assert.deepEqual(conclusionFor(after),{status:'tested_pass',assessor:corrected.assessor,assessed_at:corrected.assessed_at});
 assert.deepEqual(coverage(r.agent.list(),'2026-09'),{in_scope:1,tested:1,passed:1,failed:0,not_assessed:0});
});

test('a control without a current assessment cannot be superseded',()=>{
 const r=setup();
 const correction={...assessment,supersede_reason:'recorded_in_error'};
 assert.throws(()=>r.reviewer.supersede('C1','tested_pass',correction),/Current assessment required/);
 r.agent.collect('C1',evidence);
 assert.throws(()=>r.reviewer.supersede('C1','tested_pass',correction),/Current assessment required/);
 assert.equal(r.agent.get('C1').assessments.length,0);
});

test('supersede requires human capability, valid reason metadata and ordered time; failures are atomic',()=>{
 const r=setup();r.agent.collect('C1',evidence);r.reviewer.assess('C1','tested_fail',assessment);
 assert.equal(r.agent.supersede,undefined);
 const c=new Control(input);c.collect(evidence);
 assert.throws(()=>c.supersede('tested_pass',{...assessment,supersede_reason:'recorded_in_error'}),/Human review capability required/);
 const before=JSON.stringify(r.agent.get('C1'));
 for(const bad of [
  {...assessment,assessed_at:'2026-09-13T22:00:00Z'},
  {...assessment,assessed_at:'2026-09-13T22:00:00Z',supersede_reason:'typo'},
  {...assessment,assessed_at:'2026-09-13T22:00:00Z',supersede_reason:'other'},
  {...assessment,assessed_at:'2026-09-13T22:00:00Z',supersede_reason:'recorded_in_error',supersedes_assessment_id:99},
  {...assessment,assessed_at:'2026-09-13T20:30:00Z',supersede_reason:'recorded_in_error'},
  {...assessment,assessed_at:'2026-10-01T00:00:00Z',supersede_reason:'recorded_in_error'}
 ]){
  assert.throws(()=>r.reviewer.supersede('C1','tested_pass',bad));
  assert.equal(JSON.stringify(r.agent.get('C1')),before);
 }
 const corrected=r.reviewer.supersede('C1','tested_pass',{...assessment,assessed_at:'2026-09-13T22:00:00Z',supersede_reason:'other',supersede_reason_text:'Incorrect test population'});
 assert.equal(corrected.assessments[1].supersede_reason_text,'Incorrect test population');
 assert.deepEqual(Object.values(SupersedeReason),['recorded_in_error','evidence_reinterpreted','scope_corrected','other']);
});

test('assessment evidence digests capture the full evidence set at each assessment time',()=>{
 const r=setup();r.agent.collect('C1',evidence);r.reviewer.assess('C1','tested_fail',assessment);
 const first=r.agent.get('C1').assessments[0].evidence_digest;
 const secondEvidence={...evidence,evidence_id:'E2',source:'Defender',collected_at:'2026-09-14T20:00:00Z',artifact_ref:{...artifact_ref,locator:'artifact://session/defender/export-2',content_hash:{algorithm:'sha256',value:'b'.repeat(64)}}};
 r.agent.collect('C1',secondEvidence);
 r.reviewer.assess('C1','tested_pass',{...assessment,assessed_at:'2026-09-14T21:00:00Z'});
 const record=r.agent.get('C1'),canonical=JSON.stringify([canonicalEvidence(evidence),canonicalEvidence(secondEvidence)]);
 assert.notEqual(record.assessments[1].evidence_digest,first);
 assert.equal(record.assessments[1].evidence_digest,createHash('sha256').update(canonical).digest('hex'));
 assert.equal(record.current_assessment_id,2);assert.equal(effectiveStatus(record),'tested_pass');
 assert.throws(()=>{record.assessments[0].status='tested_pass';});
});
test('evidence records require immutable structured artifact and collector references',()=>{
 const r=setup(),record=r.agent.collect('C1',evidence),stored=record.evidence[0];
 assert.deepEqual(stored,canonicalEvidence(evidence));
 assert.equal(stored.artifact_ref.verification_status,'unverified');
 assert.throws(()=>{stored.artifact_ref.locator='changed';});
 assert.throws(()=>{stored.artifact_ref.content_hash.value='b'.repeat(64);});
 assert.deepEqual(Object.values(ArtifactType),['export','screenshot','log_query','attestation','config_snapshot']);
 assert.deepEqual(Object.values(ArtifactVerificationStatus),['unverified','verified']);
 assert.deepEqual(Object.values(CollectorType),['agent','person']);
 assert.deepEqual(Object.values(IdentityBasis),['self_reported']);
});
test('missing or malformed artifact references and unsupported verification are rejected atomically',()=>{
 const r=setup(),withoutArtifact={...evidence};delete withoutArtifact.artifact_ref;
 const invalid=[
  withoutArtifact,
  {...evidence,artifact_ref:null},
  {...evidence,artifact_ref:{...artifact_ref,type:'document'}},
  {...evidence,artifact_ref:{...artifact_ref,locator:''}},
  {...evidence,artifact_ref:{...artifact_ref,content_hash:null}},
  {...evidence,artifact_ref:{...artifact_ref,content_hash:{algorithm:'md5',value:'a'.repeat(64)}}},
  {...evidence,artifact_ref:{...artifact_ref,content_hash:{algorithm:'sha256',value:'A'.repeat(64)}}},
  {...evidence,artifact_ref:{...artifact_ref,content_hash:{algorithm:'sha256',value:'a'.repeat(63)}}},
  {...evidence,artifact_ref:{...artifact_ref,unexpected:true}}
 ];
 for(const bad of invalid)assert.throws(()=>r.agent.collect('C1',bad));
 assert.throws(()=>r.agent.collect('C1',{...evidence,artifact_ref:{...artifact_ref,verification_status:'verified'}}),/no artifact resolver exists/);
 assert.throws(()=>r.agent.collect('C1',{...evidence,artifact_ref:{...artifact_ref,verification_status:'pending'}}),/Invalid artifact_ref verification_status/);
 assert.equal(r.agent.get('C1').evidence.length,0);
});
test('collector identities distinguish known agents from self-reported people',()=>{
 for(const id of ['unknown','SOC Agent'])assert.throws(()=>setup().agent.collect('C1',{...evidence,collected_by:{type:'agent',id}}));
 for(const id of ['identity','IDENTITY','Identity Agent','field-agent-7']){
  assert.throws(()=>setup().agent.collect('C1',{...evidence,collected_by:{type:'person',id,identity_basis:'self_reported'}}),/Person collector ID cannot identify an agent/);
 }
 assert.throws(()=>setup().agent.collect('C1',{...evidence,collected_by:{type:'person',id:'Reviewer'}}),/identity_basis is required/);
 assert.throws(()=>setup().agent.collect('C1',{...evidence,collected_by:{type:'person',id:'Reviewer',identity_basis:'authenticated'}}),/Only self_reported identity_basis is currently accepted/);
 const stored=setup().agent.collect('C1',{...evidence,collected_by:{type:'person',id:'Reviewer 42',identity_basis:'self_reported'}}).evidence[0];
 assert.deepEqual(stored.collected_by,{type:'person',id:'Reviewer 42',identity_basis:'self_reported'});
});
test('changing only the artifact content hash changes the assessment evidence digest',()=>{
 const assessedDigest=hash=>{
  const r=setup();r.agent.collect('C1',{...evidence,artifact_ref:{...artifact_ref,content_hash:{algorithm:'sha256',value:hash}}});
  return r.reviewer.assess('C1','tested_pass',assessment).assessments[0].evidence_digest;
 };
 assert.notEqual(assessedDigest('a'.repeat(64)),assessedDigest('b'.repeat(64)));
});
test('evidence cannot inject status, cannot be empty or outside cycle',()=>{
 const r=setup();
 for(const bad of [{...evidence,status:'tested_pass'},{...evidence,source:''},{...evidence,collected_at:'2026-10-01T00:00:00Z'}])assert.throws(()=>r.agent.collect('C1',bad));
 assert.equal(r.agent.get('C1').status,'not_assessed');
});
test('missing assessor suppresses conclusions, including malformed imports',()=>{
 for(const status of ['tested_pass','tested_fail','exception_approved']){
  assert.equal(conclusionFor({status,assessed_at:assessment.assessed_at}),null);
  assert.equal(effectiveStatus({status}), 'not_assessed');
 }
});
test('cycle coverage excludes exceptions and evidence-only from tested count; unknown before failure',()=>{
 const r=setup();
 for(const id of ['C2','C3','C4','C5'])r.add({...input,control_id:id});
 for(const id of ['C2','C3','C4','C5'])r.agent.collect(id,evidence);
 r.reviewer.assess('C3','tested_fail',assessment);r.reviewer.assess('C4','tested_pass',assessment);r.reviewer.assess('C5','exception_approved',assessment);
 assert.equal(coverageStatement(coverage(r.agent.list(),'2026-09')),'5 controls in scope. 2 tested this cycle, 1 passed, 1 failed, 3 not yet tested.');
 assert.equal(coverage(r.agent.list(),'2026-10').in_scope,0);
 assert.deepEqual(sortControls(r.agent.list()).map(r=>r.control_id),['C1','C2','C3','C5','C4']);
});
test('agent-generated case and feed text has no forbidden verdict vocabulary',()=>{
 const h=fs.readFileSync('src/index.html','utf8');
 const content=h.slice(h.indexOf('const agents ='),h.indexOf('const caseActions='));
 assert.doesNotMatch(content,/\b(compliant|effective|secure|within policy|validated|operating correctly|all clear|nominal)\b/i);
 assert.doesNotMatch(h,/97%|94%|91%|99\.2%|87 \/ 100/);
 assert.match(h,/Not yet tested',counts.not_assessed,'unknown'/);
 assert.match(h,/labels\[effectiveStatus\(record\)\]\+attribution/);
});
