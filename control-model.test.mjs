import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {Control,ControlStatus,createControlRepository,conclusionFor,coverage,coverageStatement,sortControls,effectiveStatus} from './src/control-model.mjs';
const input={control_id:'C1',name:'Control',cycle_id:'2026-09',cycle_start:'2026-09-01T00:00:00Z',cycle_end:'2026-10-01T00:00:00Z'};
const evidence={evidence_id:'E1',source:'Observation',collected_at:'2026-09-13T20:00:00Z'};
const assessment={assessor:'Demo reviewer',assessed_at:'2026-09-13T21:00:00Z',assessment_rationale:'Test observation'};
const setup=()=>{const r=createControlRepository();r.add(input);return r;};
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
