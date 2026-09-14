import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {AgentAction,AGENT_IDS,ACTION_STATUSES,createActionRepository} from './src/action-model.mjs';
const proposal=agent_id=>({action_id:'ACT-1',agent_id,action_type:'Proposed review',target:'demo',justification:'Evidence',rule_id:'RULE-1',control_refs:['CONTROL-1'],severity:'high',proposed_at:'2026-09-13T20:00:00Z',rollback_procedure:'Human recovery'});
const decision={approver:'human:demo-reviewer',decided_at:'2026-09-13T21:00:00Z',decision_rationale:'Evidence reviewed'};
const edges={proposed:['pending_approval','expired'],pending_approval:['approved','rejected','expired'],approved:['executed','expired'],rejected:[],expired:[],executed:[]};
function at(status){
 const a=new AgentAction(proposal('soc'));
 if(status==='proposed')return a;
 if(status==='expired'){a.transition('expired');return a;}
 a.transition('pending_approval');
 if(status==='pending_approval')return a;
 a.transition(status==='rejected'?'rejected':'approved',decision);
 if(status==='executed')a.transition('executed',{executed_at:'2026-09-13T22:00:00Z'});
 return a;
}
for(const agent of AGENT_IDS)test(agent+': restricted agent port and record-only review',()=>{
 const {agent:port,review}=createActionRepository();
 const r=port.propose(proposal(agent));
 assert.equal(r.status,'proposed');assert.equal(r.approver,null);
 for(const method of ['decide','recordExecution','execute','transition'])assert.equal(port[method],undefined);
 assert.throws(()=>review.recordExecution(r.action_id,'2026-09-13T22:00:00Z'));
 port.submit(r.action_id);
 assert.throws(()=>review.decide(r.action_id,'executed',decision));
 review.decide(r.action_id,'approved',decision);
 review.recordExecution(r.action_id,'2026-09-13T22:00:00Z');
 assert.equal(port.get(r.action_id).status,'executed');
});
for(const from of ACTION_STATUSES)for(const to of ACTION_STATUSES)test(from+' → '+to,()=>{
 const a=at(from),before=a.record;
 const meta=['approved','rejected'].includes(to)?decision:to==='executed'?{executed_at:'2026-09-13T22:00:00Z'}:{};
 if(edges[from].includes(to)){a.transition(to,meta);assert.equal(a.record.status,to);}
 else{assert.throws(()=>a.transition(to,meta));assert.deepEqual(a.record,before);}
});
test('approval requires identity, timestamp and rationale; failed writes are atomic',()=>{
 for(const bad of [{},{...decision,approver:''},{...decision,approver:' '},{...decision,decided_at:null},{...decision,decided_at:'bad'},{...decision,decision_rationale:''},{...decision,decided_at:'2026-09-12T21:00:00Z'}]){
  const a=at('pending_approval');assert.throws(()=>a.transition('approved',bad));assert.equal(a.record.status,'pending_approval');
 }
});
test('constructor and snapshots cannot bypass transitions',()=>{
 for(const status of ACTION_STATUSES.filter(s=>s!=='proposed'))assert.throws(()=>new AgentAction({...proposal('soc'),status}));
 assert.throws(()=>new AgentAction({...proposal('soc'),approver:'fake'}));
 const a=at('proposed');assert.throws(()=>{a.record.status='executed'});assert.throws(()=>a.record.control_refs.push('x'));
 assert.equal(a.record.status,'proposed');
});
test('execution time cannot precede approval',()=>{
 const a=at('approved');assert.throws(()=>a.transition('executed',{executed_at:'2026-09-13T20:00:00Z'}));assert.equal(a.record.status,'approved');
});
test('action timestamps reject nonexistent calendar dates and accept a valid leap day',()=>{
 for(const date of ['2026-02-30','2025-02-29','2026-04-31','2026-13-01']){
  assert.throws(()=>new AgentAction({...proposal('soc'),proposed_at:date+'T00:00:00Z'}),/UTC timestamp/);
 }
 assert.equal(new AgentAction({...proposal('soc'),proposed_at:'2028-02-29T00:00:00Z'}).record.proposed_at,'2028-02-29T00:00:00Z');
});
test('UI syntax and no outbound writer APIs or agent decision tools',()=>{
 const h=fs.readFileSync('src/index.html','utf8'),m=fs.readFileSync('src/action-model.mjs','utf8');
 new vm.Script(h.match(/<script type="module">([\s\S]*?)<\/script>/)[1].replace(/import .*?;/g,''));
 assert.doesNotMatch(h+m,/\b(fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon)\s*\(/);
 assert.doesNotMatch(h,/set_default_autonomy|decide_security_case|data-mode|data-action=/);
 assert.match(h,/connect-src 'none'/);assert.match(h,/form-action 'none'/);
 assert.match(h,/action\.status/);assert.match(h,/href="#action\//);
});
test('entire src tree contains no fetch, XMLHttpRequest, or sendBeacon',()=>{
 const files=[];
 const visit=directory=>{
  for(const entry of fs.readdirSync(directory,{withFileTypes:true})){
   const file=path.join(directory,entry.name);
   if(entry.isDirectory())visit(file);else if(entry.isFile())files.push(file);
  }
 };
 visit('src');
 const forbidden=/\bfetch\s*\(|\bXMLHttpRequest\b|\bsendBeacon\b/;
 const violations=files.filter(file=>forbidden.test(fs.readFileSync(file,'utf8')));
 assert.deepEqual(violations,[],`Outbound transport primitive found in: ${violations.join(', ')}`);
});
