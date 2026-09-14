import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {AgentAction,AGENT_IDS,ACTION_STATUSES,createActionRepository} from './src/action-model.mjs';
import {approvalQueue} from './src/approval-queue-model.mjs';
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
test('approval and rejection cannot be backdated before the proposal',()=>{
 for(const outcome of ['approved','rejected']){
  const a=at('pending_approval'),before=a.record;
  assert.throws(()=>a.transition(outcome,{...decision,decided_at:'2026-09-13T19:59:59Z'}),/Decision precedes proposal/);
  assert.deepEqual(a.record,before);
 }
});
test('approval queue filters, links, sorts and returns immutable records',()=>{
 const repo=createActionRepository();
 const values=[
  {...proposal('soc'),action_id:'ACT-LOW',severity:'low',proposed_at:'2026-09-10T00:00:00Z'},
  {...proposal('vuln'),action_id:'ACT-CRIT-NEW',severity:'critical',proposed_at:'2026-09-12T00:00:00Z'},
  {...proposal('identity'),action_id:'ACT-CRIT-OLD',severity:'critical',proposed_at:'2026-09-11T00:00:00Z'},
  {...proposal('compliance'),action_id:'ACT-DONE',severity:'high',proposed_at:'2026-09-09T00:00:00Z'}
 ];
 for(const value of values)repo.agent.propose(value);
 for(const id of ['ACT-CRIT-NEW','ACT-CRIT-OLD','ACT-DONE'])repo.agent.submit(id);
 repo.review.decide('ACT-DONE','rejected',{...decision,decided_at:'2026-09-13T21:00:00Z'});
 const queue=approvalQueue(repo.agent.list(),[{finding_id:'F-1',action_refs:['ACT-CRIT-OLD']},{finding_id:'F-2',action_refs:['ACT-CRIT-OLD','ACT-LOW']}]);
 assert.deepEqual(queue.map(action=>action.action_id),['ACT-CRIT-OLD','ACT-CRIT-NEW','ACT-LOW']);
 assert.deepEqual(queue[0].linked_finding_ids,['F-1','F-2']);assert.equal(queue[2].status,'proposed');
 assert.throws(()=>queue.push({}));assert.throws(()=>queue[0].linked_finding_ids.push('F-3'));
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
 assert.match(h,/action\.status/);assert.match(h,/currentRoute\+'\/action\/'\+row\.dataset\.approvalId/);
});
test('approval queue UI exposes review metadata and keeps execution separate',()=>{
 const h=fs.readFileSync('src/index.html','utf8');
 assert.match(h,/<button data-route="overview">[\s\S]*?<span>Overview<\/span><\/button>\s*<button data-route="approvals">[\s\S]*?<span>Approvals<\/span><span class="nav-count" id="approval-count">0<\/span>/);
 assert.match(h,/<section class="view" data-view="approvals" hidden[\s\S]*?<section class="panel approvals-panel">[\s\S]*?id="approval-list"/);
 assert.match(h,/approvalQueue\(agentPort\.list\(\),findingRepo\.agent\.list\(overviewAsOf\)\)/);
 for(const field of ['action.action_id','action.agent_id','action.action_type','action.target','action.severity','action.rule_id','action.control_refs','action.proposed_at','action.linked_finding_ids'])assert.match(h,new RegExp(field.replace('.','\\.')));
 assert.match(h,/The proposing agent must submit this action before a reviewer can approve or reject it\./);
 assert.match(h,/Decision timestamp \(UTC ISO 8601; reviewer-supplied, unverified\)/);
 assert.match(h,/decided_at:document\.querySelector\('#decision-time'\)\.value/);
 assert.doesNotMatch(h,/decided_at:new Date\(\)\.toISOString\(\)/);
 assert.match(h,/Full justification[\s\S]*Evidence linked through finding records[\s\S]*Rollback procedure/);
 assert.match(h,/This separate step records only work a human performed outside this application, after approval\. Approval itself performs no action\./);
});

test('approval badge is rendered from queue state independently of the active view',()=>{
 const h=fs.readFileSync('src/index.html','utf8');
 assert.match(h,/const items=approvalQueue\(agentPort\.list\(\),findingRepo\.agent\.list\(overviewAsOf\)\)/);
 assert.match(h,/#approval-count'\)\.textContent=String\(items\.length\)/);
 assert.match(h,/const refresh=\(\)=>\{renderApprovalQueue\(\)/);
 assert.match(h,/renderControls\(\);renderFindings\(\);renderApprovalQueue\(\)/);
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
