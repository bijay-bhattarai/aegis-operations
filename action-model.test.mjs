import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {AgentAction,AGENT_IDS,ACTION_STATUSES,ACTION_EVENT_TYPES,createActionRepository} from './src/action-model.mjs';
import {approvalQueue} from './src/approval-queue-model.mjs';
const AS_OF='2026-09-14T23:00:00Z';
const proposal=agent_id=>({action_id:'ACT-1',agent_id,action_type:'Proposed review',target:'demo',justification:'Evidence',rule_id:'RULE-1',control_refs:['CONTROL-1'],severity:'high',proposed_at:'2026-09-13T20:00:00Z',rollback_procedure:'Human recovery'});
const decision={approver:'human:demo-reviewer',decided_at:'2026-09-13T21:00:00Z',decision_rationale:'Evidence reviewed'};
const submission={submitted_at:'2026-09-13T20:30:00Z'};
const expiry={actor:{type:'person',id:'human:demo-reviewer'},expired_at:'2026-09-13T22:00:00Z',reason:'Review window ended'};
const execution={executor:'human:operator',executed_at:'2026-09-13T22:00:00Z'};
const record=action=>action.project(AS_OF);
const edges={proposed:['pending_approval','expired'],pending_approval:['approved','rejected','expired'],approved:['executed','expired'],rejected:[],expired:[],executed:[]};
function at(status){
 const a=new AgentAction(proposal('soc'));
 if(status==='proposed')return a;
 if(status==='expired'){a.transition('expired',expiry);return a;}
 a.transition('pending_approval',submission);
 if(status==='pending_approval')return a;
 a.transition(status==='rejected'?'rejected':'approved',decision);
 if(status==='executed')a.transition('executed',execution);
 return a;
}
for(const agent of AGENT_IDS)test(agent+': restricted agent port and record-only review',()=>{
 const {agent:port,review}=createActionRepository();
 const r=port.propose(proposal(agent));
 assert.equal(r.status,'proposed');assert.equal(r.approver,null);
 for(const method of ['decide','recordExecution','execute','transition'])assert.equal(port[method],undefined);
 assert.throws(()=>review.recordExecution(r.action_id,execution));
 port.submit(r.action_id,submission);
 assert.throws(()=>review.decide(r.action_id,'executed',decision));
 review.decide(r.action_id,'approved',decision);
 review.recordExecution(r.action_id,execution);
 assert.equal(port.get(r.action_id,AS_OF).status,'executed');
});
for(const from of ACTION_STATUSES)for(const to of ACTION_STATUSES)test(from+' → '+to,()=>{
 const a=at(from),before=record(a);
 const meta=['approved','rejected'].includes(to)?decision:to==='executed'?execution:to==='pending_approval'?submission:to==='expired'?expiry:{};
 if(edges[from].includes(to)){a.transition(to,meta);assert.equal(record(a).status,to);}
 else{assert.throws(()=>a.transition(to,meta));assert.deepEqual(record(a),before);}
});
test('approval requires identity, timestamp and rationale; failed writes are atomic',()=>{
 for(const bad of [{},{...decision,approver:''},{...decision,approver:' '},{...decision,decided_at:null},{...decision,decided_at:'bad'},{...decision,decision_rationale:''},{...decision,decided_at:'2026-09-12T21:00:00Z'}]){
  const a=at('pending_approval');assert.throws(()=>a.transition('approved',bad));assert.equal(record(a).status,'pending_approval');
 }
});
test('approval and rejection cannot be backdated before the proposal',()=>{
 for(const outcome of ['approved','rejected']){
  const a=at('pending_approval'),before=record(a);
  assert.throws(()=>a.transition(outcome,{...decision,decided_at:'2026-09-13T19:59:59Z'}),/Decision precedes proposal/);
  assert.deepEqual(record(a),before);
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
 for(const id of ['ACT-CRIT-NEW','ACT-CRIT-OLD','ACT-DONE'])repo.agent.submit(id,submission);
 repo.review.decide('ACT-DONE','rejected',{...decision,decided_at:'2026-09-13T21:00:00Z'});
 const queue=approvalQueue(repo.agent.list(AS_OF),[{finding_id:'F-1',action_refs:['ACT-CRIT-OLD']},{finding_id:'F-2',action_refs:['ACT-CRIT-OLD','ACT-LOW']}]);
 assert.deepEqual(queue.map(action=>action.action_id),['ACT-CRIT-OLD','ACT-CRIT-NEW','ACT-LOW']);
 assert.deepEqual(queue[0].linked_finding_ids,['F-1','F-2']);assert.equal(queue[2].status,'proposed');
 assert.throws(()=>queue.push({}));assert.throws(()=>queue[0].linked_finding_ids.push('F-3'));
});
test('constructor and snapshots cannot bypass transitions',()=>{
 for(const status of ACTION_STATUSES.filter(s=>s!=='proposed'))assert.throws(()=>new AgentAction({...proposal('soc'),status}));
 assert.throws(()=>new AgentAction({...proposal('soc'),approver:'fake'}));
 const a=at('proposed');assert.throws(()=>{record(a).status='executed'});assert.throws(()=>record(a).control_refs.push('x'));
 assert.equal(record(a).status,'proposed');
});
test('execution time cannot precede approval',()=>{
 const a=at('approved');assert.throws(()=>a.transition('executed',{...execution,executed_at:'2026-09-13T20:00:00Z'}));assert.equal(record(a).status,'approved');
});
test('action timestamps reject nonexistent calendar dates and accept a valid leap day',()=>{
 for(const date of ['2026-02-30','2025-02-29','2026-04-31','2026-13-01']){
  assert.throws(()=>new AgentAction({...proposal('soc'),proposed_at:date+'T00:00:00Z'}),/UTC timestamp/);
 }
 const action=new AgentAction({...proposal('soc'),proposed_at:'2028-02-29T00:00:00Z'});
 assert.equal(action.project('2028-02-29T00:00:00Z').proposed_at,'2028-02-29T00:00:00Z');
});
test('append-only action history drives reproducible projections without changing record shape',()=>{
 const repo=createActionRepository(),created=repo.agent.propose(proposal('soc'));
 repo.agent.submit(created.action_id,submission);repo.review.decide(created.action_id,'approved',decision);repo.review.recordExecution(created.action_id,execution);
 assert.equal(repo.agent.get(created.action_id,'2026-09-13T20:00:00Z').status,'proposed');
 assert.equal(repo.agent.get(created.action_id,'2026-09-13T20:30:00Z').status,'pending_approval');
 assert.equal(repo.agent.get(created.action_id,'2026-09-13T21:00:00Z').status,'approved');
 assert.equal(repo.agent.get(created.action_id,'2026-09-13T22:00:00Z').status,'executed');
 const projected=repo.agent.get(created.action_id,AS_OF),history=repo.agent.history(created.action_id,AS_OF);
 assert.deepEqual(Object.keys(projected),['action_id','agent_id','action_type','target','justification','rule_id','severity','rollback_procedure','control_refs','proposed_at','status','approver','decided_at','decision_rationale','executed_at','executor','expired_at','expiry_actor']);
 assert.equal(projected.executor,'human:operator');assert.equal(projected.expired_at,null);assert.equal(projected.expiry_actor,null);
 assert.deepEqual(history.map(event=>event.type),['proposed','submitted','approved','external_execution_attested']);
 assert.deepEqual(history.map(event=>event.actor),[{type:'agent',id:'soc'},{type:'agent',id:'soc'},{type:'person',id:'human:demo-reviewer'},{type:'person',id:'human:operator'}]);
 assert.deepEqual(history.map(event=>event.occurred_at),['2026-09-13T20:00:00Z','2026-09-13T20:30:00Z','2026-09-13T21:00:00Z','2026-09-13T22:00:00Z']);
 assert.throws(()=>history.push({}));assert.throws(()=>{history[0].actor.id='changed';});
 assert.throws(()=>repo.agent.get(created.action_id));assert.throws(()=>repo.agent.list());
 assert.deepEqual(ACTION_EVENT_TYPES,['proposed','submitted','approved','rejected','expired','external_execution_attested']);
});
test('expiry requires a named actor, timestamp, and reason',()=>{
 for(const bad of [{},{expired_at:expiry.expired_at,reason:expiry.reason},{actor:expiry.actor,reason:expiry.reason},{actor:expiry.actor,expired_at:expiry.expired_at},{...expiry,actor:{type:'person',id:''}},{...expiry,actor:{type:'agent',id:'unknown'}}]){
   const action=new AgentAction(proposal('soc')),before=record(action);assert.throws(()=>action.transition('expired',bad));assert.deepEqual(record(action),before);
 }
 const action=new AgentAction(proposal('soc'));action.transition('expired',{...expiry,actor:{type:'system',id:'review-window-policy'}});
 assert.deepEqual(action.history(AS_OF).at(-1).actor,{type:'system',id:'review-window-policy'});
 const projected=record(action);assert.equal(projected.expired_at,expiry.expired_at);assert.deepEqual(projected.expiry_actor,{type:'system',id:'review-window-policy'});assert.equal(projected.executor,null);
});
test('approver and executor person IDs reuse the collector impersonation guard',()=>{
 const spoofed=['identity','IDENTITY','Identity Agent','аgent-1','Ag\u200Bent'];
 for(const id of spoofed){
   const decisionAction=at('pending_approval'),decisionBefore=decisionAction.history(AS_OF);
   assert.throws(()=>decisionAction.transition('approved',{...decision,approver:id}),/Person action actor ID cannot identify an agent/);assert.deepEqual(decisionAction.history(AS_OF),decisionBefore);
   const executionAction=at('approved'),executionBefore=executionAction.history(AS_OF);
   assert.throws(()=>executionAction.transition('executed',{...execution,executor:id}),/Person action actor ID cannot identify an agent/);assert.deepEqual(executionAction.history(AS_OF),executionBefore);
 }
 const action=at('pending_approval');action.transition('approved',{...decision,approver:'bijay'});action.transition('executed',{...execution,executor:'bijay'});
 const projected=record(action);assert.equal(projected.approver,'bijay');assert.equal(projected.executor,'bijay');
});
test('action supersede is human-only, append-only, and preserves the original event byte-for-byte',()=>{
 const repo=createActionRepository(),created=repo.agent.propose(proposal('soc'));repo.agent.submit(created.action_id,submission);
 assert.equal(repo.agent.supersede,undefined);
 const before=repo.review.history(created.action_id,AS_OF),original=JSON.stringify(before[1]);
 const entity=new AgentAction(proposal('soc'));entity.transition('pending_approval',submission);
 assert.throws(()=>entity.supersede(2,{type:'submitted'},{actor_id:'human:corrector',occurred_at:'2026-09-13T20:45:00Z',reason:'Correction'}),/Human review capability required/);
 repo.review.supersede(created.action_id,2,{type:'submitted'},{actor_id:'human:corrector',occurred_at:'2026-09-13T20:45:00Z',reason:'Submission time was recorded incorrectly'});
 const after=repo.review.history(created.action_id,AS_OF);
 assert.equal(JSON.stringify(after[1]),original);assert.equal(after[2].supersedes_event_id,2);assert.deepEqual(after[2].actor,{type:'person',id:'human:corrector'});
 assert.equal(repo.review.get(created.action_id,AS_OF).status,'pending_approval');
 assert.throws(()=>repo.review.supersede(created.action_id,2,{type:'submitted'},{actor_id:'human:corrector',occurred_at:'2026-09-13T20:46:00Z',reason:'Again'}),/already superseded/);
});
test('superseding an earlier decision preserves later lifecycle events',()=>{
 const repo=createActionRepository(),created=repo.agent.propose(proposal('soc'));repo.agent.submit(created.action_id,submission);
 repo.review.decide(created.action_id,'approved',decision);repo.review.recordExecution(created.action_id,execution);
 repo.review.supersede(created.action_id,3,{type:'approved',approver:'human:second-reviewer',decision_rationale:'Corrected reviewer attribution'},{actor_id:'human:records-reviewer',occurred_at:'2026-09-13T22:30:00Z',reason:'Decision attribution was recorded incorrectly'});
 const projected=repo.review.get(created.action_id,AS_OF);
 assert.equal(projected.status,'executed');assert.equal(projected.approver,'human:second-reviewer');assert.equal(projected.executed_at,execution.executed_at);
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
 assert.match(h,/approvalQueue\(agentPort\.list\(overviewAsOf\),findingRepo\.agent\.list\(overviewAsOf\)\)/);
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
 assert.match(h,/const items=approvalQueue\(agentPort\.list\(overviewAsOf\),findingRepo\.agent\.list\(overviewAsOf\)\)/);
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
