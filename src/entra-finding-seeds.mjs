export const ENTRA_SNAPSHOT=Object.freeze({
  evidence_id:'ENTRA-SNAPSHOT-2026-08-23',
  source:'Microsoft Entra ID',
  collected_by:Object.freeze({type:'agent',id:'identity'}),
  collected_at:'2026-08-23T20:40:22Z',
  artifact_ref:Object.freeze({
    type:'export',
    locator:'artifact://entra/entitlement-snapshot-2026-08-23',
    content_hash:Object.freeze({algorithm:'sha256',value:'f660e5b6c6787c0f54158840ccb00a120089d4c677bcea52c7fa1cce81d1239a'}),
    verification_status:'unverified'
  })
});

const matrix=(likelihood,impact)=>Object.freeze({risk_matrix:Object.freeze({likelihood,impact})});
const user=(value,label,principal_name,department,job_title,privileged)=>({type:'user',id:{namespace:'microsoft_entra_id',value},label,details:{principal_name,department,job_title,privileged}});
const facts=(...entries)=>entries.map(([key,value])=>({key,value}));
const deepFreeze=value=>{if(value&&typeof value==='object'&&!Object.isFrozen(value)){for(const child of Object.values(value))deepFreeze(child);Object.freeze(value);}return value;};

export const ENTRA_FINDING_SEEDS=Object.freeze([
  {finding_id:'IAM-0001',rule_id:'R05',title:'Missing expected Store Associate role',subject:user('10000000-0000-4000-8000-000000000001','Amara Osei','aosei@contoso.onmicrosoft.com','Store Operations','Store Associate',false),evidence_lines:facts(['expected_group','ROLE-Store-Associate'],['assigned_roles','(none)']),control_refs:['AC-2'],severity_input:matrix('high','low')},
  {finding_id:'IAM-0002',rule_id:'R05',title:'Missing expected HR Coordinator role',subject:user('10000000-0000-4000-8000-000000000003','Bea Lindqvist','blindqvist@contoso.onmicrosoft.com','HR','HR Coordinator',false),evidence_lines:facts(['expected_group','ROLE-HR-Coordinator'],['assigned_roles','(none)']),control_refs:['AC-2'],severity_input:matrix('high','low')},
  {finding_id:'IAM-0003',rule_id:'R05',title:'Missing expected Finance Controller role',subject:user('10000000-0000-4000-8000-000000000005','Camila Restrepo','crestrepo@contoso.onmicrosoft.com','Finance','Controller',false),evidence_lines:facts(['expected_group','ROLE-Finance-Controller'],['assigned_roles','(none)']),control_refs:['AC-2'],severity_input:matrix('high','low')},
  {finding_id:'IAM-0004',rule_id:'R01',title:'Store Operations user holds ROLE-IT-SysAdmin',subject:user('10000000-0000-4000-8000-000000000007','Devon Reyes','dreyes@contoso.onmicrosoft.com','Store Operations','Shift Lead',true),evidence_lines:facts(['group','ROLE-IT-SysAdmin']),control_refs:['AC-6','AC-6(1)'],severity_input:matrix('high','high')},
  {finding_id:'IAM-0005',rule_id:'R02',title:'Retains both ROLE-IT-Helpdesk and ROLE-IT-SysAdmin',subject:user('10000000-0000-4000-8000-000000000015','Owen Fitzgerald','ofitzgerald@contoso.onmicrosoft.com','IT','Systems Administrator',true),evidence_lines:facts(['group','ROLE-IT-Helpdesk'],['group','ROLE-IT-SysAdmin']),control_refs:['AC-2(3)','AC-6'],severity_input:matrix('medium','medium')},
  {finding_id:'IAM-0006',rule_id:'R03',title:'Holds toxic pair ROLE-Finance-AP and ROLE-Finance-Controller',subject:user('10000000-0000-4000-8000-000000000016','Peter Nkemelu','pnkemelu@contoso.onmicrosoft.com','Finance','Accounts Payable Clerk',true),evidence_lines:facts(['group','ROLE-Finance-AP'],['group','ROLE-Finance-Controller']),control_refs:['AC-5'],severity_input:matrix('medium','high')},
  {finding_id:'IAM-0007',rule_id:'R05',title:'Missing expected IT SysAdmin role',subject:user('10000000-0000-4000-8000-000000000017','Priya Raman','praman@contoso.onmicrosoft.com','IT','Systems Administrator',false),evidence_lines:facts(['expected_group','ROLE-IT-SysAdmin'],['assigned_roles','(none)']),control_refs:['AC-2'],severity_input:matrix('high','low')},
  {finding_id:'IAM-0008',rule_id:'R04',title:'Disabled account retains group entitlements',subject:user('10000000-0000-4000-8000-000000000018','Rashid Malik','rmalik@contoso.onmicrosoft.com','Store Operations','Store Associate',false),evidence_lines:facts(['account_enabled',false],['group','DEPT-Store-Operations'],['group','ROLE-Store-Associate']),control_refs:['AC-2(1)','AC-2(4)'],severity_input:matrix('medium','high')},
  {finding_id:'IAM-0009',rule_id:'R01',title:'Finance user holds ROLE-Store-Associate',subject:user('10000000-0000-4000-8000-000000000020','Terrence Boyd','tboyd@contoso.onmicrosoft.com','Finance','Accounts Payable Clerk',false),evidence_lines:facts(['group','ROLE-Store-Associate']),control_refs:['AC-6','AC-6(1)'],severity_input:matrix('high','medium')},
  {finding_id:'IAM-0010',rule_id:'R05',title:'Missing expected HR Coordinator role',subject:user('10000000-0000-4000-8000-000000000021','Tomas Njoku','tnjoku@contoso.onmicrosoft.com','HR','HR Coordinator',false),evidence_lines:facts(['expected_group','ROLE-HR-Coordinator'],['assigned_roles','(none)']),control_refs:['AC-2'],severity_input:matrix('high','low')}
].map(seed=>deepFreeze({...seed,control_refs:[...seed.control_refs],finding_type:'identity',evidence_id:ENTRA_SNAPSHOT.evidence_id,created_at:ENTRA_SNAPSHOT.collected_at,agent_id:'identity'})));

export const ENTRA_QUEUE_RULES=Object.freeze({R01:'priority-review',R02:'standard-review',R03:'priority-review',R04:'standard-review',R05:'standard-review'});
