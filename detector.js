/* Shadow Triage core: raw events -> features -> weighted rules -> explained verdict. No DOM; runs in browser and Node. */
const CTX={org:{brand:'northstar',domains:['northstarlabs.example']},trusted:['microsoft.com','google.com','paypal.com'],baseline:{ips:['10.20.'],devices:['mira-laptop','arjun-laptop']}};
const m=t=>{const[a,b]=t.split(':').map(Number);return a*60+b};
const L=s=>s>=50?'High':s>=25?'Medium':'Low';
function lev(a,b){const d=[...Array(a.length+1)].map((_,i)=>[i,...Array(b.length).fill(0)]);for(let j=1;j<=b.length;j++)d[0][j]=j;
 for(let i=1;i<=a.length;i++)for(let j=1;j<=b.length;j++)d[i][j]=Math.min(d[i-1][j]+1,d[i][j-1]+1,d[i-1][j-1]+(a[i-1]===b[j-1]?0:1));return d[a.length][b.length]}
const inOrg=(d,c)=>c.org.domains.some(o=>d===o||d.endsWith('.'+o));
function lookalike(domain,ctx=CTX,extra=[]){
 const d=String(domain||'').toLowerCase().trim().replace(/^www\./,'');
 if(!d.includes('.'))return{hit:false,why:'Not a valid domain'};
 if(inOrg(d,ctx))return{hit:false,why:'Matches an organization domain'};
 const trusted=[...ctx.org.domains,...ctx.trusted,...extra.map(x=>x.toLowerCase())];
 if(trusted.some(t=>d===t||d.endsWith('.'+t)))return{hit:false,why:'Exact trusted domain'};
 const lab=x=>{const p=x.split('.');return p[p.length-2]},l=lab(d);
 if(ctx.org.brand&&l.includes(ctx.org.brand))return{hit:true,why:`contains the brand "${ctx.org.brand}" but is not an organization domain`};
 for(const t of trusted){const k=lev(l,lab(t));if(l.length>=5&&k<=2)return{hit:true,why:`"${d}" is ${k} edit(s) from trusted "${t}"${k===0?' (different TLD)':''}`}}
 return{hit:false,why:'No lookalike signal (this is not proof the domain is safe)'};
}
function features(e,ctx=CTX){
 const f={},b=ctx.baseline,t=e.type||'telemetry';
 const ipKnown=!!e.ip&&b.ips.some(p=>e.ip.startsWith(p));
 f.new_ip=!!e.ip&&!ipKnown;
 f.new_dev=e.device_known===false||(!!e.device&&!b.devices.includes(e.device));
 f.loc_change=e.location_change===true;
 f.mfa_failed=e.mfa_result==='failed'||(t==='mfa'&&['denied','failed'].includes(e.result));
 f.mfa_passed=e.mfa_result==='passed';
 f.mfa_unreq=t==='mfa'&&e.result==='approved'&&e.user_initiated===false;
 f.rec_open=e.account_change==='recovery_page_opened';
 f.rec_change=e.account_change==='recovery_email_change_requested';
 f.rec_done=e.account_change==='recovery_email_changed';
 if(t==='email'){const dom=(e.from||'').split('@')[1]||'',txt=(e.subject||'')+' '+(e.body||'');
  f.lure=!inOrg(dom,ctx)&&/verify|confirm|password|sign.?in|log.?in|payroll access|account/i.test(txt)&&/urgent|expires|immediately|today|suspend|final|within/i.test(txt);
  const la=[dom,...(e.links||[]).map(u=>u.replace(/^https?:\/\//,'').split('/')[0])].map(x=>lookalike(x,ctx)).find(x=>x.hit);
  f.lookalike=!!la;f.la_why=la?la.why:''}
 if(t==='mailrule'){const dom=(e.to||'').split('@')[1]||'';f.fwd_ext=e.action==='forward'&&!inOrg(dom,ctx)}
 f.fail_known=t==='signin'&&e.result==='fail'&&ipKnown;
 return f}
const RULES=[
{id:'R1',cat:'phishing',w:30,n:'Urgent credential-lure email from an external sender',t:f=>f.lure,fp:'Real vendors send payroll notices. Verify the sender through a trusted channel.',hyp:'The user may have clicked the link or entered credentials (not in the evidence).',miss:'Link target, message headers, and whether the user clicked or submitted anything.',act:'Quarantine the message and search other mailboxes for it. Do not open the link.'},
{id:'R2',cat:'phishing',w:15,n:'Sender or link domain imitates a trusted or brand domain',t:f=>f.lookalike,fp:'Partners sometimes use similar-named domains. Check registration and ownership.',hyp:'The domain was registered to impersonate the organization.',miss:'Domain registration date and owner.',act:'Block the domain at mail and web gateways. Do not visit or test it.'},
{id:'R3',cat:'access',w:25,n:'Sign-in from an unfamiliar device on a new network or location',t:f=>f.new_dev&&(f.new_ip||f.loc_change),fp:'Could be a genuine new laptop or travel. Weak alone; stronger with MFA and account-change signals.',hyp:'Credentials may be in the hands of a third party.',miss:'IP geolocation, ASN and reputation for the sign-in.',act:'Revoke active sessions and refresh tokens; reset the password via a trusted channel.'},
{id:'R4',cat:'mfa',w:40,n:'MFA approved but the user says they did not initiate it',t:f=>f.mfa_unreq,fp:'The user may have forgotten approving it. The claim is unverified.',hyp:'The attacker may have relayed or fatigued the MFA push.',miss:'MFA push log: source IP, timing, and whether number-matching was on.',act:'Require number-matching MFA and review recent push approvals.'},
{id:'R5',cat:'persistence',w:50,n:'Mailbox rule forwarding to an external address',t:f=>f.fwd_ext,fp:'Some staff forward to a personal or partner address legitimately. Confirm with the user.',hyp:'The rule may be attacker persistence for collecting mail.',miss:'Who created the rule, from which session, and whether any mail was forwarded (data theft is NOT proven).',act:'Remove the external forwarding rule; audit mailbox rules, delegates and OAuth grants.'},
{id:'R6',cat:'mfa',w:15,n:'MFA failed from an unfamiliar device',t:f=>f.mfa_failed&&f.new_dev,fp:'Users mistype codes. A single failure is common; it matters because of what follows.',hyp:'Someone without the second factor attempted access.',miss:'Why MFA failed: code delivery path and device.',act:'Review failed-MFA history for this account.'},
{id:'R7',cat:'recovery',w:15,n:'Recovery page opened from an unfamiliar device',t:f=>f.rec_open&&f.new_dev,fp:'A genuine user who forgot a password does this. Weak alone.',hyp:'Someone is probing the recovery flow.',miss:'Whether the recovery flow was completed.',act:'Hold any pending recovery changes until the owner verifies.'},
{id:'R8',cat:'recovery',w:40,n:'Recovery email change requested from an unfamiliar device',t:f=>f.rec_change&&f.new_dev,fp:'Completion is unconfirmed. A request is not a completed takeover.',hyp:'A completed change would give lasting control of the account.',miss:'Whether the recovery email change was completed or cancelled.',act:'Hold or cancel the pending recovery change until the owner confirms.'},
{id:'R9',cat:'recovery',w:60,n:'Recovery email change completed from an unfamiliar device',t:f=>f.rec_done&&f.new_dev,fp:'Confirm with the owner; a genuine owner on a new device is possible.',hyp:'Account control may already have transferred.',miss:'Owner confirmation and the new recovery address.',act:'Revert the recovery email and lock the account pending owner verification.'},
{id:'R10',cat:'mfa',w:15,n:'MFA passed shortly after a failure from the same unfamiliar context',t:(f,p,e)=>f.mfa_passed&&f.new_dev&&p.some(x=>x.f.mfa_failed&&x.f.new_dev&&m(e.time)-m(x.e.time)<=10),fp:'A user retrying after a typo looks identical. Delivery logs separate the two.',hyp:'An attacker may have retried MFA until it passed.',miss:'Delivery path of the code that passed.',act:'Require re-verification of any session started after the failure.'},
{id:'R11',cat:'context',w:5,n:'Failed sign-in from the usual network (ambiguous, weak)',t:f=>f.fail_known,fp:'Could be a lockout after a session reset, or noise. Do not over-read it.',hyp:'',miss:'',act:''}
];
const CHAINS=[
{n:'Lure, unfamiliar sign-in, unrequested MFA approval, external forwarding rule',hyp:'Phishing-led account takeover with mailbox persistence.',p:[f=>f.lure,f=>f.new_ip,f=>f.mfa_unreq,f=>f.fwd_ext]},
{n:'MFA failure, MFA pass, recovery email change, all from an unfamiliar device',hyp:'Account-recovery takeover attempt.',p:[f=>f.mfa_failed&&f.new_dev,f=>f.mfa_passed&&f.new_dev,f=>f.rec_change&&f.new_dev]}];
function seq(rows,P){let i=0,s=0;for(const r of rows){while(i<P.length&&P[i](r.f)){if(!i)s=m(r.e.time);i++;if(i===P.length)return m(r.e.time)-s<=20}}return false}
function describe(e){if(e.note)return e.note;return Object.entries(e).filter(([k])=>!['id','time','type'].includes(k)).map(([k,v])=>k+'='+v).join(' ')}
const uniq=a=>[...new Set(a.filter(Boolean))];
function analyze(events,ctx=CTX){
 const ev=[...events].sort((a,b)=>m(a.time)-m(b.time)),done=[];
 const rows=ev.map(e=>{const f=features(e,ctx),hits=RULES.filter(r=>r.t(f,done,e));const row={e,f,hits,score:Math.min(100,hits.reduce((a,r)=>a+r.w,0))};done.push(row);return row});
 const chains=CHAINS.filter(c=>seq(rows,c.p));
 const flagged=rows.flatMap(r=>r.hits.filter(h=>h.w>5));
 const cats=uniq(flagged.map(h=>h.cat)),max=Math.max(0,...rows.map(r=>r.score));
 const score=Math.min(100,max+10*Math.max(0,cats.length-1)+(chains.length?15:0));
 const fired=[...new Map(flagged.sort((a,b)=>b.w-a.w).map(h=>[h.id,h])).values()];
 return{rows,chains,cats,score,level:L(score),conf:cats.length?Math.min(90,Math.max(25,35+14*cats.length-(chains.length?0:10))):80,
  facts:rows.map(r=>`${r.e.time} ${describe(r.e)}`),
  hyp:uniq([...chains.map(c=>c.hyp),...fired.map(h=>h.hyp)]),
  missing:uniq([...fired.map(h=>h.miss),fired.length?'Confirmation from the account owner through a trusted channel.':'']),
  act:uniq(fired.map(h=>h.act)),
  lim:['Hand-set heuristic weights, not trained on labeled data','Small sample and a configured baseline, not learned per-user history','No attacker identity or data-theft claim can be made from this evidence']};
}
const SC={
northstar:{title:'Northstar Labs: Mira',events:[
{id:'N1',time:'08:41',type:'email',from:'hr@payroll-northstar.example',subject:'Urgent: payroll access expires today',body:'Please verify your account to keep payroll access.',links:[],note:'Email from payroll-northstar.example (external): "Urgent: payroll access expires today", asks Mira to verify her account'},
{id:'N2',time:'08:44',type:'signin',result:'success',ip:'203.0.113.45',device:'new-browser',note:'Sign-in succeeds from an unfamiliar IP and a new browser'},
{id:'N3',time:'08:45',type:'mfa',result:'approved',user_initiated:false,note:'MFA push approved; Mira says she did not initiate it'},
{id:'N4',time:'08:47',type:'mailrule',action:'forward',to:'collector@mailbox-external.example',note:'Mailbox forwarding rule created to an external address'},
{id:'N5',time:'08:51',type:'signin',result:'fail',ip:'10.20.4.17',device:'mira-laptop',note:'Second sign-in attempt from the usual office network fails'},
{id:'N6',time:'08:54',type:'report',note:'Mira reports the email to IT'}]},
variantB:{title:'Variant B: Account recovery',events:[
{id:'B-211',time:'11:02',type:'telemetry',device_known:true,location_change:false,mfa_result:'passed',account_change:'none',note:'Usual device and location'},
{id:'B-212',time:'11:06',type:'telemetry',device_known:false,location_change:true,mfa_result:'failed',account_change:'recovery_page_opened',note:'MFA failed; recovery page viewed'},
{id:'B-213',time:'11:08',type:'telemetry',device_known:false,location_change:true,mfa_result:'passed',account_change:'recovery_email_change_requested',note:'Request observed; completion not confirmed'},
{id:'B-214',time:'11:16',type:'telemetry',device_known:true,location_change:false,mfa_result:'passed',account_change:'none',note:'Later familiar sign-in; user confirmation unavailable'}]},
benign:{title:'Mock negative control: travelling employee',events:[
{id:'T-1',time:'09:10',type:'telemetry',device_known:true,location_change:true,mfa_result:'passed',account_change:'none',note:'Known laptop, new city (conference), MFA passed'},
{id:'T-2',time:'09:15',type:'mailrule',action:'forward',to:'colleague@northstarlabs.example',note:'Forwarding rule to a colleague inside the organization'}]}};
const SAMPLE=`event_id,time,device_known,location_change,mfa_result,account_change,analyst_note
B-211,11:02,yes,no,passed,none,Usual device and location
B-212,11:06,no,yes,failed,recovery_page_opened,MFA failed; recovery page viewed
B-213,11:08,no,yes,passed,recovery_email_change_requested,Request observed; completion not confirmed
B-214,11:16,yes,no,passed,none,Later familiar sign-in; user confirmation unavailable`;
function parseInput(txt){
 txt=txt.trim();if(txt[0]==='['||txt[0]==='{'){const j=JSON.parse(txt);return(Array.isArray(j)?j:[j]).map((e,i)=>({id:e.id||'E'+(i+1),...e}))}
 const rows=txt.split(/\r?\n/).map(l=>l.split(/\t|,/).map(s=>s.trim()));if(/event/i.test(rows[0][0]))rows.shift();
 return rows.filter(r=>r.length>=5&&/^\d{1,2}:\d{2}$/.test(r[1])).map(r=>({id:r[0],time:r[1],type:'telemetry',device_known:r[2]==='yes',location_change:r[3]==='yes',mfa_result:r[4],account_change:r[5],note:r.slice(6).join(', ')||r[5]}));
}
function selfTests(){
 const A=k=>analyze(SC[k].events),N=A('northstar'),B=A('variantB'),T=A('benign'),R=(a,id)=>a.rows.find(r=>r.e.id===id).score;
 const drop=(k,ids)=>analyze(SC[k].events.filter(e=>!ids.includes(e.id)));
 const one=e=>analyze([{id:'X',time:'10:00',...e}]);
 return[
 ['Northstar: whole case is High with the attack chain matched',N.level==='High'&&N.chains.length===1],
 ['Northstar: external forwarding rule (N4) is High',L(R(N,'N4'))==='High'],
 ['Northstar: lookalike lure (N1), new-device sign-in (N2) and unrequested MFA (N3) each at least Medium',[R(N,'N1'),R(N,'N2'),R(N,'N3')].every(s=>s>=25)],
 ['Northstar: ambiguous failed office sign-in (N5) and the user report (N6) stay Low',L(R(N,'N5'))==='Low'&&L(R(N,'N6'))==='Low'],
 ['Variant B: B-211 Low, B-212 at least Medium, B-213 High, B-214 Low',L(R(B,'B-211'))==='Low'&&R(B,'B-212')>=25&&L(R(B,'B-213'))==='High'&&L(R(B,'B-214'))==='Low'],
 ['Variant B: MFA fail, pass, recovery change chain matched',B.chains.length===1],
 ['Mock negative control (travelling employee, internal forwarding) is Low with no chain',T.level==='Low'&&T.chains.length===0],
 ['Ablation: removing the forwarding rule breaks the chain and lowers the case score',drop('northstar',['N4']).chains.length===0&&drop('northstar',['N4']).score<N.score],
 ['Ablation: removing lure and MFA events lowers the score further',drop('northstar',['N1','N3','N4']).score<drop('northstar',['N4']).score],
 ['Known device with a location change alone is not flagged',one({type:'telemetry',device_known:true,location_change:true,mfa_result:'passed',account_change:'none'}).level==='Low'],
 ['Forwarding inside the org scores 0; forwarding outside scores High',one({type:'mailrule',action:'forward',to:'a@northstarlabs.example'}).score===0&&L(one({type:'mailrule',action:'forward',to:'a@x.example'}).score)==='High'],
 ['Domain check: brand lookalike, 1-edit typo and TLD swap flagged',lookalike('payroll-northstar.example').hit&&lookalike('micr0soft.com').hit&&lookalike('microsoft.co').hit],
 ['Domain check: org domain, subdomain and unrelated domain not flagged',!lookalike('northstarlabs.example').hit&&!lookalike('mail.northstarlabs.example').hit&&!lookalike('github.com').hit],
 ['Deterministic: same input gives identical output',JSON.stringify(analyze(SC.northstar.events).score)===JSON.stringify(N.score)&&analyze(SC.variantB.events).level===B.level],
 ['No attribution or data-theft claim in generated text',!/attacker identified|data (was )?stolen/i.test(JSON.stringify([N.hyp,N.missing,N.act,N.lim]))],
 ['Parser: CSV gives 4 events; JSON array parses',parseInput(SAMPLE).length===4&&parseInput('[{"time":"09:00","type":"report"}]').length===1]
 ].map(([n,ok])=>[n,!!ok]);
}
if(typeof module!=='undefined')module.exports={m,L,CTX,RULES,CHAINS,lookalike,features,analyze,parseInput,SC,SAMPLE,selfTests};
