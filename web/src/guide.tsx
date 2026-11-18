import React from 'react';
import {bytes,utc,type Row} from './lib';
import {PageHead,Panel,Notice,State,Badge,useApp,useData} from './ui';

const terms=[
 ['Collector','Configured logs parh kar server ko bhejne wala agent. Online heartbeat collection success ka complete proof nahi.'],
 ['Evidence','Preserved observation; har observation confirmed attack nahi hoti.'],
 ['Case','Evidence, notes aur reports ka investigation folder. Same naam ke cases ko ID se pehchanein.'],
 ['Hash','Content ka fingerprint. Change detect karne mein madad karta hai; source ki sachai prove nahi karta.'],
 ['Signature','Trusted public key ke against signed content verify hota hai. Report signatures separate files mein hain.'],
 ['Checkpoint','Archive ki aik waqt ki signed state. Independent witness ke baghair local-only assurance hai.'],
 ['COMPLETE / VALID','COMPLETE ka matlab job finish. VALID ka matlab verification checks pass. Dono alag hain.'],
 ['Lab simulation','Docker fixed requests Windows decoy ko bhejti hai. Personal Windows account hack nahi hota.'],
];

export function GettingStarted(){
 const {session,go}=useApp();const admin=session.user.role==='admin';
 const health=useData<Row>(admin?'/health/pipeline':null,15000);
 const collectors=useData<Row[]>('/collectors',15000);
 const data=health.data;const staged=data?.receipts.find((r:Row)=>r.state==='STAGED')?.count??0;
 return <>
  <PageHead eyebrow="START HERE / ASAN GUIDE" title="Start here · Asaan rehnumai" description="Pehle connection, phir aik actual observation, phir case aur report. Har step ka result verify karein." actions={<button className="secondary" onClick={()=>{health.reload();collectors.reload()}}>Refresh readiness</button>}/>
  <Notice>Browser dashboard dikhata hai; launcher terminal server chalata hai. Terminal khula rakhein. Docker is native Windows + Docker workflow ke liye zaroori nahi.</Notice>
  <div className="setup-steps">
   <article><Badge>01 · WINDOWS SETUP</Badge><h2>Collector connect karein</h2><p>Fresh laptop par pehle administrator banayein. Server terminal mein Ctrl+C dabayein, phir project folder ka <strong>Setup-Windows-Collector.cmd</strong> double-click karein. Yeh local System/Application collection provision karke server start karta hai. Existing credentials retain hoti hain.</p><p>Collector heartbeat ke baad actual event test zaroor karein. Kisi doosre laptop ka agent.json copy na karein.</p><button className="secondary" onClick={()=>go('collectors')}>Open collectors</button></article>
   <article><Badge>02 · REAL TEST EVENT</Badge><h2>Harmless Windows event</h2><p>Apne Windows laptop ki Administrator PowerShell mein yeh command chalayein. Yeh informational test log banati hai, attack nahi.</p><pre>eventcreate /T INFORMATION /ID 100 /L APPLICATION /SO CloudBoxTest /D "CBB-CHECK-001: Windows collection test"</pre><p>15–30 seconds baad exact message dhoondein. No result ho to collector source health aur case access check karein.</p><button className="secondary" onClick={()=>go('evidence?q=CBB-CHECK-001')}>Find my test event</button></article>
   <article><Badge>03 · DOCKER LAB</Badge><h2>Check → Start → Observe</h2><p>Docker Desktop start karein. Lab page par Check Docker connection, phir aik scenario Start karein. Received aur Preserved counts alag hain. Stop aagay ki requests rokta hai; received evidence rehti hai.</p><button className="secondary" onClick={()=>go('lab')}>Open simulation lab</button></article>
   <article><Badge>04 · INVESTIGATE</Badge><h2>Original evidence aur note</h2><p>Run ka Open evidence case click karein. Record click karne se detail khulegi. Original bytes inspect karein. Notes mein observed result aur limitations likhein.</p><button className="secondary" onClick={()=>go('cases')}>Open case workspace</button></article>
   <article><Badge>05 · VERIFY & REPORT</Badge><h2>Report ka snapshot</h2><p>Integrity page se aik verification queue karein. COMPLETE ke baad actual VALID/INVALID result dekhein. Case ke Reports tab se package banayein. Naya note add hua ho to naya package banayein; old package automatically update nahi hota.</p><button className="secondary" onClick={()=>go('reports')}>Open reports</button></article>
   <article><Badge>06 · PRESENT HONESTLY</Badge><h2>Scope explain karein</h2><p>Local verification external witnessing nahi. Signature complete capture ya real compromise prove nahi karti. Cloud, AI, packet sensors aur acquisitions ko apne configured test ke baghair working claim na karein.</p><button className="secondary" onClick={()=>go('integrations')}>Check tools & sensors</button></article>
  </div>
  <Panel title="Collector connection" subtitle="Heartbeat aur actual source capture alag checks hain."><div className="panel-content"><State state={collectors}>{collectors.data?.length?<p>{collectors.data.filter(c=>c.online&&c.state==='ACTIVE').length} online collectors / {collectors.data.length} registered. Check source errors on the Collectors page.</p>:<p>No collectors shown. Fresh machine setup complete karein; role restrictions bhi visibility affect kar sakti hain.</p>}</State></div></Panel>
  {admin&&<Panel title="Preservation health" subtitle="Every 15 seconds while this page is visible. Counts describe the whole deployment."><div className="panel-content"><State state={health}>{data&&<><div className="pipeline-stats"><div><small>Waiting for sealing</small><strong>{staged.toLocaleString()}</strong></div><div><small>Quarantined</small><strong>{data.receipts.find((r:Row)=>r.state==='QUARANTINED')?.count??0}</strong></div><div><small>Disk free</small><strong>{bytes(data.disk_free)}</strong></div></div><p>Last received: {utc(data.last_received_at)}</p><p>Oldest pending: {data.oldest_pending_at?utc(data.oldest_pending_at):'None'}</p><p>Intake worker last completed tick: {utc(data.worker.last_tick)}</p><p>Workers: {data.workers_enabled?'Enabled':'Disabled'} · Witness: {data.witness_configured?(data.witness_independent?'Configured as independent; verify receipts':'Configured, independence not established'):'Not configured — local checks only'}</p>{data.worker.last_error&&<Notice tone="danger">{data.worker.last_error}</Notice>}<button className="secondary" onClick={()=>go('jobs')}>Inspect background jobs</button></>}</State></div></Panel>}
  <Panel title="Project ki simple dictionary"><div className="panel-content">{terms.map(([term,meaning])=><p key={term}><strong>{term}:</strong> {meaning}</p>)}</div></Panel>
 </>;
}
