import React from 'react';
import {bytes,utc,asArray,isOnline,type Row} from './lib';
import {PageHead,Panel,Notice,State,Badge,useApp,useData} from './ui';

const terms=[
 ['Collector','An agent that reads configured log sources and sends observations to the server. A heartbeat confirms connectivity, not successful collection.'],
 ['Evidence','A preserved observation. An observation alone does not establish that an attack occurred.'],
 ['Case','An investigation workspace containing evidence, notes, and reports. Use the case ID to distinguish cases with the same title.'],
 ['Hash','A fingerprint of content used to detect changes. It does not establish that the source is truthful.'],
 ['Signature','A cryptographic check against a trusted public key. Report signatures are downloaded as separate files.'],
 ['Checkpoint','A signed snapshot of archive state. Without an independent witness, assurance is limited to local checks.'],
 ['COMPLETE / VALID','Complete means a job finished. Valid means the verification checks passed. These are separate results.'],
 ['External log source','A separate website or endpoint generates logs. A configured collector sends them to this workspace.'],
];

export function GettingStarted(){
 const {session,go}=useApp();const admin=session.user.role==='admin';
 const health=useData<Row>(admin?'/health/pipeline':null,15000);
 const collectors=useData<Row[]>('/collectors',15000);
 const data=health.data;const receipts=asArray<Row>(data?.receipts);const staged=receipts.find(r=>r.state==='STAGED')?.count??0;
 return <>
  <PageHead eyebrow="Workspace" title="Getting started" description="Connect a source, collect an observation, investigate the evidence, and export a verified report." actions={<button className="secondary" onClick={()=>{health.reload();collectors.reload()}}>Refresh readiness</button>}/>
  <Notice>Keep the project launcher running while using this dashboard. Use a separate authorized source for activity, then review its preserved logs here.</Notice>
  <div className="setup-steps">
   <article><Badge>01 · WINDOWS SETUP</Badge><h2>Connect a Windows collector</h2><p>On a new computer, create your administrator account first. Stop the server with Ctrl+C, then run <strong>Setup-Windows-Collector.cmd</strong> from the project folder. This configures local System and Application logs and restarts the server while retaining existing credentials.</p><p>Confirm collection with a test event after the collector connects. Each computer needs its own collector configuration.</p><button className="secondary" onClick={()=>go('collectors')}>Open collectors</button></article>
   <article><Badge>02 · REAL TEST EVENT</Badge><h2>Confirm event collection</h2><p>Run this command in an administrator PowerShell window on your Windows computer. It creates an informational test event.</p><pre>eventcreate /T INFORMATION /ID 100 /L APPLICATION /SO CloudBoxTest /D "CBB-CHECK-001: Windows collection test"</pre><p>Wait 15–30 seconds, then search for the exact message. If it is missing, check source health and your case access.</p><button className="secondary" onClick={()=>go('evidence?q='+encodeURIComponent('CBB-CHECK-001'))}>Find my test event</button></article>
   <article><Badge>03 · EXTERNAL LOGS</Badge><h2>Collect from a separate source</h2><p>Open your authorized test website in another browser. Use a configured collector for automatic delivery, or import an existing log file when a live collector is unavailable.</p><button className="secondary" onClick={()=>go('collectors')}>Open collectors</button></article>
   <article><Badge>04 · INVESTIGATE</Badge><h2>Review evidence and add notes</h2><p>Open your investigation case, then select a record to inspect its original bytes. Add notes describing your observations and any limitations.</p><button className="secondary" onClick={()=>go('cases')}>Open case workspace</button></article>
   <article><Badge>05 · VERIFY & REPORT</Badge><h2>Verify and export a snapshot</h2><p>Run verification from Integrity & checkpoints and review the result when it finishes. Generate a package from the case Reports tab. Generate a new package after adding notes; existing exports remain unchanged.</p><button className="secondary" onClick={()=>go('reports')}>Open reports</button></article>
   <article><Badge>06 · UNDERSTAND ASSURANCE</Badge><h2>Understand the scope</h2><p>Local verification is distinct from independent witnessing. Signatures do not prove complete capture or compromise. Validate optional cloud services, AI tools, packet sensors, and acquisitions before relying on them.</p><button className="secondary" onClick={()=>go('integrations')}>Check tools & sensors</button></article>
  </div>
  <Panel title="Collector connection" subtitle="Connectivity and source collection are separate checks."><div className="panel-content"><State state={collectors}>{collectors.data?.length?<p>{collectors.data.filter(isOnline).length} online collectors / {collectors.data.length} registered. Check source errors on the Collectors page.</p>:<p>No collectors are visible. Complete collector setup and confirm that your role has access.</p>}</State></div></Panel>
  {admin&&<Panel title="Preservation health" subtitle="Every 15 seconds while this page is visible. Counts describe the whole deployment."><div className="panel-content"><State state={health}>{data&&<><div className="pipeline-stats"><div><small>Waiting for sealing</small><strong>{staged.toLocaleString()}</strong></div><div><small>Quarantined</small><strong>{receipts.find(r=>r.state==='QUARANTINED')?.count??0}</strong></div><div><small>Disk free</small><strong>{bytes(data.disk_free)}</strong></div></div><p>Last received: {utc(data.last_received_at)}</p><p>Oldest pending: {data.oldest_pending_at?utc(data.oldest_pending_at):'None'}</p><p>Intake worker last completed tick: {utc(data.worker?.last_tick)}</p><p>Workers: {data.workers_enabled?'Enabled':'Disabled'} · Witness: {data.witness_configured?(data.witness_independent?'Configured as independent; verify receipts':'Configured, independence not established'):'Not configured — local checks only'}</p>{data.worker?.last_error&&<Notice tone="danger">{data.worker.last_error}</Notice>}<button className="secondary" onClick={()=>go('jobs')}>Inspect background jobs</button></>}</State></div></Panel>}
  <Panel title="Key concepts"><div className="panel-content concepts">{terms.map(([term,meaning])=><div key={term}><strong>{term}</strong>{meaning}</div>)}</div></Panel>
 </>;
}
