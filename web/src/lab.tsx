import React, {useEffect, useState} from 'react';
import {Play, Square, FileCheck2, RefreshCw, ArrowRight, Container, Crosshair, ShieldCheck, FileSignature} from 'lucide-react';
import {type Row, utc, routeQuery, asArray} from './lib';
import {PageHead, Panel, Notice, Badge, State, Empty, useApp, useData} from './ui';
import {Download} from './shared';

const ACTIVE=['RUNNING','STOPPING','STARTING','QUEUED','FINALIZING'];
function runActive(run:Row){return ACTIVE.includes(run.state)||run.preservation_state==='PENDING'||['QUEUED','RUNNING'].includes(run.report_state)}

export function AttackLab(){
 const {session,notify,go,act}=useApp();const allowed=session.user.role==='admin';
 // Poll quickly only while something is in progress; otherwise refresh slowly.
 const [fast,setFast]=useState(true);
 const state=useData<Row>(allowed?'/lab':null,fast?2000:15000);
 const data=state.data;const runs=asArray<Row>(data?.runs);
 const anyActive=!!data?.busy||runs.some(runActive);
 useEffect(()=>{if(data)setFast(anyActive)},[data,anyActive]);
 const [busy,setBusy]=useState(false);const [checking,setChecking]=useState(false);const [connection,setConnection]=useState<Row>();
 const run=async(fn:()=>Promise<unknown>)=>{setBusy(true);try{await fn();setFast(true);state.reload()}catch(e){notify((e as Error).message,'error')}finally{setBusy(false)}};
 async function check(){setChecking(true);setConnection(undefined);try{setConnection(await act('/lab/check','POST',{},''))}catch(e){setConnection({error:(e as Error).message})}finally{setChecking(false)}}
 const start=(scenario:string)=>run(()=>act('/lab/runs','POST',{scenario},'Simulation started. Received observations will populate its case.'));
 const stop=(id:string)=>run(()=>act('/lab/runs/'+encodeURIComponent(id)+'/stop','POST',{},'Stop requested. Already received evidence will be preserved.'));
 const recover=(id:string)=>run(()=>act('/lab/runs/'+encodeURIComponent(id)+'/recover','POST',{},'Preserved observations queued for reporting. The simulation was not replayed.'));
 return <>
  <PageHead eyebrow="Operations" title="Attack simulation lab" description="Run a bounded attack exercise in Docker, preserve the target's real observations, and produce a verifiable case report." actions={<button className="secondary" onClick={state.reload}><RefreshCw size={16}/> Refresh</button>}/>
  {!allowed?<Notice>Starting exercises requires an administrator. Authorized case members can review the resulting evidence and reports in their case workspace.</Notice>:<State state={state}>
   <div className="lab-flow"><span><Container size={15}/> 01 · Attacker container</span><ArrowRight size={18}/><span><Crosshair size={15}/> 02 · Target service</span><ArrowRight size={18}/><span><ShieldCheck size={15}/> 03 · Sealed evidence</span><ArrowRight size={18}/><span><FileSignature size={15}/> 04 · Signed report</span></div>
   <Panel title="Simulator readiness" subtitle="Lab simulations only: fixed destinations, fixed payloads and a bounded number of requests." actions={<button className="secondary small" disabled={checking||busy||data?.busy} onClick={()=>void check()}><RefreshCw size={14} className={checking?'spin':''}/>{checking?'Checking…':'Check connection'}</button>}>
    <div className="panel-content"><div className="lab-status"><Badge tone={data?.configured?'green':'amber'}>{data?.configured?'Simulator available':'Simulator unavailable'}</Badge>{connection?.reachable&&<span role="status">Connected · {connection.system} · Python {connection.python} · checked {utc(connection.checked_at)}{connection.note?' · '+connection.note:''}</span>}</div>
    {connection?.error&&<p role="alert" className="form-error" style={{marginTop:10}}>{connection.error}</p>}
    {data&&!data.configured&&<Notice tone="warning">The attack simulator is not reachable from the server. In the Docker deployment make sure the simulator service is running (docker compose ps), then refresh this page.</Notice>}</div>
   </Panel>
   <div className="lab-cards">{Object.entries(data?.scenarios||{}).map(([id,value])=>{const scenario=value as Row;return <Panel key={id}><div className="panel-content"><Badge tone="blue">{scenario.count} requests max</Badge><h2>{scenario.label}</h2><p>{scenario.description}</p><button className="primary" disabled={busy||data?.busy||!data?.configured} onClick={()=>void start(id)}><Play size={16}/>Start simulation</button></div></Panel>})}</div>
   <Panel title="Run history & automatic reports" subtitle={anyActive?'A run is in progress · refreshing every 2 seconds':'Idle · refreshing every 15 seconds'}><div className="panel-content">
    {!runs.length&&<Empty title="No exercises yet" description="Choose a scenario to create a dedicated case and start collecting observations."/>}
    {runs.map(r=><article className="lab-run" key={r.id}>
     <div className="lab-run-heading"><div><h3>{data?.scenarios?.[r.scenario]?.label||r.scenario}</h3><small>{utc(r.started_at)} · {r.id}</small></div><Badge>{r.state}</Badge></div>
     <div className="pipeline-stats" aria-live="polite"><div><small>Received</small><strong>{r.observed_count??0}</strong></div><div><small>Preserved</small><strong>{r.sealed_count??0} / {r.observed_count??0}</strong><Badge>{r.preservation_state||'—'}</Badge></div><div><small>Report</small><Badge>{r.report_state||'NOT STARTED'}</Badge>{r.report_state==='RUNNING'&&<span className="muted">{r.report_progress??0}%</span>}</div></div>
     {r.preservation_state==='PENDING'&&<p>Observations are waiting to be sealed. Allow preservation to finish before starting another simulation.</p>}
     {r.report_state==='RUNNING'&&<p>The report is being generated. Download options appear when it is complete.</p>}
     {r.error&&<p role="alert" className="form-error">{r.error}</p>}{r.report_error&&<p role="alert" className="form-error">Report: {r.report_error}</p>}
     <div className="actions">
      {r.recoverable&&<button className="secondary small" disabled={busy||data?.busy} onClick={()=>void recover(r.id)}>Recover evidence &amp; report</button>}
      {['RUNNING','STOPPING'].includes(r.state)&&<button className="destructive small" disabled={busy||r.state==='STOPPING'} onClick={()=>void stop(r.id)}><Square size={14}/>Stop</button>}
      {r.case_id&&<button className="secondary small" onClick={()=>go(routeQuery('cases',{id:r.case_id}))}><FileCheck2 size={14}/>Open case</button>}
      {r.job_id&&<button className="text-button" onClick={()=>go('jobs')}>Report job</button>}
      {r.export_id&&<><Download primary path={'/exports/'+r.export_id+'/download'} filename={'lab-'+r.export_id+'.zip'} label="Signed evidence ZIP"/>{['pdf','docx','json'].map(f=><Download key={f} path={'/exports/'+r.export_id+'/report/'+f} filename={'lab-'+r.export_id+'.'+f} label={f==='docx'?'Word':f.toUpperCase()}/>)}<details><summary>Detached signatures</summary><div className="actions">{['pdf','docx','json'].map(f=><Download key={f} path={'/exports/'+r.export_id+'/report/'+f+'?signature=true'} filename={'lab-'+r.export_id+'.'+f+'.signature.json'} label={f.toUpperCase()+' .sig'}/>)}</div></details></>}
     </div>
    </article>)}
   </div></Panel>
  </State>}
  <Notice>Signature verification: download the signed ZIP and verify it against your independently retained public key. Its Ed25519-signed manifest covers JSON, Word, PDF and raw evidence hashes. Each format also has a detached Ed25519 signature. These are not embedded Adobe or Microsoft certificate signatures; editing a report invalidates its original signature.</Notice>
  <Panel title="Presentation checklist"><div className="panel-content"><ol><li>Check the simulator connection and explain the attacker → target → evidence flow.</li><li>Start a scenario and watch received observations appear. Stop early to demonstrate cancellation.</li><li>Open its case and inspect original bytes, timestamps and provenance.</li><li>Wait for the report job, download PDF or Word, and retain the signed ZIP.</li><li>Demonstrate offline verification and explain that lab activity does not prove real intrusion or complete capture.</li></ol></div></Panel>
 </>;
}
