import React, {useState} from 'react';
import {Play, Square, FileCheck2, Download, RefreshCw, ArrowRight} from 'lucide-react';
import {api, type Row, utc} from './lib';
import {PageHead, Panel, Notice, Badge, State, useApp, useData} from './ui';

export function AttackLab() {
  const {session,notify,go}=useApp();
  const allowed=session.user.role==='admin';
  const state=useData<Row>(allowed?'/lab':null,2000);
  const [busy,setBusy]=useState(false);
  const [checking,setChecking]=useState(false);
  const [connection,setConnection]=useState<Row>();
  const data=state.data;
  async function check(){setChecking(true);setConnection(undefined);try{setConnection(await api<Row>('/lab/check','POST',{}))}catch(e){setConnection({error:(e as Error).message})}finally{setChecking(false)}}
  async function start(scenario:string){setBusy(true);try{await api('/lab/runs','POST',{scenario});notify('Docker exercise started. Received observations will populate its case.');state.reload()}catch(e){notify((e as Error).message,'error')}finally{setBusy(false)}}
  async function stop(id:string){setBusy(true);try{await api('/lab/runs/'+id+'/stop','POST',{});notify('Stop requested. Already received evidence will be preserved.');state.reload()}catch(e){notify((e as Error).message,'error')}finally{setBusy(false)}}
  async function recover(id:string){setBusy(true);try{await api('/lab/runs/'+id+'/recover','POST',{});notify('Preserved observations queued for reporting. Docker sender was not replayed.');state.reload()}catch(e){notify((e as Error).message,'error')}finally{setBusy(false)}}
  return <>
    <PageHead eyebrow="FYP LAB / DOCKER → WINDOWS → EVIDENCE" title="Attack simulation & reports" description="Run a bounded exercise from Docker, preserve real target observations, and produce a verifiable case report." actions={<button className="secondary" onClick={state.reload}><RefreshCw size={16}/>Refresh</button>}/>
    <Notice>Lab simulations only: fixed destinations, fixed payloads, up to six requests. Existing Linux journal collection is independent. No personal accounts are tested.</Notice>
    {!allowed?<Notice>Starting exercises requires an administrator. Authorized case members can review the resulting evidence and reports in their case workspace.</Notice>:<State state={state}>
      <Panel title="Docker sender readiness"><div className="panel-content"><p>Start Docker Desktop with its Linux engine. Each run creates a temporary restricted sender container. Windows collects the observations.</p><button className="secondary" disabled={checking||busy||data?.busy} onClick={()=>void check()}><RefreshCw size={16}/>{checking?'Checking Docker…':'Check Docker connection'}</button>{connection?.error&&<p role="alert" className="form-error">{connection.error}</p>}{connection?.reachable&&<p role="status">Docker connected · {connection.system} · Python {connection.python} · Checked {utc(connection.checked_at)}. {connection.note}</p>}</div></Panel>
      <div className="lab-flow"><span>01 · Docker sender</span><ArrowRight size={18}/><span>02 · Windows decoy</span><ArrowRight size={18}/><span>03 · Sealed evidence</span><ArrowRight size={18}/><span>04 · Signed package</span></div>
      {data&&!data.configured&&<Notice>Docker connection is not configured. Start the existing VM and configure the local SSH key and pinned host entry described in docs/DOCKER-LOG-CONNECTION.md. No requests will be sent until configuration is available.</Notice>}
      <div className="lab-cards">{Object.entries(data?.scenarios||{}).map(([id,value])=>{const scenario=value as Row;return <Panel key={id}><div className="panel-content"><Badge tone="blue">{scenario.count} REQUESTS MAXIMUM</Badge><h2>{scenario.label}</h2><p>{scenario.description}</p><button className="primary" disabled={busy||data?.busy||!data?.configured} onClick={()=>void start(id)}><Play size={16}/>Start simulation</button></div></Panel>})}</div>
      <Panel title="Run history & automatic reports"><div className="panel-content">
        {!data?.runs?.length&&<p>No exercises yet. Choose a scenario to create a dedicated case and start collecting observations.</p>}
        {(data?.runs||[]).map((run:Row)=><article className="lab-run" key={run.id}>
          <div className="lab-run-heading"><div><h3>{data?.scenarios[run.scenario]?.label||run.scenario}</h3><small>{utc(run.started_at)} · {run.id}</small></div><Badge>{run.state}</Badge></div>
          <div className="pipeline-stats" aria-live="polite"><div><small>Received / mili requests</small><strong>{run.observed_count}</strong></div><div><small>Preserved / mehfooz records</small><strong>{run.sealed_count} / {run.observed_count}</strong> <Badge>{run.preservation_state}</Badge></div><div><small>Report job</small><Badge>{run.report_state}</Badge>{run.report_state==='RUNNING'&&<span> · {run.report_progress}%</span>}</div></div>
          {run.preservation_state==='PENDING'&&<p>Requests receive ho gayi hain; sealing abhi baqi hai. New simulation repeat karne se pehle preservation complete hone dein.</p>}
          {run.report_state==='RUNNING'&&<p>Report ban rahi hai. Large archive verification mein waqt lag sakta hai; COMPLETE ka wait karein.</p>}
          {run.error&&<p role="alert" className="form-error">{run.error}</p>}{run.report_error&&<p role="alert" className="form-error">Report: {run.report_error}</p>}
          <div className="actions">
            {run.recoverable&&<button className="secondary" disabled={busy||data?.busy} onClick={()=>void recover(run.id)}>Recover evidence &amp; report — no new requests</button>}
            {['RUNNING','STOPPING'].includes(run.state)&&<button className="secondary" disabled={busy||run.state==='STOPPING'} onClick={()=>void stop(run.id)}><Square size={16}/>Stop simulation</button>}
            <button className="secondary" onClick={()=>go('cases?id='+run.case_id)}><FileCheck2 size={16}/>Open evidence case</button>
            {run.job_id&&<button className="secondary" onClick={()=>go('jobs')}>Report job</button>}
            {run.export_id&&<><a className="primary" href={'/api/v1/exports/'+run.export_id+'/download'}><Download size={16}/>Signed evidence ZIP</a>{['pdf','docx','json'].map(format=><React.Fragment key={format}><a className="secondary" href={'/api/v1/exports/'+run.export_id+'/report/'+format}>{format==='docx'?'Word':format.toUpperCase()}</a><a className="text-button" href={'/api/v1/exports/'+run.export_id+'/report/'+format+'?signature=true'}>{format.toUpperCase()} signature</a></React.Fragment>)}</>}
          </div>
        </article>)}
      </div></Panel>
    </State>}
    <Notice>Signature verification: download the signed ZIP and verify it against your independently retained public key. Its Ed25519-signed manifest covers JSON, Word, PDF and raw evidence hashes. Each format also has a downloadable detached Ed25519 signature. Use verify-report to check it. These are not embedded Adobe or Microsoft certificate signatures. Editing a report invalidates its original signature.</Notice>
    <Panel><div className="panel-content"><h2>Presentation checklist</h2><ol><li>Show the Docker connection check and explain the Windows observation service.</li><li>Start a scenario and watch received observations appear. Stop early to demonstrate cancellation.</li><li>Open its case and inspect original bytes, timestamps and provenance.</li><li>Wait for the report job, download PDF or Word, and retain the signed ZIP.</li><li>Demonstrate offline verification and explain that lab activity does not prove real intrusion or complete capture.</li></ol></div></Panel>
  </>;
}
