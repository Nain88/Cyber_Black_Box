import React, {useState} from 'react';
import {Pause, Play, RefreshCw, ArrowRight, ShieldCheck, Radio, Bell, Activity} from 'lucide-react';
import {useApp, useData, State, Panel, PageHead, Notice, Badge, Table, Stamp, Severity, sources, StructuredView} from './ui';
import {type Row, parseJson, isOnline, routeQuery, asArray} from './lib';

type VolumeBucket = {minute:string; windows:number; linux:number; other:number};
const series = [
 {key:'windows',label:'Windows'},
 {key:'linux',label:'Linux'},
 {key:'other',label:'Other sources'},
] as const;

function LogVolume({buckets}: {buckets:VolumeBucket[]}) {
 if (!buckets.length) return null;
 const peak = Math.max(...buckets.flatMap(bucket=>series.map(({key})=>bucket[key])));
 const top = Math.max(4, Math.ceil(peak/4)*4);
 const x = (index:number)=>46+index*748/(buckets.length-1);
 const y = (count:number)=>158-count*132/top;
 const clock = (index:number)=>buckets[index].minute.slice(11,16);
 return <div className="panel-content log-volume">
  <ul className="log-volume-key" aria-label="Totals in the displayed window">
   {series.map(({key,label})=><li key={key}><span className={'log-dot '+key}/>{label} <strong>{buckets.reduce((total,bucket)=>total+bucket[key],0).toLocaleString()}</strong></li>)}
  </ul>
  <svg viewBox="0 0 810 190" role="img" aria-label="Preserved logs per minute by source. Exact counts are in the expandable table.">
   {[0,1,2,3,4].map(step=><g key={step}><line x1={46} x2={794} y1={y(top*step/4)} y2={y(top*step/4)}/><text x={39} y={y(top*step/4)+4} textAnchor="end">{top*step/4}</text></g>)}
   {series.map(({key})=><polyline key={key} className={key} fill="none" vectorEffect="non-scaling-stroke"
     points={buckets.map((bucket,index)=>x(index)+','+y(bucket[key])).join(' ')}/>)}
   {[0, 7, 14, 21, 29].map(index=><text key={index} x={x(index)} y={180} textAnchor={index===0?'start':index===29?'end':'middle'}>{clock(index)}</text>)}
  </svg>
  <details><summary>View counts by minute</summary><Table rows={buckets} columns={[
   {label:'Minute (UTC)',render:r=>r.minute.slice(11,16)},
   ...series.map(({key,label})=>({label,key})),
  ]}/></details>
 </div>;
}

export function LiveMonitor(){
 const {session,go}=useApp();const admin=session.user.role==='admin';const [paused,setPaused]=useState(false);const [source,setSource]=useState('');
 const events=useData('/live/events?limit=100&source='+encodeURIComponent(source),paused?0:5000);
 const volume=useData<{buckets:VolumeBucket[]}>('/live/volume?source='+encodeURIComponent(source),paused?0:5000);
 const alerts=useData<Row[]>('/alerts?order=newest',paused?0:5000);
 const runtime=useData(admin?'/runtime/status':null,paused?0:30000);
 const collectors=useData<Row[]>(admin?'/collectors':null,paused?0:15000);
 const health=useData(admin?'/health/evidence':null,paused?0:15000);
 const recent:Row[]=events.data?.items||[];const open=(alerts.data||[]).filter(r=>r.status==='NEW');
 const rt=runtime.data;
 const reloadAll=()=>{events.reload();volume.reload();alerts.reload();runtime.reload();collectors.reload();health.reload()};
 const monitor=events.error?'Stale':paused?'Paused':'Live';
 return <><PageHead eyebrow="Workspace" title="Live monitor" description="Latest preserved observations, threat indicators and sensor coverage. Updates every five seconds while visible." actions={<><button className="secondary" onClick={()=>setPaused(!paused)}>{paused?<Play size={16}/>:<Pause size={16}/>} {paused?'Resume':'Pause'}</button><button className="primary" onClick={reloadAll}><RefreshCw size={16}/> Refresh</button></>}/>
  <Notice>Capture covers configured sources only. Suricata sees its selected interface; encrypted payloads and unseen devices remain outside coverage. A firewall drop or an alert is an observation to investigate, not proof of a successful attack.</Notice>
  <div className="stats-grid">
   <div className="stat-card"><div className="stat-top"><span>Monitor</span><span className={'stat-icon '+(events.error?'danger':paused?'warn':'ok')}><Radio size={18}/></span></div><strong className="stat-word">{monitor}</strong><small>Last refresh <Stamp value={events.stamp}/></small></div>
   <button className="stat-card" onClick={()=>go('alerts')}><div className="stat-top"><span>New alerts</span><span className={'stat-icon '+(open.length?'warn':'ok')}><Bell size={18}/></span></div><strong>{alerts.error?'—':open.length}</strong><div>Review indicators <ArrowRight size={14}/></div></button>
   <div className="stat-card"><div className="stat-top"><span>Observations in window</span><span className="stat-icon"><Activity size={18}/></span></div><strong>{events.data?recent.length:'—'}</strong><small>Latest <Stamp value={recent[0]?.received_at}/></small></div>
  </div>
  <Panel title="Log volume" subtitle="Logs received per minute over the last 30 minutes (UTC). Windows includes Event Log and Firewall. The current minute is still accumulating." actions={<label>Source <select value={source} onChange={e=>setSource(e.target.value)}><option value="">All sources</option>{sources.map(s=><option key={s}>{s}</option>)}</select></label>}>
   <State state={volume}>{volume.data&&<LogVolume buckets={volume.data.buckets}/>}</State>
  </Panel>
  {admin&&<Panel title="Evidence health" subtitle="Active issues clear automatically when current health recovers."><State state={health}>{health.data&&<>
   <div className="panel-content actions">
    <Badge tone={health.data.staged_receipts?'amber':health.data.last_sealed_received_at?'green':'slate'}>{health.data.staged_receipts?health.data.staged_receipts+' awaiting sealing':health.data.last_sealed_received_at?'Evidence sealed':'No sealed evidence'}</Badge>
    <Badge tone={health.data.analysis_delayed?'amber':'slate'}>{health.data.analysis_delayed?'Analysis delayed':'Analysis within threshold'}</Badge>
    <span className="muted">{health.data.pending_analysis} pending analysis jobs · {health.data.analysis_delay_seconds}s delay threshold</span>
   </div>
   <Table rows={health.data.issues} columns={[{label:'Issue',key:'issue'},{label:'Scope',key:'scope'},{label:'Details',key:'detail'}]} empty="No active evidence health issues."/>
  </>}</State></Panel>}
  {admin&&<State state={runtime}>{rt&&<div className="integration-grid">
   {rt.firewall&&<Panel title="Windows Firewall"><div className="panel-content"><Badge tone={rt.firewall.state==='ENABLED'?'green':'amber'}>{rt.firewall.state||'UNKNOWN'}</Badge><p className="tool-version">Connection logging: {rt.firewall.logging_enabled?'enabled':'unavailable / not fully enabled'}</p><small className="muted">Checked <Stamp value={rt.checked_at}/></small>{rt.firewall.profiles&&<details><summary>Effective profiles</summary><StructuredView value={rt.firewall.profiles}/></details>}</div></Panel>}
   {rt.ollama&&<Panel title="Local AI"><div className="panel-content"><Badge>{rt.ollama.state||'UNKNOWN'}</Badge><p className="tool-version">{rt.ollama.model||'No model configured'}</p><small className="muted">Availability does not certify model accuracy. Review generated advice in Evidence assistant.</small></div></Panel>}
   {rt.suricata&&<Panel title="Network IDS"><div className="panel-content"><Badge>{rt.suricata.state||'UNKNOWN'}</Badge><p className="tool-version">{rt.suricata.version||'No executable detected on this server'}</p><small className="muted">Check sensor coverage below for a recent EVE input and the selected adapter.</small></div></Panel>}
  </div>}</State>}
  {admin&&<Panel title="Sensor coverage" subtitle="A fresh heartbeat does not guarantee readable inputs. Expand errors before relying on coverage."><State state={collectors}><Table rows={collectors.data||[]} columns={[{label:'Sensor',render:r=><div className="table-title"><strong>{r.name}</strong><small>{String(parseJson(r.health,{})?.platform||'')}</small></div>},{label:'Heartbeat',render:r=><Badge tone={isOnline(r)?'green':'amber'}>{isOnline(r)?'Recent':'Offline / stale'}</Badge>},{label:'Last seen',render:r=><Stamp value={r.last_heartbeat}/>},{label:'Inputs and errors',render:r=>{const h=parseJson(r.health,{}) as Row;const errors=asArray(h?.errors);return <details><summary>{asArray(h?.network_inputs).length+asArray(h?.firewall_inputs).length} inputs{errors.length?` · ${errors.length} errors`:''}</summary><StructuredView value={{eve:h?.network_inputs,firewall:h?.firewall_inputs,errors:h?.errors}} empty="No inputs reported."/></details>}}]} empty="No collectors are enrolled yet."/></State></Panel>}
  <Panel title="Incoming preserved logs" subtitle="Latest 100 records in your authorized scope. Use Evidence explorer for the complete paginated history.">
   <State state={events}><Table rows={recent} onRow={r=>go(routeQuery('evidence',{id:r.id}))} columns={[
    {label:'Observed activity',render:r=><div className="table-title"><strong>{r.summary||r.event_type}</strong><small>{r.source_type} · {r.event_type}</small></div>},
    {label:'Severity',render:r=><Severity value={r.severity}/>},{label:'Received',render:r=><Stamp value={r.received_at}/>},
    {label:'Source → destination',render:r=>{const s=r.subject||r.envelope?.subject||{};return <span className="mono small-text break">{s.src_ip||'—'} → {s.dst_ip||'—'}{s.dst_port?':'+s.dst_port:''}</span>}},
    // Records returned here come from the sealed evidence table, so every row is preserved.
    {label:'Preservation',render:()=><Badge tone="green"><ShieldCheck size={12}/> Sealed</Badge>}]} empty="No preserved logs in this scope yet. Connect a collector or import logs from an authorized source."/></State>
  </Panel>
  <Panel title="Newest alerts" subtitle="Review source bytes and false positives before response."><State state={alerts}><Table rows={open.slice(0,20)} onRow={r=>go(routeQuery('alerts',{id:r.id}))} columns={[{label:'Rule',render:r=><span className="source-label">{r.rule_id}</span>},{label:'Observation',render:r=><span className="truncate" title={r.explanation}>{r.explanation}</span>},{label:'Severity',render:r=><Severity value={r.severity}/>},{label:'Created',render:r=><Stamp value={r.created_at}/>}]} empty="No new alerts in the returned window. This does not establish that the device is attack-free."/></State></Panel></>;
}
