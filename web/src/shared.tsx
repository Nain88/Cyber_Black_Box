import React, {useState} from 'react';
import {ArrowDownToLine, ArrowRight, Link2, LoaderCircle, Plus} from 'lucide-react';
import {caseLabel, bytes, short, routeQuery, type Row} from './lib';
import {useApp, useData, State, Form, SelectField, TextArea, Severity, Badge, CopyButton, Tabs, DetailGrid, Stamp, Id, Notice, StructuredView, roleWrite} from './ui';

/** Download an authenticated API resource as a file. */
export async function downloadFile(path:string,filename:string){
 const r=await fetch('/api/v1'+path,{credentials:'same-origin'});
 if(!r.ok){const e=await r.json().catch(()=>({}));throw new Error(typeof e.detail==='string'?e.detail:'Download failed')}
 const blob=await r.blob();const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=filename;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}

export function Download({path,filename,label='Download',primary=false}:{path:string;filename:string;label?:string;primary?:boolean}){
 const {notify}=useApp();const [busy,setBusy]=useState(false);
 return <button type="button" className={(primary?'primary':'secondary')+' small'} disabled={busy} onClick={async()=>{setBusy(true);try{await downloadFile(path,filename);notify('Download prepared')}catch(e){notify((e as Error).message,'error')}finally{setBusy(false)}}}>{busy?<LoaderCircle className="spin" size={15}/>:<ArrowDownToLine size={15}/>} {label}</button>;
}

export function AddToCase({ids}:{ids:string[]}){
 const {act,close}=useApp();const cases=useData<Row[]>('/cases');
 return <><p className="lead">Add <strong>{ids.length}</strong> selected evidence record{ids.length===1?'':'s'} to a case. Originals remain unchanged.</p><State state={cases}><Form submit="Add evidence" onSubmit={async v=>{await act('/cases/'+encodeURIComponent(v.case_id)+'/evidence','POST',{evidence_ids:ids,reason:v.reason},'Evidence added to case');close()}}><SelectField label="Case" name="case_id" options={[{value:'',label:'Select a case'},...(cases.data||[]).map(c=>({value:c.id,label:caseLabel(c)}))]} required/><TextArea label="Reason for inclusion" name="reason" required defaultValue="Relevant to the investigation scope."/></Form></State></>;
}

export function EvidenceDetail({id}:{id:string}){
 const {modal,go,session}=useApp();const state=useData('/evidence/'+encodeURIComponent(id));const [tab,setTab]=useState('Summary');const d=state.data;
 const subject=d?.envelope?.subject;const provenance=d?.envelope?.provenance;
 const hasSubject=subject&&typeof subject==='object'&&Object.keys(subject).length>0;const hasProvenance=provenance&&typeof provenance==='object'&&Object.keys(provenance).length>0;
 return <State state={state}>{d&&<>
  <h2 className="drawer-title">{d.summary||d.event_type}</h2>
  <div className="id-line"><code>{d.id}</code><CopyButton value={d.id}/></div>
  <div className="actions"><Severity value={d.severity}/><Badge tone="blue">{d.source_type}</Badge><Badge tone="green">Sealed</Badge></div>
  <Tabs items={['Summary','Integrity','Envelope']} value={tab} onChange={setTab}/>
  {tab==='Summary'?<>
   <DetailGrid items={[["Event type",d.event_type],["Occurrence time",<Stamp value={d.occurred_at}/>],["Received",<Stamp value={d.received_at}/>],["Asset",<Id value={d.asset_id}/>],["Collector",<Id value={d.collector_id}/>],["Sequence",d.sequence]]}/>
   {hasSubject&&<><h3>Source details</h3><StructuredView value={subject}/></>}
   {hasProvenance&&<><h3>Provenance</h3><StructuredView value={provenance}/></>}
   {!hasSubject&&!hasProvenance&&<Notice>No additional normalized source fields. Download Original bytes to inspect the preserved observation. Empty normalized fields do not mean that original evidence is missing.</Notice>}
  </>:tab==='Integrity'?<>
   <Notice>These are stored integrity values. Run verification to check them against the archive and a trusted checkpoint.</Notice>
   <DetailGrid items={[["Chain",<code className="break">{d.chain_id}</code>],["Sequence",d.sequence],["Raw SHA-256",<code className="break">{d.raw_sha256}</code>],["Envelope SHA-256",<code className="break">{d.envelope_sha256}</code>],["Previous record hash",<code className="break">{d.previous_hash}</code>],["Record hash",<code className="break">{d.record_hash}</code>],["Archive location",<span>{short(d.segment_id)} · offset {d.raw_offset} · {bytes(d.raw_length)}</span>]]}/>
   <button className="secondary" onClick={()=>go('integrity')}>Open verification <ArrowRight size={15}/></button>
  </>:<StructuredView value={d.envelope} raw/>}
  <div className="drawer-actions">
   {session.user.role!=='auditor'&&<Download path={'/evidence/'+encodeURIComponent(id)+'/raw'} filename={id+'.raw'} label="Original bytes"/>}
   {roleWrite(session.user)&&<button className="primary small" onClick={()=>modal('Add evidence to case',<AddToCase ids={[id]}/>)}><Plus size={15}/> Add to case</button>}
   <button className="secondary small" onClick={()=>go(routeQuery('custody',{target:id}))}><Link2 size={15}/> Custody</button>
  </div>
 </>}</State>;
}
