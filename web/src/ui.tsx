import React, {createContext, useContext, useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode} from 'react';
import {Check, CircleHelp, Copy, Layers3, LoaderCircle, ShieldAlert, TriangleAlert} from 'lucide-react';
import {api, type Row, utc, short, pretty, statusTone, severityLabel} from './lib';

export type Session={user:Row;csrf:string};
export type Context={session:Session;status:Row;revision:number;refresh:()=>void;notify:(message:string,kind?:string)=>void;modal:(title:string,content:ReactNode)=>void;close:()=>void;go:(path:string)=>void;act:(path:string,method:string,body?:unknown,message?:string)=>Promise<any>};
export const Ctx=createContext<Context>(null!);
export const useApp=()=>useContext(Ctx);
export const sources=['windows.event','windows.firewall','linux.journal','suricata.eve','zeek','fim','yara','acquisition','collector.health','lab.fixture'];
export const roleWrite=(u:Row)=>['admin','investigator'].includes(u.role);

/** Fetch an API path, optionally polling. Data is cleared when the path changes so a
 *  previous item's results are never shown as if they belonged to the new one. */
export function useData<T=any>(path:string|null,poll=0){
 const {revision}=useApp();const [data,setData]=useState<T>();const [error,setError]=useState('');const [loading,setLoading]=useState(false);const [stamp,setStamp]=useState('');const [local,setLocal]=useState(0);
 const lastPath=useRef(path);
 useEffect(()=>{if(lastPath.current!==path){lastPath.current=path;setData(undefined);setError('');setStamp('')}},[path]);
 useEffect(()=>{let active=true;const load=async()=>{if(!path)return;setLoading(true);try{const value=await api<T>(path);if(active){setData(value);setError('');setStamp(new Date().toISOString());}}catch(e){if(active)setError((e as Error).message);}finally{if(active)setLoading(false);}};void load();const timer=poll?setInterval(()=>{if(!document.hidden)void load()},poll):null;return()=>{active=false;if(timer)clearInterval(timer)}},[path,revision,local,poll]);
 return {data,error,loading,stamp,reload:()=>setLocal(x=>x+1)};
}
export type DataState=ReturnType<typeof useData>;

export function State({state,children,empty,description}:{state:DataState;children:ReactNode;empty?:boolean;description?:string}){
 return <>{state.error&&<div className="notice danger" role="alert"><ShieldAlert size={18}/><div><strong>{state.data?'Showing previous results. ':''}{state.error}</strong><small>Refresh to try again. Existing values are not replaced with zeros.</small></div><button className="small secondary" onClick={state.reload}>Retry</button></div>}{!state.data&&state.loading?<div className="loading"><LoaderCircle className="spin" size={18}/>Loading…</div>:empty?<Empty description={description}/>:children}</>;
}
export function Empty({title='Nothing here yet',description='New records will appear here when they are available.',action}:{title?:string;description?:string;action?:ReactNode}){return <div className="empty"><div className="empty-icon"><Layers3 size={24}/></div><h3>{title}</h3><p>{description}</p>{action}</div>}
export function Badge({children,tone}:{children:ReactNode;tone?:string}){return <span className={'badge '+(tone||statusTone(String(children)))}><span className="badge-dot"/>{children}</span>}
export function Severity({value}:{value:number}){const n=Number(value);const level=Number.isInteger(n)&&n>=0&&n<=5?n:0;return <Badge tone={'sev-'+level}>{severityLabel(level)}</Badge>}
export function Json({value}:{value:unknown}){return <pre className="json">{pretty(value)}</pre>}

/* ---- Structured, readable rendering of API documents ---- */
const label=(key:string)=>key.replace(/_/g,' ');
function isScalar(v:unknown){return v==null||['string','number','boolean'].includes(typeof v)}
function looksLikeTime(key:string,v:unknown){return typeof v==='string'&&/(_at|time|expires|until|^created|^updated)$/i.test(key)&&!Number.isNaN(Date.parse(v))}
function Scalar({k,v}:{k:string;v:unknown}){
 if(v==null||v==='')return <span className="kv-empty">not set</span>;
 if(typeof v==='boolean')return <span className={v?'kv-bool-true':'kv-bool-false'}>{v?'Yes':'No'}</span>;
 if(looksLikeTime(k,v))return <time title={String(v)}>{utc(v)}</time>;
 const s=String(v);
 if(/^[a-f0-9]{40,}$/i.test(s)||/sha|hash|signature|key|fingerprint|id$/i.test(k))return <code className="break">{s}</code>;
 return <span>{s}</span>;
}
function Structured({value,k,depth}:{value:unknown;k:string;depth:number}):ReactNode{
 if(isScalar(value))return <Scalar k={k} v={value}/>;
 if(Array.isArray(value)){
  if(!value.length)return <span className="kv-empty">none</span>;
  if(value.every(isScalar))return <span>{value.map((x,i)=><React.Fragment key={i}>{i>0&&', '}<Scalar k={k} v={x}/></React.Fragment>)}</span>;
  if(depth>=3)return <Json value={value}/>;
  return <ol className="kv-list">{value.map((x,i)=><li key={i}><Structured value={x} k={k} depth={depth+1}/></li>)}</ol>;
 }
 const entries=Object.entries(value as Row);
 if(!entries.length)return <span className="kv-empty">empty</span>;
 if(depth>=3)return <Json value={value}/>;
 return <dl className="kv">{entries.map(([key,v])=><React.Fragment key={key}><dt>{label(key)}</dt><dd><Structured value={v} k={key} depth={depth+1}/></dd></React.Fragment>)}</dl>;
}
/** Key/value view for nested JSON documents with an optional raw-JSON disclosure. */
export function StructuredView({value,raw=false,empty='No details recorded.'}:{value:unknown;raw?:boolean;empty?:string}){
 if(value==null||(typeof value==='object'&&!Array.isArray(value)&&!Object.keys(value as Row).length)||(Array.isArray(value)&&!value.length))return <p className="kv-empty">{empty}</p>;
 return <>{isScalar(value)?<p><Scalar k="" v={value}/></p>:<Structured value={value} k="" depth={0}/>}{raw&&<details className="raw-json"><summary>Raw JSON</summary><Json value={value}/></details>}</>;
}

export function CopyButton({value,label='Copy'}:{value:string;label?:string}){const {notify}=useApp();const [done,setDone]=useState(false);return <button type="button" className="icon-button" title={label} aria-label={label} onClick={e=>{e.stopPropagation();navigator.clipboard.writeText(value).then(()=>{setDone(true);setTimeout(()=>setDone(false),1500);notify('Copied to clipboard')}).catch(()=>notify('Copy unavailable in this browser','error'))}}>{done?<Check size={15}/>:<Copy size={15}/>}</button>}
export function Id({value}:{value:unknown}){return <span className="mono" title={String(value||'')}>{short(value)}</span>}
export function Stamp({value}:{value:unknown}){return <time title={utc(value)}>{utc(value)}</time>}

/** Notices: warnings and errors stay expanded. Long informational text collapses to
 *  its first sentence so it does not push content below the fold; nothing is removed. */
export function Notice({children,tone='info',expanded=false}:{children:ReactNode;tone?:string;expanded?:boolean}){
 const Icon=tone==='danger'?ShieldAlert:tone==='warning'?TriangleAlert:CircleHelp;
 if(tone==='info'&&!expanded&&typeof children==='string'&&children.length>150){
  const m=children.match(/^(.+?[.!?])(\s+)([\s\S]+)$/);
  if(m)return <div className="notice collapsible"><details><summary><Icon size={16}/><span className="notice-preview">{m[1]}</span><span className="notice-toggle">More</span></summary><div className="notice-body">{m[3]}</div></details></div>;
 }
 return <div className={'notice '+tone} role={tone==='danger'?'alert':undefined}><Icon size={18}/><div>{children}</div></div>;
}
export function Panel({title,subtitle,actions,children,className=''}:{title?:string;subtitle?:string;actions?:ReactNode;children:ReactNode;className?:string}){return <section className={'panel '+className}>{(title||actions)&&<div className="panel-heading"><div>{title&&<h2>{title}</h2>}{subtitle&&<p>{subtitle}</p>}</div>{actions&&<div className="actions">{actions}</div>}</div>}{children}</section>}
export function PageHead({eyebrow,title,description,actions}:{eyebrow:string;title:string;description:string;actions?:ReactNode}){return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{actions&&<div className="actions">{actions}</div>}</div>}
export function Field({label,help,children}:{label:string;help?:string;children:ReactNode}){return <label className="field"><span>{label}</span>{children}{help&&<small>{help}</small>}</label>}
export function TextField({label,name,defaultValue='',type='text',required=false,help,min,max,placeholder}:{label:string;name:string;defaultValue?:string|number;type?:string;required?:boolean;help?:string;min?:number;max?:number;placeholder?:string}){return <Field label={label} help={help}><input name={name} type={type} defaultValue={defaultValue} required={required} minLength={type==='text'||type==='password'?min:undefined} maxLength={type==='text'||type==='password'?max:undefined} min={type==='number'?min:undefined} max={type==='number'?max:undefined} placeholder={placeholder}/></Field>}
export function SelectField({label,name,options,defaultValue='',required=false}:{label:string;name:string;options:(string|{value:string;label:string})[];defaultValue?:string;required?:boolean}){return <Field label={label}><select name={name} defaultValue={defaultValue} required={required}>{options.map(o=>typeof o==='string'?<option key={o} value={o}>{o}</option>:<option key={o.value} value={o.value}>{o.label}</option>)}</select></Field>}
export function TextArea({label,name,defaultValue='',help,required=false,rows=4}:{label:string;name:string;defaultValue?:string;help?:string;required?:boolean;rows?:number}){return <Field label={label} help={help}><textarea name={name} defaultValue={defaultValue} rows={rows} required={required}/></Field>}
export function Form({children,onSubmit,submit='Save changes',danger=false}:{children:ReactNode;onSubmit:(values:Record<string,string>,form:HTMLFormElement)=>Promise<unknown>;submit?:string;danger?:boolean}){const [busy,setBusy]=useState(false);const [error,setError]=useState('');return <form className="form" onSubmit={async e=>{e.preventDefault();const f=e.currentTarget;setBusy(true);setError('');try{await onSubmit(Object.fromEntries(new FormData(f).entries()) as Record<string,string>,f)}catch(x){setError((x as Error).message)}finally{setBusy(false)}}}>{children}{error&&<div className="form-error" role="alert">{error}</div>}<div className="form-footer"><button className={danger?'destructive':'primary'} disabled={busy} type="submit">{busy?<LoaderCircle size={16} className="spin"/>:<Check size={16}/>} {busy?'Working…':submit}</button></div></form>}

export type Col={label:string;key?:string;render?:(r:Row)=>ReactNode;className?:string};
const interactive='button,a,input,select,textarea,label,summary,details';
/** Data table. With onRow the whole row is clickable and keyboard-operable (Enter/Space);
 *  clicks on controls inside a cell keep their own behaviour. */
export function Table({columns,rows,onRow,empty='No records match this view.'}:{columns:Col[];rows:Row[];onRow?:(r:Row)=>void;empty?:string}){
 if(!rows.length)return <Empty description={empty}/>;
 const cell=(c:Col,r:Row)=>c.render?c.render(r):String(r[c.key||'']??'—');
 return <div className="table-wrap"><table><thead><tr>{columns.map((c,i)=><th key={i} className={c.className} scope="col">{c.label}</th>)}</tr></thead><tbody>{rows.map((r,i)=><tr key={r.id||i} className={onRow?'clickable':undefined} tabIndex={onRow?0:undefined}
  onClick={onRow?e=>{const hit=(e.target as HTMLElement).closest(interactive);if(hit&&e.currentTarget.contains(hit))return;onRow(r)}:undefined}
  onKeyDown={onRow?e=>{if(e.target===e.currentTarget&&(e.key==='Enter'||e.key===' ')){e.preventDefault();onRow(r)}}:undefined}>
  {columns.map((c,j)=><td key={j} className={c.className}>{cell(c,r)}</td>)}</tr>)}</tbody></table></div>;
}

/** Accessible tabs: roving tabindex with Arrow/Home/End keys. */
export function Tabs({items,value,onChange}:{items:string[];value:string;onChange:(x:string)=>void}){
 const base=useId();const refs=useRef<(HTMLButtonElement|null)[]>([]);
 const move=(e:KeyboardEvent,i:number)=>{const n=items.length;const next=e.key==='ArrowRight'?(i+1)%n:e.key==='ArrowLeft'?(i-1+n)%n:e.key==='Home'?0:e.key==='End'?n-1:-1;if(next<0)return;e.preventDefault();onChange(items[next]);refs.current[next]?.focus()};
 return <div className="tabs" role="tablist">{items.map((item,i)=><button type="button" role="tab" id={base+'-'+i} ref={el=>{refs.current[i]=el}} aria-selected={value===item} tabIndex={value===item?0:-1} key={item} className={value===item?'selected':''} onClick={()=>onChange(item)} onKeyDown={e=>move(e,i)}>{item}</button>)}</div>;
}
export function DetailGrid({items}:{items:[string,ReactNode][]}){return <dl className="detail-grid">{items.map(([label,value])=><div key={label}><dt>{label}</dt><dd>{value??'—'}</dd></div>)}</dl>}
export function Confirm({description,onConfirm,label='Confirm',reason=true}:{description:ReactNode;onConfirm:(v:Record<string,string>)=>Promise<unknown>;label?:string;reason?:boolean}){return <Form onSubmit={onConfirm} submit={label} danger><Notice tone="warning">{description}</Notice>{reason&&<TextArea label="Reason" name="reason" required/>}</Form>}

/** Small dependency-free horizontal bar chart. */
export function BarChart({data,color='var(--accent)',onSelect}:{data:{label:string;value:number;color?:string}[];color?:string;onSelect?:(label:string)=>void}){
 const max=Math.max(1,...data.map(d=>d.value));const row=30;const labelW=140;const w=520;const h=data.length*row;
 return <svg viewBox={`0 0 ${w} ${h}`} role="img" aria-label={data.map(d=>`${d.label}: ${d.value}`).join(', ')}>
  {data.map((d,i)=>{const bw=Math.max(2,(w-labelW-60)*d.value/max);return <g key={d.label} transform={`translate(0 ${i*row})`} style={{cursor:onSelect?'pointer':undefined}} onClick={onSelect?()=>onSelect(d.label):undefined}>
   <text x={0} y={row/2+4} className="chart-axis">{d.label.length>18?d.label.slice(0,17)+'…':d.label}</text>
   <rect x={labelW} y={7} width={w-labelW-60} height={row-14} rx={4} fill="var(--surface-3)"/>
   <rect x={labelW} y={7} width={bw} height={row-14} rx={4} fill={d.color||color}/>
   <text x={labelW+bw+8} y={row/2+4} className="chart-value">{d.value.toLocaleString()}</text></g>})}
 </svg>;
}
/** Donut chart with a centred total. */
export function Donut({data,total,caption}:{data:{label:string;value:number;color:string}[];total?:ReactNode;caption?:string}){
 const sum=data.reduce((n,d)=>n+d.value,0);const r=52;const c=2*Math.PI*r;let offset=0;
 return <svg viewBox="0 0 140 140" role="img" aria-label={data.map(d=>`${d.label}: ${d.value}`).join(', ')}>
  <circle cx={70} cy={70} r={r} fill="none" stroke="var(--surface-3)" strokeWidth={16}/>
  {sum>0&&data.filter(d=>d.value>0).map(d=>{const len=c*d.value/sum;const el=<circle key={d.label} cx={70} cy={70} r={r} fill="none" stroke={d.color} strokeWidth={16} strokeDasharray={`${len} ${c-len}`} strokeDashoffset={-offset} transform="rotate(-90 70 70)"/>;offset+=len;return el})}
  <text x={70} y={72} textAnchor="middle" className="donut-total">{total??sum}</text>
  {caption&&<text x={70} y={90} textAnchor="middle" className="donut-label">{caption}</text>}
 </svg>;
}
