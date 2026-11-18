import React, {useEffect, useMemo, useRef, useState, type ReactNode} from 'react';
import {createRoot} from 'react-dom/client';
import {ArrowRight, Bell, BookOpen, Boxes, BrainCircuit, CheckCircle2, ChevronDown, ChevronRight, Clock3, Cloud, Cpu, FileCheck2, FileSearch, FileText, Fingerprint, FlaskConical, FolderOpen, HardDriveDownload, History, LayoutDashboard, Link2, ListChecks, LoaderCircle, LockKeyhole, LogOut, Menu, Monitor, Moon, Network, Pause, Play, Plus, Radio, RefreshCw, Search, Settings, ShieldAlert, ShieldCheck, Sun, Users, Wrench, X, type LucideIcon} from 'lucide-react';
import {api, setCsrf, type Row, bytes, utc, short, routeQuery, asArray, isOnline, severityLabels} from './lib';
import './theme.css';
import {AttackLab} from './lab';
import {GettingStarted} from './guide';
import {SignalBanner} from './edge';
import {Ctx, useApp, sources, roleWrite, useData, State, Empty, Badge, Severity, CopyButton, Id, Stamp, Notice, Panel, PageHead, TextField, SelectField, TextArea, Form, Table, Tabs, DetailGrid, StructuredView, BarChart, Donut, type Session, type Context} from './ui';
import {AddToCase, EvidenceDetail} from './shared';
import {LiveMonitor} from './live';
import {Integrations, CloudArchive, Assistant} from './integrations';
import {Collectors, Integrity, Custody, Acquisitions, Reports, Jobs, Models, Admin} from './operations';

/* ---------------- Theme ---------------- */
type Theme='dark'|'light';
function storedTheme():Theme{try{const t=localStorage.getItem('cbb-theme');if(t==='light'||t==='dark')return t}catch{/* storage unavailable */}return 'dark'}
function applyTheme(t:Theme){document.documentElement.dataset.theme=t;document.querySelector('meta[name=theme-color]')?.setAttribute('content',t==='dark'?'#0a0f16':'#f3f5f9')}
applyTheme(storedTheme());

/* ---------------- Auth ---------------- */
function Auth({status,onLogin,onStatus}:{status:Row;onLogin:(s:Session)=>void;onStatus:()=>void}){
 const setup=status.setup_required;const [error,setError]=useState('');const [busy,setBusy]=useState(false);
 return <div className="auth"><div className="auth-story"><div className="brand"><div className="brand-mark"><Boxes/></div><span>CYBER<b>BLACK BOX</b></span></div><div className="auth-story-body"><div className="eyebrow">Preserve · Investigate · Verify</div><h1>Every event.<br/>A stronger<br/><em>evidence trail.</em></h1><p>A single workspace for endpoint collection, tamper-evident preservation and accountable investigations.</p><div className="auth-features"><span><Fingerprint/> Signed checkpoints</span><span><Link2/> Chain of custody</span><span><Monitor/> Virtual + cloud deployment</span></div></div><span className="auth-caption">Cyber Black Box · Final Year Project</span></div>
 <main className="auth-main"><div className="auth-form"><Badge tone="blue">{status.mode==='cloud'?'Cloud mode':'Virtual mode'}</Badge><h2>{setup?'Create your workspace':'Welcome back'}</h2><p>{setup?'Use the one-time setup token saved by the server to create the first administrator.':'Sign in to your investigation workspace.'}</p>
 <form onSubmit={async e=>{e.preventDefault();setBusy(true);setError('');const v=Object.fromEntries(new FormData(e.currentTarget).entries());try{if(setup){await api('/admin/setup','POST',v);onStatus();}else{const s=await api<Session>('/auth/session','POST',v);setCsrf(s.csrf);onLogin(s)}}catch(x){setError((x as Error).message)}finally{setBusy(false)}}}>
  {setup&&<TextField label="One-time setup token" name="token" type="password" required help="Printed by the server on first start (data/keys/bootstrap.token). It is deleted after setup."/>}
  <TextField label="Username" name="username" required min={3} max={80} placeholder="Your username"/>
  <TextField label="Password" name="password" type="password" required min={setup?12:undefined} max={256} help={setup?'At least 12 characters. Use a unique password.':undefined}/>
  {!setup&&<TextField label="Authenticator code (if enabled)" name="otp" placeholder="6-digit code" max={6}/>}
  {error&&<div className="form-error" role="alert">{error}</div>}
  <button className="primary full" disabled={busy}>{busy?<LoaderCircle className="spin" size={18}/>:<ArrowRight size={18}/>} {busy?'Please wait…':setup?'Create administrator':'Sign in securely'}</button>
 </form><div className="deployment-id"><LockKeyhole size={14}/><span>Deployment <code>{short(status.deployment_id,24)}</code></span></div><details className="trust-details"><summary>Server public key</summary><code className="break">{status.public_key}</code><p>Compare this with a trusted copy from your administrator. A key displayed here does not independently establish trust.</p></details></div></main></div>;
}

/* ---------------- Navigation model ---------------- */
type NavItem={id:string;label:string;icon:LucideIcon};
const navGroups:{group:string;items:NavItem[]}[]=[
 {group:'Workspace',items:[{id:'overview',label:'Overview',icon:LayoutDashboard},{id:'live',label:'Live monitor',icon:Radio},{id:'guide',label:'Getting started',icon:BookOpen}]},
 {group:'Investigation',items:[{id:'evidence',label:'Evidence explorer',icon:FileSearch},{id:'timeline',label:'Timeline',icon:History},{id:'alerts',label:'Alerts & anomalies',icon:Bell},{id:'cases',label:'Case workspace',icon:FolderOpen},{id:'assistant',label:'Evidence assistant',icon:BrainCircuit}]},
 {group:'Preservation',items:[{id:'collectors',label:'Collectors',icon:Monitor},{id:'integrity',label:'Integrity',icon:ShieldCheck},{id:'custody',label:'Chain of custody',icon:Link2},{id:'acquisitions',label:'Acquisitions',icon:HardDriveDownload},{id:'reports',label:'Reports & exports',icon:FileText},{id:'cloud',label:'Cloud archive',icon:Cloud}]},
 {group:'Operations',items:[{id:'lab',label:'Attack simulation lab',icon:FlaskConical},{id:'integrations',label:'Tools & sensors',icon:Wrench},{id:'jobs',label:'Background jobs',icon:ListChecks},{id:'models',label:'Models & rules',icon:Cpu},{id:'admin',label:'Administration',icon:Settings}]},
];
const flatNav=navGroups.flatMap(g=>g.items.map(i=>({...i,group:g.group})));
function storedCollapsed():string[]{try{return JSON.parse(localStorage.getItem('cbb-nav-collapsed')||'[]')}catch{return []}}

/* ---------------- App ---------------- */
function App(){
 const [status,setStatus]=useState<Row>();const [session,setSession]=useState<Session>();const [ready,setReady]=useState(false);const [loadError,setLoadError]=useState('');
 const [location,setLocation]=useState(window.location.hash.slice(1)||'overview');const [revision,setRevision]=useState(0);
 const [toast,setToast]=useState<{message:string;kind:string}|null>(null);const [dialog,setDialog]=useState<{title:string;content:ReactNode}|null>(null);
 const [navOpen,setNavOpen]=useState(false);const [theme,setTheme]=useState<Theme>(storedTheme());const [collapsed,setCollapsed]=useState<string[]>(storedCollapsed());
 const dialogRef=useRef<HTMLDialogElement>(null);
 const loadStatus=()=>api('/status').then(s=>{setStatus(s);setLoadError('')}).catch(e=>setLoadError(e.message));
 useEffect(()=>{void loadStatus();api<Session>('/auth/me').then(s=>{setCsrf(s.csrf);setSession(s)}).catch(()=>{}).finally(()=>setReady(true));const route=()=>{setLocation(window.location.hash.slice(1)||'overview');setNavOpen(false);window.scrollTo(0,0)};const expired=()=>{setSession(undefined);setCsrf('');setDialog(null)};window.addEventListener('hashchange',route);window.addEventListener('session-expired',expired);return()=>{window.removeEventListener('hashchange',route);window.removeEventListener('session-expired',expired)}},[]);
 useEffect(()=>{if(!toast)return;const t=setTimeout(()=>setToast(null),5000);return()=>clearTimeout(t)},[toast]);
 useEffect(()=>{if(dialog&&!dialogRef.current?.open)dialogRef.current?.showModal();if(!dialog)dialogRef.current?.close()},[dialog]);
 useEffect(()=>{applyTheme(theme);try{localStorage.setItem('cbb-theme',theme)}catch{/* ignore */}},[theme]);
 useEffect(()=>{try{localStorage.setItem('cbb-nav-collapsed',JSON.stringify(collapsed))}catch{/* ignore */}},[collapsed]);
 const go=(path:string)=>{window.location.hash=path};const refresh=()=>setRevision(x=>x+1);const notify=(message:string,kind='success')=>setToast({message,kind});
 const context:Context={session:session!,status:status!,revision,refresh,notify,modal:(title,content)=>setDialog({title,content}),close:()=>setDialog(null),go,act:async(path,method,body,message='Changes saved')=>{const result=await api(path,method,body);refresh();if(message)notify(message);return result}};
 const [page,query='']=location.split('?');const params=new URLSearchParams(query);
 const selected=flatNav.find(x=>x.id===page)||flatNav[0];
 const detail=params.get('id')||params.get('target')||'';
 useEffect(()=>{document.title=selected.label+' · Cyber Black Box'},[selected.label]);
 if(!ready||!status)return <div className="boot"><div className="brand-mark"><Boxes/></div><h1>Cyber Black Box</h1>{loadError?<><p role="alert">{loadError}</p><button className="secondary" onClick={()=>void loadStatus()}>Retry connection</button></>:<><LoaderCircle className="spin"/><p>Connecting to your workspace…</p></>}</div>;
 if(!session)return <Auth status={status} onLogin={setSession} onStatus={loadStatus}/>;
 const toggleGroup=(g:string)=>setCollapsed(c=>c.includes(g)?c.filter(x=>x!==g):[...c,g]);
 return <Ctx.Provider value={context}><a className="skip" href="#main-content" onClick={e=>{e.preventDefault();document.getElementById('main-content')?.focus()}}>Skip to content</a>
 <div className="app-shell">
  <aside className={'sidebar'+(navOpen?' is-open':'')}>
   <a className="brand" href="#overview"><div className="brand-mark"><Boxes/></div><span>CYBER<b>BLACK BOX</b></span></a>
   <div className="workspace-tag"><span className="live-dot"/> {status.mode==='cloud'?'Cloud deployment':'Investigation workspace'}</div>
   <nav id="main-navigation" aria-label="Main navigation">{navGroups.map(g=>{const isCollapsed=collapsed.includes(g.group)&&!g.items.some(i=>i.id===page);return <div key={g.group} className={'nav-group'+(isCollapsed?' collapsed':'')}>
    <button type="button" className="nav-label" aria-expanded={!isCollapsed} onClick={()=>toggleGroup(g.group)}>{g.group}<ChevronDown size={14}/></button>
    <div className="nav-items">{g.items.map(({id,label,icon:Icon})=><a key={id} href={'#'+id} aria-current={page===id?'page':undefined} className={page===id?'active':''}>{page===id&&<span className="nav-marker"/>}<Icon size={17}/><span>{label}</span></a>)}</div>
   </div>})}</nav>
   <div className="sidebar-bottom"><ShieldCheck size={18}/><div>Evidence first<small>Accountable by design</small></div><span>v{status.version}</span></div>
  </aside>
  {navOpen&&<button className="nav-overlay" aria-label="Close navigation" onClick={()=>setNavOpen(false)}/>}
  <div className="main-shell">
   <header className="topbar"><div className="topbar-left"><button className="icon-button mobile-menu" aria-label={navOpen?'Close navigation':'Open navigation'} aria-expanded={navOpen} aria-controls="main-navigation" onClick={()=>setNavOpen(!navOpen)}><Menu size={20}/></button>
    <nav className="breadcrumb" aria-label="Breadcrumb"><span>{selected.group}</span><ChevronRight size={14}/>{detail?<><a href={'#'+selected.id}>{selected.label}</a><ChevronRight size={14}/><span className="crumb-detail" title={detail}>{short(detail,14)}</span></>:<b>{selected.label}</b>}</nav></div>
    <div className="topbar-right"><Badge tone="blue">{status.mode==='cloud'?'Cloud mode':'Virtual mode'}</Badge><UtcClock/>
     <button className="icon-button theme-toggle" title={theme==='dark'?'Switch to light theme':'Switch to dark theme'} aria-label={theme==='dark'?'Switch to light theme':'Switch to dark theme'} onClick={()=>setTheme(theme==='dark'?'light':'dark')}>{theme==='dark'?<Sun/>:<Moon/>}</button>
     <button className="profile" onClick={()=>context.modal('Account security',<AccountSecurity/>)}><span className="avatar">{session.user.username.slice(0,2).toUpperCase()}</span><span>{session.user.username}<small>{session.user.role}</small></span></button>
     <button title="Sign out" aria-label="Sign out" className="icon-button" onClick={async()=>{try{await api('/auth/session','DELETE');setSession(undefined);setCsrf('');setDialog(null);notify('Signed out')}catch(e){notify((e as Error).message,'error')}}}><LogOut size={17}/></button></div></header>
   <main id="main-content" tabIndex={-1}><Page page={page} params={params}/></main>
   <footer className="main-footer"><span>CYBER BLACK BOX · Evidence preservation platform</span><span>Deployment <Id value={status.deployment_id}/></span></footer>
  </div>
 </div>
 <dialog ref={dialogRef} className="modal" aria-labelledby="modal-title" onCancel={()=>setDialog(null)} onClick={e=>{if(e.target===dialogRef.current)setDialog(null)}}>{dialog&&<><div className="modal-heading"><h2 id="modal-title">{dialog.title}</h2><button className="icon-button" aria-label="Close dialog" onClick={()=>setDialog(null)}><X size={18}/></button></div><div className="modal-body">{dialog.content}</div></>}</dialog>
 {toast&&<div className={'toast '+toast.kind} role="status">{toast.kind==='error'?<ShieldAlert size={18}/>:<CheckCircle2 size={18}/>}<span>{toast.message}</span><button className="icon-button" aria-label="Dismiss notification" onClick={()=>setToast(null)}><X size={15}/></button></div>}
 </Ctx.Provider>;
}

function UtcClock(){const [now,setNow]=useState(()=>new Date());useEffect(()=>{const t=setInterval(()=>setNow(new Date()),30000);return()=>clearInterval(t)},[]);return <span className="utc-label" title="All times are shown in UTC"><Clock3 size={13}/>{now.toISOString().slice(11,16)} UTC</span>}

function Page({page,params}:{page:string;params:URLSearchParams}){
 switch(page){
  case 'guide':return <GettingStarted/>;case 'lab':return <AttackLab/>;case 'live':return <LiveMonitor/>;case 'integrations':return <Integrations/>;
  case 'cloud':return <CloudArchive/>;case 'assistant':return <Assistant/>;case 'evidence':return <Evidence params={params}/>;case 'timeline':return <Timeline/>;
  case 'alerts':return <Alerts/>;case 'cases':return <Cases params={params}/>;case 'collectors':return <Collectors/>;case 'integrity':return <Integrity/>;
  case 'custody':return <Custody params={params}/>;case 'acquisitions':return <Acquisitions/>;case 'reports':return <Reports/>;case 'jobs':return <Jobs/>;
  case 'models':return <Models/>;case 'admin':return <Admin/>;default:return <Overview/>;
 }
}

function AccountSecurity(){const {act,close,session}=useApp();const [secret,setSecret]=useState<Row>();return <><p className="lead">Protect <strong>{session.user.username}</strong> with a time-based authenticator code. Your current password is required.</p><Form submit={secret?'Enable authenticator':'Generate authenticator secret'} onSubmit={async v=>{const result=await act('/auth/mfa','POST',{...v,secret:secret?.secret},secret?'Authenticator enabled':'Secret generated; confirm a code to enable');if(secret)close();else setSecret(result)}}><TextField label="Current password" name="password" type="password" required/><TextField label="Current authenticator code (if already enabled)" name="current_otp"/>{secret&&<><Notice>Enter this secret into your authenticator app, then provide the current code below.</Notice><div className="secret"><code>{secret.secret}</code><CopyButton value={secret.secret}/></div><TextField label="New authenticator code" name="otp" required min={6} max={6}/></>}</Form></>}

/* ---------------- Overview ---------------- */
const sevColors=['var(--sev-0)','var(--sev-1)','var(--sev-2)','var(--sev-3)','var(--sev-4)','var(--sev-5)'];
function Overview(){
 const {go}=useApp();const [paused,setPaused]=useState(false);
 const state=useData('/overview',paused?0:10000);const alerts=useData<Row[]>('/alerts',paused?0:15000);const cases=useData<Row[]>('/cases',paused?0:15000);
 const d=state.data;const collectors=asArray<Row>(d?.collectors);const online=d?collectors.filter(isOnline).length:undefined;
 const sourceRows=asArray<Row>(d?.sources).slice().sort((a,b)=>b.count-a.count);
 const alertRows=alerts.data||[];const openAlerts=alertRows.filter(a=>['NEW','ACKNOWLEDGED','INVESTIGATING'].includes(a.status)).length;
 const bySeverity=useMemo(()=>{const counts=[0,0,0,0,0,0];for(const a of alertRows){const s=Number(a.severity);counts[s>=0&&s<=5?s:0]++}return counts},[alertRows]);
 const verification=d?.verification;const vStatus=verification?.status;
 const kpis:[LucideIcon,string,ReactNode,string,string,string][]=[
  [FileCheck2,'Sealed evidence',d?.evidence?.toLocaleString(),'Immutable records','evidence',''],
  [Bell,'Open alerts',alerts.data?openAlerts:undefined,alertRows.length+' findings in total','alerts',openAlerts?'warn':'ok'],
  [FolderOpen,'Assigned cases',d?.cases,`${d?.pending??'—'} receipts awaiting sealing`,'cases',''],
  [Monitor,'Collectors online',online==null?undefined:`${online} / ${collectors.length}`,'Heartbeat within 90 seconds','collectors',online&&online>0?'ok':'warn'],
 ];
 return <><SignalBanner/>
  <PageHead eyebrow="Workspace" title="Security overview" description="Collection, preservation and case activity across your authorized scope." actions={<><button className="secondary" onClick={()=>setPaused(!paused)}>{paused?<Play size={16}/>:<Pause size={16}/>} {paused?'Resume':'Pause live'}</button><button className="primary" onClick={()=>{state.reload();alerts.reload();cases.reload()}}><RefreshCw size={16} className={state.loading?'spin':''}/> Refresh</button></>}/>
  <State state={state}>
   <div className="refresh-line"><span className={'status-dot'+(state.error?' amber-dot':paused?' gray-dot':'')}/>{paused?'Live refresh paused':'Live · refreshes every 10 seconds while visible'}<span>Updated {utc(state.stamp)}</span></div>
   <div className="stats-grid">{kpis.map(([Icon,label,value,hint,link,tone])=><button key={label} className="stat-card" onClick={()=>go(link)}><div className="stat-top"><span>{label}</span><span className={'stat-icon '+tone}><Icon size={18}/></span></div><strong>{value??'—'}</strong><div>{hint}<ArrowRight size={14}/></div></button>)}</div>
   <div className="overview-grid">
    <Panel title="Evidence by source" subtitle="Preserved records in your authorized scope" actions={<button className="text-button" onClick={()=>go('evidence')}>Explore evidence <ArrowRight size={14}/></button>}>
     {sourceRows.length?<div className="chart"><BarChart data={sourceRows.map(s=>({label:String(s.source_type),value:Number(s.count)||0}))} onSelect={l=>go(routeQuery('evidence',{source:l}))}/></div>
     :<Empty title="Begin your evidence trail" description="Enroll a collector, run an attack simulation or import a fixture to start preserving records." action={<button className="secondary" onClick={()=>go('lab')}>Open simulation lab <ArrowRight size={15}/></button>}/>}
    </Panel>
    <Panel title="Preservation health" subtitle="Integrity and availability are separate checks" className="preservation-panel">
     <div className="health-summary"><div className={'health-icon '+(vStatus==='INVALID'?'bad':!verification?'idle':'')}>{vStatus==='INVALID'?<ShieldAlert size={26}/>:<ShieldCheck size={26}/>}</div><div><h3>{verification?vStatus==='INVALID'?'Verification needs attention':'Latest verification: '+vStatus:'Verification not run yet'}</h3><p>{verification?.assurance||'Run a verification to assess preserved data.'}</p></div></div>
     <div className="health-rows"><div><span>Last checkpoint</span><b>{d?.checkpoint?<Stamp value={d.checkpoint.created_at}/>:'Not created'}</b></div><div><span title="An independent witness stores checkpoint receipts separately from this server.">External witness</span><Badge tone={d?.witness_independent?'green':'slate'}>{d?.witness_independent?'Independent':d?.witness_configured?'Local witness':'Local only'}</Badge></div><div><span>Archive free space</span><b>{bytes(d?.disk?.free)}</b></div><div><span>Background worker</span><Badge tone={d?.worker?.last_error?'red':d?.worker?.last_tick?'green':'slate'}>{d?.worker?.last_error?'Attention':d?.worker?.last_tick?'Running':'Not observed'}</Badge></div></div>
     <button className="secondary" onClick={()=>go('integrity')}>Review integrity <ArrowRight size={15}/></button>
    </Panel>
   </div>
   <div className="overview-bottom">
    <Panel title="Priority alerts" subtitle="Ranked by risk. Scores support, not replace, analyst decisions" actions={<button className="text-button" onClick={()=>go('alerts')}>View all <ArrowRight size={14}/></button>}>
     <State state={alerts}><Table rows={alertRows.slice(0,6)} onRow={r=>go(routeQuery('alerts',{id:r.id}))} columns={[{label:'Finding',render:r=><div className="table-title"><strong>{r.rule_id}</strong><small>{r.explanation}</small></div>},{label:'Severity',render:r=><Severity value={r.severity}/>},{label:'Risk',render:r=><span className={'risk-value'+(Number(r.risk)>70?' high-risk':'')}>{Number(r.risk).toFixed(1)}</span>},{label:'Status',render:r=><Badge>{r.status}</Badge>}]} empty="No findings yet. Rules run automatically as evidence is sealed."/></State>
    </Panel>
    <div>
     <Panel title="Alerts by severity" subtitle="All findings in your scope"><div className="chart"><div className="donut-wrap"><Donut data={bySeverity.map((v,i)=>({label:severityLabels[i],value:v,color:sevColors[i]}))} caption="ALERTS"/><div className="chart-legend" style={{flexDirection:'column'}}>{bySeverity.map((v,i)=>v>0&&<span key={i}><i style={{background:sevColors[i]}}/>{severityLabels[i]} · {v}</span>).reverse()}{!alertRows.length&&<span>No alerts recorded</span>}</div></div></div></Panel>
     <Panel title="Recent cases" actions={<button className="text-button" onClick={()=>go('cases')}>View all <ArrowRight size={14}/></button>}><State state={cases}><div className="case-list">{(cases.data||[]).slice(0,4).map(c=><button key={c.id} onClick={()=>go(routeQuery('cases',{id:c.id}))}><span className="case-icon"><FolderOpen size={18}/></span><span><b>{c.title}</b><small>{c.status} · v{c.version} · {c.hold?'Retention hold':'No hold'}</small></span><ChevronRight size={16}/></button>)}</div>{!cases.data?.length&&<Empty description="Create a case to organize evidence, notes and reports."/>}</State></Panel>
    </div>
   </div>
  </State></>;
}

/* ---------------- Evidence ---------------- */
const toUtcIso=(v:string)=>v?(v.length===16?v+':00':v)+'Z':'';
function Evidence({params}:{params:URLSearchParams}){
 const {go,modal,session}=useApp();const [selected,setSelected]=useState<string[]>([]);const [severity,setSeverity]=useState('');
 const query={q:params.get('q')||'',source:params.get('source')||'',asset:params.get('asset')||'',start:params.get('start')||'',end:params.get('end')||'',cursor:params.get('cursor')||'',snapshot:params.get('snapshot')||''};
 const path=routeQuery('/evidence',query);const state=useData(path);const rows:Row[]=state.data?.items||[];const visible=severity?rows.filter(r=>String(r.severity)===severity):rows;
 const detail=params.get('id');const evidenceDialog=useRef<HTMLDialogElement>(null);
 useEffect(()=>{if(detail&&!evidenceDialog.current?.open)evidenceDialog.current?.showModal();},[detail]);
 useEffect(()=>setSelected([]),[path]);
 const closeDetail=()=>go(routeQuery('evidence',query));
 const allSelected=!!visible.length&&visible.every(r=>selected.includes(r.id));
 return <><PageHead eyebrow="Investigation" title="Evidence explorer" description="Search preserved observations. Every record links back to its original bytes." actions={<button className="secondary" onClick={state.reload}><RefreshCw size={16}/> Refresh</button>}/>
  <Panel><form className="search-filters" onSubmit={e=>{e.preventDefault();const v=Object.fromEntries(new FormData(e.currentTarget).entries()) as Record<string,string>;go(routeQuery('evidence',{...v,start:toUtcIso(v.start),end:toUtcIso(v.end)}))}} key={path}>
   <div className="filter-row"><div className="search-box"><Search size={18}/><input aria-label="Search evidence" name="q" defaultValue={query.q} placeholder="Search summary, event type, evidence ID or SHA-256…"/></div>
    <select name="source" defaultValue={query.source} aria-label="Source"><option value="">All sources</option>{sources.map(s=><option key={s}>{s}</option>)}</select>
    <input name="asset" aria-label="Asset ID" placeholder="Asset ID" defaultValue={query.asset}/></div>
   <div className="filter-row"><label className="inline-label">From (UTC) <input type="datetime-local" name="start" defaultValue={query.start.replace('Z','').slice(0,16)} aria-label="Received from, UTC"/></label><label className="inline-label">To (UTC) <input type="datetime-local" name="end" defaultValue={query.end.replace('Z','').slice(0,16)} aria-label="Received until, UTC"/></label><button className="primary" type="submit"><Search size={15}/> Search</button><button className="text-button" type="button" onClick={()=>go('evidence')}>Clear filters</button></div>
  </form></Panel>
  <div className="results-toolbar"><div><strong>{visible.length}</strong> records on this page {state.data&&<span className="muted">· frozen at sequence {state.data.snapshot}</span>}</div><div className="actions"><select aria-label="Filter severity on this page" value={severity} onChange={e=>setSeverity(e.target.value)}><option value="">All severities</option>{[5,4,3,2,1].map(n=><option value={n} key={n}>{severityLabels[n]}</option>)}</select>{roleWrite(session.user)&&<button className="secondary" disabled={!selected.length} onClick={()=>modal('Add selected evidence to a case',<AddToCase ids={selected}/>)}><FolderOpen size={15}/> Add {selected.length||''} to case</button>}</div></div>
  <Panel><State state={state}><Table rows={visible} onRow={r=>go(routeQuery('evidence',{...query,id:r.id}))} columns={[
   {label:'',className:'select-col',render:r=><input type="checkbox" aria-label={'Select evidence '+r.id} checked={selected.includes(r.id)} onChange={e=>setSelected(s=>e.target.checked?[...s,r.id]:s.filter(id=>id!==r.id))}/>},
   {label:'Record / summary',render:r=><div className="table-title"><span className="mono">#{r.sequence} · {short(r.id)}</span><strong>{r.summary||r.event_type}</strong><small>{r.event_type}</small></div>},
   {label:'Source',render:r=><span className="source-label">{r.source_type}</span>},{label:'Received (UTC)',render:r=><Stamp value={r.received_at}/>},{label:'Severity',render:r=><Severity value={r.severity}/>},{label:'Asset',render:r=><Id value={r.asset_id}/>}]} empty="No evidence matches these filters. Check your case access and source coverage, or widen the time range."/>
   {!!visible.length&&<div className="table-footer"><label><input type="checkbox" checked={allSelected} onChange={e=>setSelected(e.target.checked?visible.map(r=>r.id):[])}/> Select all on this page</label><span>{selected.length} selected</span><div className="actions"><button className="secondary small" disabled={!query.cursor} onClick={()=>go(routeQuery('evidence',{...query,cursor:'',snapshot:''}))}>First page</button><button className="secondary small" disabled={!state.data?.next_cursor} onClick={()=>go(routeQuery('evidence',{...query,cursor:state.data.next_cursor,snapshot:state.data.snapshot}))}>Next page <ChevronRight size={15}/></button></div></div>}
  </State></Panel>
  {detail&&<dialog ref={evidenceDialog} className="evidence-dialog" aria-label="Evidence detail" onCancel={closeDetail} onClick={e=>{if(e.target===evidenceDialog.current)closeDetail()}}><div className="drawer-heading"><div className="eyebrow">Immutable evidence record</div><button className="icon-button" aria-label="Close evidence detail" onClick={closeDetail}><X size={18}/></button></div><EvidenceDetail key={detail} id={detail}/></dialog>}</>;
}

/* ---------------- Cases ---------------- */
function CaseForm({item}:{item?:Row}){
 const {act,close,go}=useApp();
 return <Form submit={item?'Save case version':'Create case'} onSubmit={async v=>{
  // Severity is only set at creation; the edit endpoint does not change it, so never send a default.
  const payload:Row=item?{title:v.title,description:v.description,status:v.status,conclusion:v.conclusion,hold:v.hold==='on',version:item.version}:{...v,severity:Number(v.severity||2)};
  const result=await act(item?'/cases/'+encodeURIComponent(item.id):'/cases',item?'PATCH':'POST',payload,item?'Case updated':'Case created');close();if(!item)go(routeQuery('cases',{id:result.id}))}}>
  <TextField label="Case title" name="title" defaultValue={item?.title} required min={3} max={200}/><TextArea label="Investigation scope" name="description" defaultValue={item?.description}/>
  {item?<><SelectField label="Status" name="status" defaultValue={item.status} options={['OPEN','TRIAGE','INVESTIGATING','REVIEW','CLOSED']}/><TextArea label="Conclusion and remaining risks" name="conclusion" defaultValue={item.conclusion||''} help="A conclusion is required before closing a case."/><label className="check-label"><input type="checkbox" name="hold" defaultChecked={item.hold}/> Keep evidence under retention hold</label><Notice>Editing case version {item.version}. A concurrent change will block this save so you can refresh and reconcile your changes.</Notice></>
  :<SelectField label="Severity" name="severity" defaultValue="3" options={[5,4,3,2,1].map(n=>({value:String(n),label:severityLabels[n]}))}/>}
 </Form>;
}
function CaseMembers({item}:{item:Row}){const users=useData<Row[]>('/users');const {act,close}=useApp();const options=(users.data||[]).filter(u=>u.active&&u.id!==item.owner_id&&!asArray<Row>(item.members).some(m=>m.user_id===u.id)).map(u=>({value:u.id,label:u.username+' · '+u.role}));return <State state={users}><Notice>Case members can access this case according to their account role. Share only with authorized investigators and reviewers.</Notice>{options.length?<Form submit="Add case member" onSubmit={async v=>{await act('/cases/'+encodeURIComponent(item.id)+'/members','POST',v,'Case access granted');close()}}><SelectField label="User" name="user_id" options={options} required/></Form>:<Empty title="No one else to add" description="Every active account already has access, or no other accounts exist. Administrators can create accounts in Administration."/>}</State>}
function Cases({params}:{params:URLSearchParams}){
 const {modal,go,session}=useApp();const state=useData<Row[]>('/cases');const id=params.get('id');
 return <><PageHead eyebrow="Investigation" title="Case workspace" description="Build a documented investigation with scoped evidence, notes and decisions." actions={roleWrite(session.user)&&<button className="primary" onClick={()=>modal('Create an investigation case',<CaseForm/>)}><Plus size={16}/> New case</button>}/>
  {id?<CaseDetail id={id}/>:<State state={state}><div className="case-grid">{(state.data||[]).map(c=><button className="case-card" key={c.id} onClick={()=>go(routeQuery('cases',{id:c.id}))}><div className="case-card-top"><span className="case-icon"><FolderOpen size={20}/></span><Badge>{c.status}</Badge></div><h2>{c.title}</h2><p>{c.description||'No description added.'}</p><div className="case-card-meta"><Severity value={c.severity}/><span><LockKeyhole size={13}/>{c.hold?'Retention hold':'Hold released'}</span></div><div className="case-card-footer"><span>v{c.version} · {short(c.id,8)}<small className="block">{utc(c.created_at)}</small></span><span>Open <ArrowRight size={15}/></span></div></button>)}</div>
  {!state.data?.length&&<Panel><Empty title="Start your first investigation" description="A case organizes evidence, notes, acquisition approvals and signed export packages." action={roleWrite(session.user)&&<button className="primary" onClick={()=>modal('Create a case',<CaseForm/>)}><Plus size={16}/> New case</button>}/></Panel>}</State>}</>;
}
function CaseDetail({id}:{id:string}){
 const {session,modal,go,act,notify,close}=useApp();const state=useData('/cases/'+encodeURIComponent(id));const users=useData<Row[]>('/users');const [tab,setTab]=useState('Evidence');const [exporting,setExporting]=useState(false);const c=state.data;
 const userName=(uid:string)=>users.data?.find(u=>u.id===uid)?.username;
 return <><button className="text-button back-link" onClick={()=>go('cases')}>← All cases</button><State state={state}>{c&&<><Panel>
  <div className="case-detail-header"><div><div className="actions"><Badge>{c.status}</Badge><Severity value={c.severity}/><span className="muted">Version {c.version}</span></div><h2>{c.title}</h2><p>{c.description}</p><div className="id-line"><code>{c.id}</code><CopyButton value={c.id}/></div></div>
   <div className="actions">{roleWrite(session.user)&&<button className="secondary" onClick={()=>modal('Edit case',<CaseForm item={c}/>)}>Edit case</button>}{c.owner_id===session.user.id&&<button className="secondary" onClick={()=>modal('Share case access',<CaseMembers item={c}/>)}><Users size={15}/> Members</button>}</div></div>
  <div className="case-summary-strip"><span><LockKeyhole size={15}/>{c.hold?'Evidence under retention hold':'Retention hold released'}</span><span><FileCheck2 size={15}/>{asArray(c.evidence).length} evidence records</span><span>{asArray(c.notes).length} notes</span><span>Updated <Stamp value={c.updated_at}/></span></div>
  <div style={{padding:'0 18px'}}><Tabs items={['Evidence','Notes','Summary','Reports']} value={tab} onChange={setTab}/></div>
  {tab==='Evidence'?<><Table rows={asArray(c.evidence)} onRow={r=>go(routeQuery('evidence',{id:r.id}))} columns={[{label:'Evidence',render:r=><div className="table-title"><span className="mono">#{r.sequence} · {short(r.id)}</span><strong>{r.summary}</strong></div>},{label:'Source',render:r=><span className="source-label">{r.source_type}</span>},{label:'Occurrence (UTC)',render:r=><Stamp value={r.occurred_at}/>}]} empty="No evidence is assigned yet. Select records in Evidence explorer and add them to this case."/>{roleWrite(session.user)&&<div className="panel-foot"><button className="secondary" onClick={()=>go('evidence')}><Plus size={15}/> Find evidence</button></div>}</>
  :tab==='Notes'?<div className="notes"><div className="note-list">{asArray<Row>(c.notes).map(n=>{const name=userName(n.author_id);return <article className="note" key={n.id}><div><span className="avatar small-avatar">{(name||'??').slice(0,2).toUpperCase()}</span><strong title={n.author_id}>{name||short(n.author_id)}</strong><time>{utc(n.created_at)}</time>{n.previous_id&&<Badge tone="blue">Revision</Badge>}</div><p>{n.body}</p>{session.user.id===n.author_id&&<button className="text-button" onClick={()=>modal('Append a note revision',<Form submit="Save revision" onSubmit={async v=>{await act('/cases/'+encodeURIComponent(id)+'/notes','POST',{body:v.body,previous_id:n.id},'Revision appended');close()}}><TextArea label="Revised note" name="body" defaultValue={n.body} required/><Notice>The original note remains in the custody record.</Notice></Form>)}>Revise note</button>}</article>})}{!asArray(c.notes).length&&<Empty title="No notes yet" description="Record observations, hypotheses and limitations as you investigate."/>}</div>{session.user.role!=='auditor'&&<Form submit="Add note" onSubmit={async(v,f)=>{await act('/cases/'+encodeURIComponent(id)+'/notes','POST',v,'Note added');f.reset()}}><TextArea label="Investigation note" name="body" required help="Plain text. Notes are append-only; revisions preserve the original."/></Form>}</div>
  :tab==='Summary'?<div className="panel-content"><DetailGrid items={[["Owner",userName(c.owner_id)||<Id value={c.owner_id}/>],["Created",<Stamp value={c.created_at}/>],["Status",<Badge>{c.status}</Badge>],["Case members",String(asArray(c.members).length+1)],["Conclusion",c.conclusion||'No conclusion recorded.']]}/><button className="secondary" onClick={()=>go(routeQuery('custody',{target:id}))}><Link2 size={15}/> View custody trail</button></div>
  :<div className="panel-content"><Notice>Export packages freeze the case version and selected evidence. They include the report, original bytes, manifest, signature and verification result.</Notice><div className="actions"><button className="primary" disabled={exporting||!asArray(c.evidence).length||!roleWrite(session.user)} onClick={async()=>{setExporting(true);try{await act('/exports','POST',{case_id:id},'Report queued. Follow its progress in Background jobs.');go('reports')}catch(e){notify((e as Error).message,'error')}finally{setExporting(false)}}}><FileText size={16}/>{exporting?'Queuing report…':'Generate signed package'}</button><button className="secondary" onClick={()=>go('reports')}>View existing packages</button></div></div>}
 </Panel></>}</State></>;
}

/* ---------------- Alerts ---------------- */
function AlertDetail({a}:{a:Row}){const {close,go}=useApp();return <><DetailGrid items={[["Rule",a.rule_id],["Risk score",Number(a.risk).toFixed(2)],["Severity",<Severity value={a.severity}/>],["Model",a.model_id||'Rule based'],["Status",<Badge>{a.status}</Badge>],["Created",<Stamp value={a.created_at}/>]]}/><p>{a.explanation}</p><h3>Score components</h3><StructuredView value={a.components}/>{a.decision&&<><h3>Latest analyst decision</h3><StructuredView value={typeof a.decision==='string'?(()=>{try{return JSON.parse(a.decision)}catch{return a.decision}})():a.decision}/></>}<button className="secondary" onClick={()=>{close();go(routeQuery('evidence',{id:a.evidence_id}))}}>Open supporting evidence <ArrowRight size={15}/></button></>}
function Alerts(){
 const {session,modal,act,close}=useApp();const state=useData<Row[]>('/alerts',15000);const [status,setStatus]=useState('');const [type,setType]=useState('All findings');
 const items=(state.data||[]).filter(a=>(!status||a.status===status)&&(type==='All findings'||(type==='Model results'?!!a.model_id:!a.model_id)));
 return <><PageHead eyebrow="Investigation" title="Alerts & anomalies" description="Review ranked findings with their supporting evidence and record your decision." actions={<button className="secondary" onClick={state.reload}><RefreshCw size={16}/> Refresh</button>}/>
  <Notice>Scores are investigation aids. A low score does not prove an event harmless; a high score does not establish malicious intent.</Notice>
  <Panel><div className="panel-heading"><Tabs items={['All findings','Rule results','Model results']} value={type} onChange={setType}/><select aria-label="Alert status" value={status} onChange={e=>setStatus(e.target.value)}><option value="">All statuses</option>{['NEW','ACKNOWLEDGED','INVESTIGATING','DISMISSED','RESOLVED'].map(s=><option key={s}>{s}</option>)}</select></div>
  <State state={state}><Table rows={items} onRow={a=>modal('Finding details',<AlertDetail a={a}/>)} columns={[{label:'Finding',render:a=><div className="table-title"><strong>{a.rule_id}</strong><small>{a.explanation}</small></div>},{label:'Risk',render:a=><span className={'risk-value'+(Number(a.risk)>70?' high-risk':'')}>{Number(a.risk).toFixed(1)}</span>},{label:'Severity',render:a=><Severity value={a.severity}/>},{label:'Status',render:a=><Badge>{a.status}</Badge>},{label:'Asset',render:a=><Id value={a.asset_id}/>},{label:'Review',render:a=>roleWrite(session.user)?<button className="secondary small" onClick={()=>modal('Record analyst decision',<Form submit="Save decision" onSubmit={async v=>{await act('/alerts/'+encodeURIComponent(a.id)+'/decisions','POST',v,'Decision recorded');close()}}><Notice tone="warning">{a.rule_id}: {a.explanation}</Notice><SelectField label="Decision status" name="status" options={['ACKNOWLEDGED','INVESTIGATING','DISMISSED','RESOLVED']} defaultValue="ACKNOWLEDGED"/><TextArea label="Reason and supporting observations" name="reason" required/></Form>)}>Review <ChevronRight size={14}/></button>:<span className="muted">Read only</span>}]} empty="No findings match this filter. Rule processing and model scoring produce separate results."/></State></Panel></>;
}

/* ---------------- Timeline ---------------- */
function Timeline(){
 const {go,modal,act,close,session}=useApp();const incidents=useData<Row[]>('/incidents');const events=useData('/evidence?limit=200');
 const [view,setView]=useState('Correlated incidents');const [sort,setSort]=useState('Occurrence time');const [lane,setLane]=useState('');
 const time=(x:Row)=>Date.parse(x.occurred_at||x.received_at)||0;
 const rows=(events.data?.items||[]).filter((x:Row)=>!lane||x.source_type===lane).slice().sort((a:Row,b:Row)=>sort==='Receipt sequence'?a.sequence-b.sequence:time(a)-time(b));
 return <><PageHead eyebrow="Investigation" title="Timeline & correlation" description="Follow event sequences and inspect why observations were linked." actions={<button className="secondary" onClick={()=>{incidents.reload();events.reload()}}><RefreshCw size={16}/> Refresh</button>}/>
  <Panel><div className="panel-heading"><Tabs items={['Correlated incidents','Event timeline']} value={view} onChange={setView}/><div className="actions">{view==='Event timeline'&&<><select value={lane} onChange={e=>setLane(e.target.value)} aria-label="Source lane"><option value="">All source lanes</option>{sources.map(s=><option key={s}>{s}</option>)}</select><select value={sort} onChange={e=>setSort(e.target.value)} aria-label="Timeline sort"><option>Occurrence time</option><option>Receipt sequence</option></select></>}</div></div>
  {view==='Correlated incidents'?<State state={incidents}><div className="incident-list">{(incidents.data||[]).map(i=><article className="incident" key={i.id}><div className="incident-header"><span className="incident-icon"><Network size={20}/></span><div><h3>{i.title}</h3><p>{i.rule_id} · v{i.version} · asset {short(i.asset_id)}</p></div><Badge tone={i.confidence>=.8?'blue':'amber'}>{Math.round(i.confidence*100)}% confidence</Badge></div>
   <div className="evidence-chain">{asArray<string>(i.evidence_ids).map((id,n)=><React.Fragment key={id}>{n>0&&<ArrowRight size={16}/>}<button onClick={()=>go(routeQuery('evidence',{id}))}><FileCheck2 size={15}/><Id value={id}/></button></React.Fragment>)}</div>
   <div className="incident-footer"><Stamp value={i.created_at}/><div className="actions"><button className="text-button" onClick={()=>modal('Correlation decision history',<><Notice>Correlation proposes a relationship. Confidence reflects the available join keys and time window.</Notice><StructuredView value={i.decisions} empty="No analyst decisions recorded yet."/></>)}>Decision history ({asArray(i.decisions).length})</button>{roleWrite(session.user)&&<button className="secondary small" onClick={()=>modal('Review correlated incident',<Form submit="Record review" onSubmit={async v=>{await act('/incidents/'+encodeURIComponent(i.id)+'/decisions','POST',v,'Incident review appended');close()}}><SelectField label="Decision" name="decision" options={['accepted','rejected','needs-review']}/><TextArea label="Reason" name="reason" required/><Notice>This decision appends a new incident version. Original evidence remains unchanged.</Notice></Form>)}>Review link</button>}</div></div></article>)}</div>
   {!incidents.data?.length&&<Empty title="No correlated incidents yet" description="The engine links related process, file and network observations using asset, process identity and bounded time windows."/>}</State>
  :<State state={events}><div style={{padding:'14px 18px 0'}}><Notice>Showing up to 200 records from the first frozen page. Unknown occurrence times use receipt time and are marked explicitly. Use Evidence explorer to search the complete archive.</Notice></div><div className="event-timeline">{rows.map((e:Row)=><button key={e.id} className="timeline-event" onClick={()=>go(routeQuery('evidence',{id:e.id}))}><div className="timeline-time"><Stamp value={sort==='Receipt sequence'?e.received_at:e.occurred_at||e.received_at}/><small>Sequence {e.sequence}</small></div><div className={'timeline-dot severity-'+(Number(e.severity)||0)}/><div className="timeline-body"><div><span className="source-label">{e.source_type}</span><Severity value={e.severity}/>{!e.occurred_at&&<Badge tone="amber">Receipt time</Badge>}</div><strong>{e.summary||e.event_type}</strong><small>{e.event_type} · {short(e.asset_id)}</small></div><ChevronRight size={16}/></button>)}</div>{!rows.length&&<Empty description="No evidence is available for this source lane."/>}</State>}</Panel></>;
}

createRoot(document.getElementById('root')!).render(<App/>);
