"""Bounded Kali exercises against an ephemeral Windows loopback-only decoy.

No user-supplied shell, destination, payload or command is accepted. SSH forwards
only the two local decoy ports. Existing Kali journal collection is independent.
"""
import base64
import json
import secrets
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socketserver import BaseRequestHandler, ThreadingTCPServer
from sqlalchemy import select, update
from . import db as D
from .crypto import uid, now, sha, canon, dumps, loads
from .service import DomainError, row, rows
from .kali import connection, ssh_base, check_connection

SCENARIOS = {
    'login-failures': {'label': 'Failed login simulation', 'count': 6, 'description': 'Six invalid logins to an isolated Windows decoy; no real accounts.'},
    'web-probes': {'label': 'Web path probing', 'count': 5, 'description': 'Five requests to fixed nonexistent decoy paths.'},
    'port-probe': {'label': 'TCP connection probing', 'count': 6, 'description': 'Six connections to one dedicated lab listener; no network scan.'},
}
PATHS = ('/.env', '/admin', '/backup.zip', '/wp-admin', '/server-status')


def runner_source(scenario, token):
    # The only substitutions are a server-generated token and a validated enum.
    if scenario not in SCENARIOS:
        raise ValueError('Unknown scenario')
    return '''import json,socket,time,urllib.request,urllib.error
scenario=SCENARIO
token=TOKEN
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
paths=['/.env','/admin','/backup.zip','/wp-admin','/server-status']
for i in range(5 if scenario=='web-probes' else 6):
 try:
  check=urllib.request.Request('http://127.0.0.1:18888/continue',headers={'X-Lab-Token':token})
  with opener.open(check,timeout=3) as r: pass
  if scenario=='port-probe':
   with socket.create_connection(('127.0.0.1',18889),timeout=3) as s:
    s.sendall((token+'\\n').encode());s.settimeout(3);s.recv(32)
  else:
   path='/api/login' if scenario=='login-failures' else paths[i]
   payload=json.dumps({'username':'lab-user','password':'invalid-lab-only'}).encode() if scenario=='login-failures' else None
   req=urllib.request.Request('http://127.0.0.1:18888'+path,data=payload,headers={'X-Lab-Token':token,'Content-Type':'application/json'})
   try:
    with opener.open(req,timeout=3) as r: pass
   except urllib.error.HTTPError as e:
    if e.code not in (401,404): raise
  time.sleep(.6)
 except Exception:
  raise SystemExit(2)
'''.replace('SCENARIO', repr(scenario)).replace('TOKEN', repr(token))


class LabManager:
    def __init__(self, service):
        self.service = service
        self.lock = threading.RLock()
        self.active = None
        self.cancel = threading.Event()
        self.thread = None
        self.last_start = -100.0
        self.root = Path(__file__).resolve().parents[1]
        self.executor = self.execute_ssh

    def recover(self):
        with self.service.db.tx() as c:
            c.execute(update(D.lab_runs).where(D.lab_runs.c.state.in_(['RUNNING','STOPPING','FINALIZING'])).values(state='INTERRUPTED',ended_at=now(),error='Server restarted. Preserved receipts remain; no exercise was replayed.'))

    def available(self):
        try:connection(self.root)
        except (ValueError, TypeError, OSError):return False
        return self.service.settings.mode == 'virtual' and bool(shutil.which('ssh')) and all((self.root/'work'/n).is_file() for n in ('kali-ssh','kali-known-hosts'))

    def check(self):
        if not self.available():raise DomainError('LAB_NOT_CONFIGURED','Check local Kali connection configuration, SSH key and pinned host entry.',422)
        try:return {**check_connection(self.root), 'checked_at':now()}
        except (ValueError, TypeError, OSError, subprocess.TimeoutExpired) as exc:
            raise DomainError('LAB_CONNECTION_FAILED',str(exc)[:300],422) from exc

    def status(self, actor):
        with self.service.db.read() as c:
            runs = rows(c, select(D.lab_runs).where(D.lab_runs.c.actor_id==actor['id']).order_by(D.lab_runs.c.started_at.desc()).limit(30))
            for run in runs:
                run['observed_count'] = len(loads(run.pop('receipts'), []))
                job = row(c,select(D.jobs).where(D.jobs.c.id==run['job_id'])) if run['job_id'] else None
                run['report_state'] = job['state'] if job else 'NOT_QUEUED'
                run['export_id'] = loads(job['result'],{}).get('export_id') if job else None
                run['report_error'] = job['error'] if job else None
        return {'configured':self.available(), 'busy':self.active is not None, 'scenarios':SCENARIOS, 'runs':runs,
                'target':'Windows loopback decoy via pinned Kali SSH', 'signature':'Ed25519 signed package manifest; PDF/DOCX are covered by their SHA-256 hashes.'}

    def start(self, actor, scenario):
        if not isinstance(scenario,str) or scenario not in SCENARIOS:
            raise DomainError('LAB_SCENARIO','Choose a predefined scenario',422)
        if not self.available():
            raise DomainError('LAB_NOT_CONFIGURED','Local Kali SSH key and pinned host entry are required; see Kali setup.',422)
        with self.lock:
            if self.active:raise DomainError('LAB_BUSY','Another exercise is still running or finalizing',409)
            if time.monotonic()-self.last_start<6:raise DomainError('LAB_COOLDOWN','Wait six seconds between exercises',429)
            rid,cid=uid(),uid()
            with self.service.db.tx() as c:
                c.execute(D.cases.insert().values(id=cid,title='LAB · '+SCENARIOS[scenario]['label'],description='Authorized bounded simulation originating on Kali against a Windows loopback decoy. Only received requests are evidence. Run '+rid,owner_id=actor['id'],status='INVESTIGATING',severity=2,version=1,hold=True,created_at=now(),updated_at=now()))
                c.execute(D.lab_runs.insert().values(id=rid,actor_id=actor['id'],case_id=cid,scenario=scenario,state='RUNNING',started_at=now(),receipts='[]'))
                self.service.audit(c,actor['id'],'LAB_STARTED',cid,details={'run_id':rid,'scenario':scenario,'limit':SCENARIOS[scenario]['count']})
            self.active=rid;self.cancel.clear();self.last_start=time.monotonic()
            self.thread=threading.Thread(target=self.execute,args=(rid,),daemon=True);self.thread.start()
            return {'id':rid,'case_id':cid}

    def stop_run(self, actor, rid):
        with self.lock, self.service.db.tx() as c:
            run=row(c,select(D.lab_runs).where(D.lab_runs.c.id==rid))
            if not run or run['actor_id']!=actor['id']:raise DomainError('NOT_FOUND','Run not found',404)
            if self.active==rid and run['state'] in ('RUNNING','STOPPING'):
                self.cancel.set()
                c.execute(update(D.lab_runs).where(D.lab_runs.c.id==rid).values(state='STOPPING'))
                self.service.audit(c,actor['id'],'LAB_STOP_REQUESTED',run['case_id'],details={'run_id':rid})
        return {'stopping':self.cancel.is_set() and self.active==rid}

    def close(self):
        self.cancel.set()
        if self.thread:self.thread.join(timeout=12)

    def execute_ssh(self, scenario, token, http_port, tcp_port):
        base,destination=ssh_base(self.root)
        command=base+['-R',f'127.0.0.1:18888:127.0.0.1:{http_port}','-R',f'127.0.0.1:18889:127.0.0.1:{tcp_port}',destination,'python3','-']
        process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        try:
            process.stdin.write(runner_source(scenario,token).encode());process.stdin.close()
            deadline=time.monotonic()+45
            while process.poll() is None:
                if self.cancel.wait(.1):process.terminate();break
                if time.monotonic()>deadline:process.terminate();raise RuntimeError('Kali exercise timed out')
            process.wait(timeout=5)
            if process.returncode and not self.cancel.is_set():raise RuntimeError('Kali connection or exercise failed. Check VM, SSH key permissions and reserved lab ports.')
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=5)

    def execute(self, rid):
        servers=[];started_servers=[];error=None;collector=None
        with self.service.db.read() as c:run=row(c,select(D.lab_runs).where(D.lab_runs.c.id==rid))
        records=[];observe_lock=threading.Lock();token=secrets.token_urlsafe(32);manager=self
        try:
            enrollment=secrets.token_urlsafe(32)
            with self.service.db.tx() as c:
                c.execute(D.enrollments.insert().values(id=uid(),token_hash=sha(enrollment.encode()),name='Windows lab observer '+rid[:8],os='lab',expires=time.time()+60,used=False))
            credentials=self.service.enroll(enrollment)
            with self.service.db.tx() as c:
                c.execute(update(D.collectors).where(D.collectors.c.id==credentials['collector_id']).values(configuration=dumps({'intake_case_id':run['case_id']})))
                collector=row(c,select(D.collectors).where(D.collectors.c.id==credentials['collector_id']))
            def observe(kind, detail):
                with observe_lock:
                    if manager.cancel.is_set() or len(records)>=SCENARIOS[run['scenario']]['count']:return False
                    event={'lab_simulation':True,'run_id':rid,'event_type':kind,'observed_at':now(),'severity':3 if kind=='lab.auth.failure' else 2,'summary':'LAB observed '+kind+' from Kali through SSH','detail':detail,'transport':'SSH forwarded loopback; source IP is not original Kali address'}
                    raw=canon(event)
                    receipt=manager.service.accept(collector,[{'boot_id':rid,'source_seq':str(len(records)+1),'source_type':'lab.fixture','event_type':kind,'collected_at':event['observed_at'],'original_timestamp':event['observed_at'],'raw_media_type':'application/json','raw_base64':base64.b64encode(raw).decode(),'raw_sha256':sha(raw),'source_cursor':{'run_id':rid}}])[0]
                    records.append(receipt)
                    with manager.service.db.tx() as c:c.execute(update(D.lab_runs).where(D.lab_runs.c.id==rid).values(receipts=dumps(records)))
                    return True
            class HTTP(BaseHTTPRequestHandler):
                def setup(self):
                    super().setup();self.connection.settimeout(3)
                def log_message(self,*args):pass
                def do_GET(self):
                    authorized=secrets.compare_digest(self.headers.get('X-Lab-Token',''),token) and not manager.cancel.is_set()
                    code=403
                    if authorized and self.path=='/continue':code=200
                    elif authorized and self.path in PATHS and run['scenario']=='web-probes':
                        code=404 if observe('lab.http.probe',{'path':self.path,'status':404}) else 409
                    self.send_response(code);self.send_header('Content-Length','0');self.end_headers()
                def do_POST(self):
                    if self.path!='/api/login' or run['scenario']!='login-failures' or not secrets.compare_digest(self.headers.get('X-Lab-Token',''),token):code=403
                    else:
                        try:
                            size=int(self.headers.get('Content-Length','0'))
                            if not 0<size<=1024:raise ValueError()
                            body=self.rfile.read(size)
                            if len(body)!=size:raise ValueError()
                            parsed=json.loads(body)
                            if not isinstance(parsed,dict):raise ValueError()
                            username=parsed.get('username')
                            if username is not None and (not isinstance(username,str) or len(username)>64):raise ValueError()
                            # Store only the observed username; never retain passwords.
                            code=401 if observe('lab.auth.failure',{'username':username,'status':401}) else 409
                        except (ValueError,OSError):code=400
                    self.send_response(code);self.send_header('Content-Length','0');self.end_headers()
            class TCP(BaseRequestHandler):
                def handle(self):
                    self.request.settimeout(3)
                    try:
                        incoming=b''
                        while b'\n' not in incoming and len(incoming)<128:
                            chunk=self.request.recv(128-len(incoming))
                            if not chunk:break
                            incoming+=chunk
                        incoming=incoming.strip().decode('ascii')
                        if run['scenario']=='port-probe' and secrets.compare_digest(incoming,token):
                            if observe('lab.port.probe',{'listener':'Windows isolated TCP decoy'}):self.request.sendall(b'LAB\n')
                    except (OSError,UnicodeError):pass
            http=ThreadingHTTPServer(('127.0.0.1',0),HTTP);servers.append(http)
            tcp=ThreadingTCPServer(('127.0.0.1',0),TCP);tcp.daemon_threads=True;servers.append(tcp)
            for server in servers:
                threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.1},daemon=True).start();started_servers.append(server)
            self.executor(run['scenario'],token,http.server_address[1],tcp.server_address[1])
        except Exception as exc:error=str(exc)[:300]
        finally:
            for server in started_servers:server.shutdown()
            for server in servers:server.server_close()
            with self.service.db.tx() as c:c.execute(update(D.lab_runs).where(D.lab_runs.c.id==rid).values(state='FINALIZING'))
            try:
                # Accept only already sealed observations; do not invent evidence
                # for failed requests. Existing intake worker owns sealing.
                deadline=time.monotonic()+45
                ids=[r['evidence_id'] for r in records]
                receipt_ids=[r['receipt_id'] for r in records]
                while ids:
                    # A bounded run must not wait behind an unrelated historical
                    # backlog. Concurrent sealing rechecks STAGED under the DB lock.
                    self.service.seal_pending(limit=6,receipt_ids=receipt_ids)
                    with self.service.db.read() as c:items=rows(c,select(D.evidence).where(D.evidence.c.id.in_(ids)))
                    if len(items)==len(ids):break
                    if time.monotonic()>deadline:raise RuntimeError('Receipt sealing still pending; preserve the run and inspect Background jobs.')
                    time.sleep(.2)
                state='FAILED' if error else 'STOPPED' if self.cancel.is_set() else 'COMPLETE' if len(records)==SCENARIOS[run['scenario']]['count'] else 'PARTIAL'
                with self.service.db.tx() as c:
                    self.service.audit(c,run['actor_id'],'LAB_FINISHED',run['case_id'],details={'run_id':rid,'state':state,'observed':len(ids),'error':error})
                    actor=row(c,select(D.users).where(D.users.c.id==run['actor_id']))
                    jid=None
                    if ids and actor and actor['active'] and actor['role']=='admin':
                        case=self.service.allowed_case(c,actor,run['case_id'],write=True)
                        jid=self.service.create_job(c,'export',actor['id'],{'evidence_ids':ids,'case_version':case['version'],'case_snapshot':case,'notes_snapshot':[],'ai_snapshot':[]},run['case_id'],operation_key='lab-export:'+rid)
                    c.execute(update(D.lab_runs).where(D.lab_runs.c.id==rid).values(state=state,ended_at=now(),error=error,job_id=jid))
            except Exception as exc:
                with self.service.db.tx() as c:c.execute(update(D.lab_runs).where(D.lab_runs.c.id==rid).values(state='FAILED',ended_at=now(),error=str(exc)[:300]))
            finally:
                try:
                    if collector:
                        with self.service.db.tx() as c:
                            c.execute(update(D.collectors).where(D.collectors.c.id==collector['id']).values(state='REVOKED'))
                finally:
                    with self.lock:self.active=None
