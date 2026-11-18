"""Exercise controls use real loopback decoys; SSH is replaced only in unit tests."""
import json
import socket
import threading
import time
import zipfile
from io import BytesIO
import httpx
import pytest
from sqlalchemy import select, update
from test_api import app_client
from cbb import db as D
from cbb.service import row
from cbb.lab import SCENARIOS, PATHS, runner_source
from cbb.verify import verify_package


def test_docker_runner_preserves_token_and_fixed_destination():
    source=runner_source('port-probe','secret18888TOKEN18889',host='host.docker.internal',http_port=40001,tcp_port=40002)
    assert "token='secret18888TOKEN18889'" in source
    assert 'host.docker.internal:40001' in source
    assert "('host.docker.internal',40002)" in source
    compile(source,'docker-runner','exec')


def finish(app, client):
    app.state.lab.thread.join(12)
    assert not app.state.lab.thread.is_alive()
    return client.get('/api/v1/lab').json()['runs'][0]


def local_sender(scenario, token, hp, tp):
    with httpx.Client(base_url=f'http://127.0.0.1:{hp}',trust_env=False) as client:
        assert client.get('/continue').status_code==403
        headers={'X-Lab-Token':token}
        for i in range(SCENARIOS[scenario]['count']):
            assert client.get('/continue',headers=headers).status_code==200
            if scenario=='login-failures':
                assert client.post('/api/login',headers=headers,json={'password':'DO-NOT-PRESERVE'}).status_code==401
            elif scenario=='web-probes':assert client.get(PATHS[i],headers=headers).status_code==404
            else:
                with socket.create_connection(('127.0.0.1',tp),timeout=3) as sock:
                    sock.sendall((token+'\n').encode());assert sock.recv(32)==b'LAB\n'
        if scenario=='login-failures':assert client.post('/api/login',headers=headers,json={}).status_code==409


@pytest.mark.parametrize('scenario',list(SCENARIOS))
def test_lab_observations_and_signed_reports(app_client,monkeypatch,tmp_path,scenario):
    app,c=app_client;lab=app.state.lab;service=app.state.service
    monkeypatch.setattr(lab,'available',lambda:True);lab.executor=local_sender
    r=c.post('/api/v1/lab/runs',json={'scenario':scenario});assert r.status_code==202,r.text
    run=finish(app,c)
    assert run['state']=='COMPLETE',run
    assert run['observed_count']==SCENARIOS[scenario]['count']
    with service.db.read() as conn:
        job=row(conn,select(D.jobs).where(D.jobs.c.id==run['job_id']))
        case=row(conn,select(D.cases).where(D.cases.c.id==run['case_id']))
    assert case['version']==1+run['observed_count']
    result=service.run_job(job)
    for fmt,magic in [('pdf',b'%PDF'),('docx',b'PK'),('json',b'{')]:
        response=c.get('/api/v1/exports/'+result['export_id']+'/report/'+fmt)
        assert response.status_code==200,response.text[:100]
        assert response.content.startswith(magic)
        assert response.headers['x-signature-scope']=='Detached Ed25519 signature and signed ZIP manifest'
        from cbb.crypto import verify_signature, sha
        sig=c.get('/api/v1/exports/'+result['export_id']+'/report/'+fmt+'?signature=true')
        assert sig.status_code==200
        payload=verify_signature(sig.json(),'CBB-REPORT-v1',service.deployment['public_key'])
        assert payload['sha256']==sha(response.content)
    package=c.get('/api/v1/exports/'+result['export_id']+'/download')
    path=tmp_path/'run.zip';path.write_bytes(package.content)
    assert verify_package(path,service.deployment['public_key'])['status']=='VALID'
    with zipfile.ZipFile(BytesIO(package.content)) as z:
        report=json.loads(z.read('report.json'));assert len(report['evidence'])==run['observed_count']
        for name in z.namelist():
            if name.endswith('.raw'):assert b'DO-NOT-PRESERVE' not in z.read(name)
    assert c.get('/api/v1/exports/'+result['export_id']+'/report/exe').status_code==422


def test_lab_stop_busy_and_no_fabricated_observations(app_client,monkeypatch):
    app,c=app_client;lab=app.state.lab
    monkeypatch.setattr(lab,'available',lambda:True)
    entered=threading.Event()
    def wait_sender(*args):entered.set();lab.cancel.wait(5)
    lab.executor=wait_sender
    r=c.post('/api/v1/lab/runs',json={'scenario':'web-probes'});assert r.status_code==202
    assert entered.wait(3)
    assert c.post('/api/v1/lab/runs',json={'scenario':'web-probes'}).status_code==409
    assert c.post('/api/v1/lab/runs/'+r.json()['id']+'/stop',json={}).status_code==200
    run=finish(app,c);assert run['state']=='STOPPED';assert run['observed_count']==0;assert run['job_id'] is None


def test_lab_failure_and_input_scope(app_client,monkeypatch):
    app,c=app_client;lab=app.state.lab
    monkeypatch.setattr(lab,'available',lambda:True)
    def fail(*args):raise RuntimeError('SSH unavailable')
    lab.executor=fail
    for payload in ({'scenario':'shell'},{'scenario':[]},{'scenario':'web-probes','target':'8.8.8.8'}):
        assert c.post('/api/v1/lab/runs',json=payload).status_code==422
    assert c.post('/api/v1/lab/runs',json={'scenario':'web-probes'},headers={'x-csrf-token':'wrong'}).status_code==403
    c.post('/api/v1/lab/runs',json={'scenario':'web-probes'})
    run=finish(app,c);assert run['state']=='FAILED';assert run['observed_count']==0;assert run['job_id'] is None
    with pytest.raises(ValueError):runner_source('shell','token')


def test_lab_reviewer_cannot_run(app_client):
    app,c=app_client
    c.post('/api/v1/users',json={'username':'lab-reviewer','password':'reviewer-password-123','role':'reviewer'})
    login=c.post('/api/v1/auth/session',json={'username':'lab-reviewer','password':'reviewer-password-123'}).json()
    c.headers['x-csrf-token']=login['csrf']
    assert c.get('/api/v1/lab').status_code==403
    assert c.post('/api/v1/lab/runs',json={'scenario':'web-probes'}).status_code==403


def test_lab_seals_own_receipts_without_draining_backlog(app_client,monkeypatch):
    from cbb.crypto import uid
    app,c=app_client;lab=app.state.lab;service=app.state.service
    monkeypatch.setattr(lab,'available',lambda:True)
    backlog_id=uid()
    def sender(*args):
        local_sender(*args)
        with service.db.tx() as conn:
            original=row(conn,select(D.receipts).limit(1))
            original.update(id=backlog_id,evidence_id=uid(),boot_id=uid(),received_at='2000-01-01T00:00:00.000Z')
            conn.execute(D.receipts.insert().values(**original))
    lab.executor=sender
    assert c.post('/api/v1/lab/runs',json={'scenario':'login-failures'}).status_code==202
    run=finish(app,c)
    assert run['state']=='COMPLETE' and run['observed_count']==6
    with service.db.read() as conn:
        assert row(conn,select(D.receipts).where(D.receipts.c.id==backlog_id))['state']=='STAGED'
        assert len(conn.execute(select(D.case_evidence).where(D.case_evidence.c.case_id==run['case_id'])).all())==6


def test_recover_finalization_without_replaying_sender(app_client,monkeypatch):
    app,c=app_client;lab=app.state.lab;service=app.state.service
    monkeypatch.setattr(lab,'available',lambda:True)
    calls=[]
    def sender(*args):calls.append(1);local_sender(*args)
    lab.executor=sender
    original=service.seal_pending
    def unavailable(*args,**kwargs):raise RuntimeError('Temporary storage unavailable')
    monkeypatch.setattr(service,'seal_pending',unavailable)
    rid=c.post('/api/v1/lab/runs',json={'scenario':'web-probes'}).json()['id']
    run=finish(app,c)
    assert run['state']=='FAILED' and run['sealed_count']==0 and run['recoverable']
    monkeypatch.setattr(service,'seal_pending',original)
    c.post('/api/v1/cases/'+run['case_id']+'/notes',json={'body':'Recovery review note'}).raise_for_status()
    r=c.post('/api/v1/lab/runs/'+rid+'/recover',json={});assert r.status_code==200,r.text
    assert not r.json()['sender_replayed']
    second=c.post('/api/v1/lab/runs/'+rid+'/recover',json={})
    assert second.json()['job_id']==r.json()['job_id']
    recovered=c.get('/api/v1/lab').json()['runs'][0]
    assert recovered['state']=='PARTIAL' and recovered['sealed_count']==5 and not recovered['recoverable']
    assert len(calls)==1
    with service.db.read() as conn:
        job=row(conn,select(D.jobs).where(D.jobs.c.id==r.json()['job_id']))
    assert 'Recovery review note' in job['payload']
    assert c.post('/api/v1/lab/runs/'+rid+'/recover',json={},headers={'x-csrf-token':'bad'}).status_code==403
    c.post('/api/v1/users',json={'username':'other-admin','password':'another-admin-password-123','role':'admin'}).raise_for_status()
    login=c.post('/api/v1/auth/session',json={'username':'other-admin','password':'another-admin-password-123'}).json();c.headers['x-csrf-token']=login['csrf']
    assert c.post('/api/v1/lab/runs/'+rid+'/recover',json={}).status_code==404


def test_pipeline_health_requires_admin(app_client):
    app,c=app_client
    result=c.get('/api/v1/health/pipeline');assert result.status_code==200
    assert 'oldest_pending_at' in result.json() and 'disk_free' in result.json()
    c.post('/api/v1/users',json={'username':'health-reviewer','password':'health-reviewer-password','role':'reviewer'}).raise_for_status()
    login=c.post('/api/v1/auth/session',json={'username':'health-reviewer','password':'health-reviewer-password'}).json();c.headers['x-csrf-token']=login['csrf']
    assert c.get('/api/v1/health/pipeline').status_code==403
