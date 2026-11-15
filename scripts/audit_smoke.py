import json, os, re, socket, subprocess, sys, tempfile, time
from pathlib import Path
import httpx
root=Path(__file__).resolve().parents[1]
os.chdir(root)
(root/'work').mkdir(exist_ok=True)
sys.path.insert(0,str(root))
from cbb.config import Settings
from cbb.service import Service
from cbb.cli import seed_demo
from cbb.verify import verify_package
with tempfile.TemporaryDirectory(prefix='cbb-acceptance-') as tmp:
 data=Path(tmp)/'data'
 service=Service(Settings(data=data,workers=False))
 login=seed_demo(service); public_key=service.deployment['public_key']; service.db.engine.dispose()
 with socket.socket() as sock:
  sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
 base=f'http://127.0.0.1:{port}'
 env={k:v for k,v in os.environ.items() if not k.startswith('CBB_')};env['CBB_PUBLIC_URL']=base
 with open(root/'work/acceptance-server.log','w') as log:
  process=subprocess.Popen([sys.executable,'-m','cbb.cli','--data',str(data),'serve','--port',str(port)],env=env,stdout=log,stderr=log)
  try:
   with httpx.Client(base_url=base,timeout=30,trust_env=False) as client:
    for attempt in range(100):
     try:
      if client.get('/health/ready').status_code==200:break
     except httpx.TransportError:pass
     if process.poll() is not None:raise RuntimeError('Server exited; see acceptance log')
     time.sleep(.2)
    else:raise RuntimeError('Server readiness timeout')
    page=client.get('/');page.raise_for_status()
    assets=re.findall(r'(?:src|href)="(/assets/[^\"]+)"',page.text)
    assert assets,'Compiled GUI assets missing'
    for asset in assets:client.get(asset).raise_for_status()
    response=client.post('/api/v1/auth/session',json={k:login[k] for k in ('username','password')});response.raise_for_status()
    client.headers['x-csrf-token']=response.json()['csrf']
    checked=[]
    for route in ('overview','cases','evidence','alerts','incidents','collectors','checkpoints','custody','jobs','exports','verification-runs'):
     response=client.get('/api/v1/'+route);response.raise_for_status();checked.append(route)
    response=client.post('/api/v1/exports',json={'case_id':login['case_id']});response.raise_for_status();jid=response.json()['job_id']
    deadline=time.monotonic()+90
    while time.monotonic()<deadline:
     jobs=client.get('/api/v1/jobs').json();job=next(j for j in jobs if j['id']==jid)
     if job['state']=='COMPLETE':break
     if job['state']=='FAILED':raise RuntimeError(str(job['error']))
     time.sleep(.5)
    else:raise RuntimeError('Export timeout')
    package=client.get('/api/v1/exports/'+job['result']['export_id']+'/download');package.raise_for_status()
    path=Path(tmp)/'case.zip';path.write_bytes(package.content)
    verified=verify_package(path,public_key);assert verified['status']=='VALID',verified
  finally:
   process.terminate();process.wait(timeout=15)
 backup=Path(tmp)/'backup';restored=Path(tmp)/'restored'
 for arguments in (['--data',str(data),'backup',str(backup)],['--data',str(restored),'restore',str(backup)]):
  output=subprocess.run([sys.executable,'-m','cbb.cli',*arguments],env=env,capture_output=True,text=True,timeout=90)
  assert output.returncode==0,output.stderr
 result={'status':'PASS','http_routes':checked,'compiled_assets':len(assets),'background_export':'VALID','offline_backup_restore':'PASS','data':'isolated synthetic fixtures only'}
 (root/'work/acceptance-result.json').write_text(json.dumps(result,indent=2))
 print(json.dumps(result,indent=2))
