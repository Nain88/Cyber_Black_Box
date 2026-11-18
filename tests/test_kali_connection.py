import json
from types import SimpleNamespace
import pytest
from cbb.kali import connection, ssh_base, check_connection
from test_api import app_client


def write_config(tmp_path, value):
    (tmp_path/'work').mkdir(exist_ok=True)
    (tmp_path/'work/kali-connection.json').write_text(json.dumps(value))


def test_default_and_vmware_connection(tmp_path):
    assert connection(tmp_path)=={'host':'127.0.0.1','port':2222,'username':'kali'}
    write_config(tmp_path,{'host':'192.168.56.12','port':22,'username':'student'})
    args,dest=ssh_base(tmp_path)
    assert dest=='student@192.168.56.12'
    assert args[args.index('-p')+1]=='22'
    assert 'StrictHostKeyChecking=yes' in args


@pytest.mark.parametrize('value',[
    {'host':'8.8.8.8'}, {'host':'example.com'}, {'host':'169.254.169.254'},
    {'port':True}, {'port':0}, {'port':'22'}, {'username':'-oProxyCommand=x'},
    {'username':'kali;whoami'}, {'command':'whoami'}, [],
])
def test_invalid_connection_rejected(tmp_path,value):
    write_config(tmp_path,value)
    with pytest.raises((ValueError,TypeError)):connection(tmp_path)


def test_connection_check_validates_response(tmp_path,monkeypatch):
    monkeypatch.setattr('cbb.kali.subprocess.run',lambda *a,**kw:SimpleNamespace(returncode=0,stdout='{"system":"Linux","python":"3.13.1"}'))
    assert check_connection(tmp_path)['reachable']
    monkeypatch.setattr('cbb.kali.subprocess.run',lambda *a,**kw:SimpleNamespace(returncode=1,stdout=''))
    with pytest.raises(ValueError,match='SSH check failed'):check_connection(tmp_path)


def test_readiness_endpoint_auth_and_error(app_client,monkeypatch):
    app,c=app_client
    monkeypatch.setattr(app.state.lab,'available',lambda:True)
    monkeypatch.setattr('cbb.lab.subprocess.run',lambda *a,**kw:SimpleNamespace(returncode=0,stdout='linux'))
    assert c.post('/api/v1/lab/check',json={}).json()['reachable']
    assert c.post('/api/v1/lab/check',json={},headers={'x-csrf-token':'wrong'}).status_code==403
    monkeypatch.setattr(app.state.lab,'available',lambda:False)
    assert c.post('/api/v1/lab/check',json={}).status_code==422
