"""Local operator configuration for a pinned Kali SSH connection."""
import ipaddress
import json
import re
import subprocess
from pathlib import Path


def connection(root):
    path = Path(root) / 'work/kali-connection.json'
    value = json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {}
    if not isinstance(value, dict) or set(value) - {'host', 'port', 'username'}:
        raise ValueError('Kali configuration accepts only host, port and username')
    config = {'host': '127.0.0.1', 'port': 2222, 'username': 'kali', **value}
    address = ipaddress.IPv4Address(config['host'])
    private_ranges = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8')
    if not any(address in ipaddress.IPv4Network(net) for net in private_ranges):
        raise ValueError('Kali host must be a private or loopback IPv4 address')
    if type(config['port']) is not int or not 1 <= config['port'] <= 65535:
        raise ValueError('Kali SSH port must be an integer from 1 to 65535')
    if not isinstance(config['username'], str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', config['username']):
        raise ValueError('Invalid Kali SSH username')
    return config


def ssh_base(root):
    config = connection(root)
    return ['ssh', '-T', '-i', str(Path(root)/'work/kali-ssh'), '-p', str(config['port']),
            '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile='+str(Path(root)/'work/kali-known-hosts'),
            '-o', 'ExitOnForwardFailure=yes', '-o', 'ConnectTimeout=8',
            '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2'], config['username']+'@'+config['host']


def check_connection(root):
    base, destination = ssh_base(root)
    script = 'import json,platform; print(json.dumps({"system":platform.system(),"python":platform.python_version()}))'
    result = subprocess.run(base+[destination, 'python3', '-'], input=script,
                            text=True, capture_output=True, timeout=20,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise ValueError('SSH check failed. Check the running VM, SSH service, key permissions and pinned host entry.')
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict) or payload.get('system') != 'Linux':
        raise ValueError('The simulation sender must run Linux with Python 3')
    return {'reachable': True, 'system': 'Linux', 'python': str(payload.get('python', ''))[:32],
            'note': 'SSH and Python checked; simulation forwarding is verified when a run starts.'}


if __name__ == '__main__':
    print(json.dumps(connection(Path(__file__).resolve().parents[1])))
