"""Build the source release without local data, credentials or environments."""
from pathlib import Path
import hashlib
import zipfile
import json
import sys
import os
import subprocess
root=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(root))
from cbb.schema import WireEvent
from cbb.config import Settings
from cbb.api import create_app
docs=root/'docs'
(docs/'ingest.schema.json').write_text(json.dumps(WireEvent.model_json_schema(),indent=2),encoding='utf-8')
app=create_app(Settings(data=root/'work/schema-data',workers=False))
(docs/'openapi.json').write_text(json.dumps(app.openapi(),indent=2),encoding='utf-8')
app.state.service.db.engine.dispose()
out=root/'release';out.mkdir(exist_ok=True)
target=out/'Cyber-Black-Box-Complete-Project.zip'
# Only version-controlled source belongs in a release. This excludes local lab
# credentials, evidence, virtual environments and the pnpm directory junction.
tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode('utf-8').split('\0')
selected = {root / name for name in tracked if name and not name.startswith('.pnpm-store/')}
# Generated API schemas and the compiled interface are intentional additions.
selected.update({docs/'ingest.schema.json', docs/'openapi.json', docs/'RELEASE-ACCEPTANCE-2026-11-12.md', root/'scripts/audit_smoke.py', root/'scripts/start-kali-bridge.ps1', root/'Start-Kali-Log-Bridge.cmd', docs/'KALI-LOG-CONNECTION.md'})
selected.update(path for path in (root/'web/dist').rglob('*') if path.is_file())
selected.update({root/'cbb/lab.py', root/'tests/test_lab_workflow.py', docs/'FYP-PRESENTATION.md'})
selected.update({root/'cbb/kali.py', root/'tests/test_kali_connection.py', docs/'KALI-PRESENTATION-2026-11-14.md'})
if not (root/'web/dist/index.html').is_file():
    raise RuntimeError('Build the interface before packaging: pnpm --dir web build')
selected.update({root/'Setup-Docker-Lab.cmd', root/'Setup-Windows-Collector.cmd', root/'web/src/guide.tsx', docs/'DOCKER-LAB.md'})
count=0
with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as z:
    for path in sorted(selected):
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root):
            continue
        rel=path.relative_to(root)
        if any(part in {'node_modules', '__pycache__', '.pytest_cache', '.git', '.lab-state'} for part in rel.parts):
            continue
        if path.name == '.env' or (path.name.startswith('.env.') and path.name != '.env.example'):
            continue
        if path.suffix in {'.pyc', '.tsbuildinfo'}:
            continue
        z.write(path,'Cyber-Black-Box/'+rel.as_posix());count+=1
digest=hashlib.sha256(target.read_bytes()).hexdigest()
(out/'SHA256SUMS.txt').write_text(digest+'  '+target.name+'\n')
print(json.dumps({'file':str(target),'files':count,'bytes':target.stat().st_size,'sha256':digest},indent=2))
