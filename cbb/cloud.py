"""One-way, hash-verified MEGA archival. Never mirrors local deletions."""
import gzip
import os
import re
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, and_, update
from . import db as D
from .crypto import now,uid,file_sha,canon,sha,loads,dumps,atomic_write
from .service import DomainError,row,rows
from .tooling import mega_command

DEFAULTS={"enabled":False,"automatic":False,"interval_minutes":15,"remote_root":"/CyberBlackBox","expire_logs":False}
LOG_SUFFIXES = {"segment": ".jsonl", "manifest": ".manifest.json"}


class MegaPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    enabled: bool = False
    automatic: bool = False
    interval_minutes: int = Field(default=15, ge=5, le=1440)
    remote_root: str = Field(default="/CyberBlackBox", max_length=180)
    expire_logs: bool = False


def save_policy(service, policy, actor):
    if not re.fullmatch(r"/[A-Za-z0-9_/-]{1,179}", policy.remote_root) or ".." in policy.remote_root:
        raise DomainError("MEGA_PATH", "Use an absolute folder with letters, digits, slash, dash or underscore", 422)
    if policy.automatic and not policy.enabled:
        raise DomainError("MEGA_DISABLED", "Enable backup before automatic scheduling", 422)
    if policy.expire_logs and not policy.enabled:
        raise DomainError("MEGA_DISABLED", "Enable MEGA backup before log expiry", 422)
    if policy.expire_logs and not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)+", policy.remote_root.rstrip("/")):
        raise DomainError("MEGA_PATH", "Log expiry requires a folder with a single slash between names", 422)
    document = policy.model_dump()
    with service.db.tx() as c:
        old = row(c, select(D.config).where(D.config.c.id == "mega-policy"))
        values = {"value": dumps(document), "version": old["version"] + 1 if old else 1, "updated_at": now()}
        if old:
            c.execute(update(D.config).where(D.config.c.id == "mega-policy").values(**values))
        else:
            c.execute(D.config.insert().values(id="mega-policy", **values))
        service.audit(c, actor, "MEGA_POLICY_UPDATED", "mega-policy", details=document)
    return document


def queue_backup(service, actor):
    if not settings(service)["enabled"]:
        raise DomainError("MEGA_DISABLED", "Enable MEGA in backup settings first", 422)
    with service.db.tx() as c:
        job = row(c, select(D.jobs).where(
            D.jobs.c.kind == "mega-backup", D.jobs.c.state.in_(["QUEUED", "RUNNING"]),
        ))
        if job:
            return job["id"]
        job_id = service.create_job(c, "mega-backup", actor, {"actor_id": actor})
        service.audit(c, actor, "MEGA_BACKUP_REQUESTED", job_id)
        return job_id


def mega_file_handle(remote_path):
    """Identify one exact file. Directory listings and ambiguous names fail closed."""
    name = remote_path.rsplit("/", 1)[-1]
    try:
        output = mega_command("ls", "-l", "--show-handles", remote_path, timeout=15)
    except DomainError as exc:
        if exc.code == "MEGA_NOT_FOUND":
            return None
        raise
    matches = re.findall(
        rf"^-[^\s]{{3}}\s+\d+\s+\d+\s+[^\n]*?\b(H:[A-Za-z0-9_-]{{8}})\s+{re.escape(name)}\s*$",
        output, re.MULTILINE,
    )
    if len(matches) != 1:
        raise DomainError("MEGA_FILE_IDENTITY", "Could not identify one exact MEGA archive file.", 503)
    return matches[0]


def held_segment_query():
    return select(D.evidence.c.segment_id).join(
        D.case_evidence, D.case_evidence.c.evidence_id == D.evidence.c.id,
    ).join(D.cases, D.cases.c.id == D.case_evidence.c.case_id).where(
        D.case_evidence.c.active.is_(True), D.cases.c.hold.is_(True),
    )


def due_logs(cutoff):
    return select(D.cloud_objects, D.cloud_log_retention.c.remote_handle, D.cloud_log_retention.c.expires_at).join(
        D.cloud_log_retention, D.cloud_log_retention.c.object_id == D.cloud_objects.c.id,
    ).where(
        D.cloud_objects.c.provider == "mega", D.cloud_objects.c.state == "VERIFIED",
        D.cloud_objects.c.source_kind.in_(tuple(LOG_SUFFIXES)),
        D.cloud_log_retention.c.expires_at <= cutoff, D.cloud_log_retention.c.expired_at.is_(None),
        ~held_segment_query().where(D.evidence.c.segment_id == D.cloud_objects.c.source_id).exists(),
    )


def expire_mega_logs(service, payload):
    """Move tracked log copies to the MEGA Rubbish Bin. Leave local evidence intact."""
    policy = settings(service)
    if not (policy["enabled"] and policy["expire_logs"]):
        return {"expired": 0, "skipped": 0}
    with service.db.read() as c:
        pending = rows(c, due_logs(now()).order_by(D.cloud_log_retention.c.expires_at).limit(10))
    if pending:
        mega_command("whoami", timeout=15)
    expired = skipped = 0
    deployment = service.deployment["id"]
    for item in pending:
        policy = settings(service)
        if not (policy["enabled"] and policy["expire_logs"]):
            break
        name = item["source_id"] + LOG_SUFFIXES[item["source_kind"]]
        suffix = f"/{deployment}/objects/{item['sha256']}/{name}"
        remote_path = item["remote_path"]
        local = service.root / "archive" / name
        if (not re.fullmatch(r"[a-f0-9-]{36}", item["source_id"])
                or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
                or not remote_path.endswith(suffix)
                or not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)+", remote_path[:-len(suffix)])
                or item["local_path"] != "archive/" + name
                or not local.is_file() or file_sha(local) != item["sha256"]):
            raise DomainError("MEGA_EXPIRY_GUARD", "Cloud expiry blocked. Inspect the preserved file and backup inventory.", 409)
        handle = item["remote_handle"]
        if not re.fullmatch(r"H:[A-Za-z0-9_-]{8}", handle):
            raise DomainError("MEGA_EXPIRY_GUARD", "Cloud expiry blocked because the file identity is invalid.", 409)
        trash_dir = f"//bin/CBB-{deployment}-expired/{item['sha256']}"
        trash_path = trash_dir + "/" + name
        active_handle = mega_file_handle(remote_path)
        if active_handle != handle and (active_handle is not None or mega_file_handle(trash_path) != handle):
            with service.db.tx() as c:
                c.execute(update(D.cloud_objects).where(D.cloud_objects.c.id == item["id"]).values(state="MISMATCH"))
                service.audit(c, payload["actor_id"], "MEGA_EXPIRY_SKIPPED", item["id"], result="FAILED",
                              details={"reason": "The expected remote file identity was not found."})
            skipped += 1
            continue
        if active_handle == handle:
            mega_command("mkdir", "-p", trash_dir, timeout=15)
            with service.db.read() as c:
                eligible = row(c, due_logs(now()).where(D.cloud_objects.c.id == item["id"]))
            policy = settings(service)
            if not eligible or not (policy["enabled"] and policy["expire_logs"]):
                continue
            mega_command("mv", handle, trash_dir + "/", timeout=20)
            if mega_file_handle(trash_path) != handle:
                raise DomainError("MEGA_EXPIRY_UNCONFIRMED", "MEGA did not confirm the file in the Rubbish Bin.", 503)
        with service.db.tx() as c:
            c.execute(update(D.cloud_objects).where(D.cloud_objects.c.id == item["id"]).values(state="EXPIRED"))
            c.execute(update(D.cloud_log_retention).where(D.cloud_log_retention.c.object_id == item["id"]).values(expired_at=now()))
            service.audit(c, payload["actor_id"], "MEGA_LOG_EXPIRED", item["id"],
                          details={"sha256": item["sha256"], "remote_path": remote_path, "destination": trash_path})
        expired += 1
    return {"expired": expired, "skipped": skipped}

def restore_check(service,payload):
    """Download to a new staging folder; never replace preserved originals."""
    with service.db.read() as c:obj=row(c,select(D.cloud_objects).where(D.cloud_objects.c.id==payload["object_id"]))
    if not obj:raise DomainError("NOT_FOUND","Backup object not found",404)
    if obj["state"] == "EXPIRED":
        raise DomainError("MEGA_EXPIRED", "This MEGA log copy expired. Open the preserved local evidence.", 409)
    if obj["size"]>__import__('shutil').disk_usage(service.root).free-50*1024**2:raise DomainError("VERIFY_CAPACITY","Insufficient free space for restore verification",503)
    target=service.root/"restore-staging"/uid();target.mkdir(parents=True)
    mega_command("get",obj["remote_path"],str(target)+os.sep)
    downloaded=target/Path(obj["local_path"]).name
    matched=downloaded.is_file() and file_sha(downloaded)==obj["sha256"]
    with service.db.tx() as c:
        c.execute(update(D.cloud_objects).where(D.cloud_objects.c.id==obj["id"]).values(state="VERIFIED" if matched else "MISMATCH",verified_at=now()))
        service.audit(c,payload["actor_id"],"MEGA_RESTORE_CHECK",obj["source_id"],result="SUCCESS" if matched else "FAILED",details={"object_id":obj["id"],"expected_sha256":obj["sha256"],"staging_path":str(target.relative_to(service.root))})
    if not matched:raise DomainError("REMOTE_HASH_MISMATCH","Restore bytes do not match preserved digest; staged output is untrusted",409)
    return {"verified":True,"sha256":obj["sha256"],"staging_path":str(downloaded.relative_to(service.root)),"originals_replaced":False}

def settings(service):
    with service.db.read() as c:r=row(c,select(D.config).where(D.config.c.id=="mega-policy"))
    return {**DEFAULTS,**(loads(r["value"]) if r else {})}

def candidates(service):
    result=[]
    with service.db.read() as c:
        for s in rows(c,select(D.segments).where(D.segments.c.closed==True)):
            result.extend([("segment",s["id"],s["path"],s["sha256"]),("manifest",s["id"],str(Path(s["path"]).with_suffix(".manifest.json")).replace("\\","/"),None)])
        for a in rows(c,select(D.artifacts)):result.append(("artifact",a["id"],a["path"],a["sha256"]))
        for a in rows(c,select(D.exports)):result.append(("report-package",a["id"],a["path"],a["sha256"]))
        for a in rows(c,select(D.checkpoints)):result.append(("checkpoint",a["id"],"checkpoints/"+a["id"]+".json",a["sha256"]))
    return result

def replicate_mega(service,payload):
    policy=settings(service)
    if not policy["enabled"]:raise DomainError("MEGA_DISABLED","Enable MEGA backup after signing in to official MEGAcmd",422)
    remote=policy["remote_root"]
    if not re.fullmatch(r"/[A-Za-z0-9_/-]{1,180}",remote) or ".." in remote:raise DomainError("MEGA_PATH","Use an absolute MEGA folder containing letters, digits, slash, dash or underscore",422)
    mega_command("whoami",timeout=15)
    service.checkpoint(payload.get("actor_id","system"))
    verification=service.verify()
    if verification["status"]=="INVALID":raise DomainError("INTEGRITY_FAILED","Cloud upload blocked because archive verification failed",409)
    prefix=remote.rstrip("/")+"/"+service.deployment["id"]
    count=0;already=0;expired=0
    items=candidates(service)
    # Freeze custody and descriptive metadata without copying live database or secrets.
    with service.db.read() as c:
        custody=[{"sequence":str(r["sequence"]),"envelope":loads(r["envelope"]),"entry_hash":r["entry_hash"],"previous_hash":r["previous_hash"]} for r in rows(c,select(D.custody).order_by(D.custody.c.sequence))]
        metadata={"schema":"cbb.archive-metadata/1","deployment":service.deployment,"cases":rows(c,select(D.cases)),"case_members":rows(c,select(D.case_members)),"case_evidence":rows(c,select(D.case_evidence)),"notes":rows(c,select(D.notes)),"custody":custody,"witness_receipts":rows(c,select(D.witness_receipts)),"ai_runs":rows(c,select(D.ai_runs)),"assets":rows(c,select(D.assets)),"created_at":now()}
    snapshot_id = uid()
    snapshot = service.root / "cloud-snapshots" / (snapshot_id + ".json.gz")
    atomic_write(snapshot, gzip.compress(canon(metadata), compresslevel=3, mtime=0))
    items.append(("metadata-snapshot", snapshot_id, snapshot.relative_to(service.root).as_posix(), file_sha(snapshot)))
    for kind,source_id,relative,expected in items:
        path=(service.root/relative).resolve()
        if not path.is_relative_to(service.root.resolve()) or not path.is_file():raise DomainError("ARCHIVE_PATH","Archive object is unavailable",409)
        digest=file_sha(path)
        if expected and digest!=expected:raise DomainError("OBJECT_MODIFIED","Object changed before cloud backup",409)
        with service.db.read() as c:
            old = row(c, select(D.cloud_objects, D.cloud_log_retention.c.remote_handle).outerjoin(
                D.cloud_log_retention, D.cloud_log_retention.c.object_id == D.cloud_objects.c.id,
            ).where(and_(D.cloud_objects.c.provider=="mega",D.cloud_objects.c.local_path==relative,D.cloud_objects.c.sha256==digest)))
        if old and old["state"]=="VERIFIED":already+=1;continue
        if old and old["state"]=="EXPIRED":expired+=1;continue
        # Content-addressed remote names do not overwrite a prior different version.
        folder=prefix+"/objects/"+digest
        destination=folder+"/"+path.name
        mega_command("mkdir","-p",folder)
        mega_command("put",str(path),folder+"/")
        tracked = kind in LOG_SUFFIXES and ((old and old["remote_handle"]) or (not old and policy["expire_logs"]))
        handle = mega_file_handle(destination) if tracked else None
        if tracked and not handle:
            raise DomainError("MEGA_FILE_IDENTITY", "Uploaded log has no verifiable MEGA file identity.", 503)
        if file_sha(path)!=digest:raise DomainError("UPLOAD_RACE","Local object changed while uploading; no verified backup recorded",409)
        if path.stat().st_size>__import__('shutil').disk_usage(service.root).free-50*1024**2:raise DomainError("VERIFY_CAPACITY","Need free local space to read back and verify the remote object",503)
        with tempfile.TemporaryDirectory(prefix="mega-readback-",dir=service.root) as temp:
            mega_command("get",destination,temp+os.sep)
            downloaded=Path(temp)/path.name
            if not downloaded.is_file() or file_sha(downloaded)!=digest:raise DomainError("REMOTE_HASH_MISMATCH","MEGA readback did not match local evidence",409)
        if handle and mega_file_handle(destination) != handle:
            raise DomainError("MEGA_FILE_IDENTITY", "MEGA file identity changed during readback.", 503)
        with service.db.tx() as c:
            verified = now()
            object_id = old["id"] if old else uid()
            values={"provider":"mega","source_kind":kind,"source_id":source_id,"local_path":relative,"remote_path":destination,"sha256":digest,"size":path.stat().st_size,"state":"VERIFIED","verified_at":verified}
            if old:c.execute(update(D.cloud_objects).where(D.cloud_objects.c.id==object_id).values(**values))
            else:c.execute(D.cloud_objects.insert().values(id=object_id,created_at=verified,**values))
            if handle:
                deadline = datetime.fromisoformat(verified) + timedelta(days=5)
                retention = {"remote_handle": handle, "expires_at": deadline.isoformat(timespec="milliseconds").replace("+00:00", "Z")}
                if old:
                    c.execute(update(D.cloud_log_retention).where(D.cloud_log_retention.c.object_id == object_id).values(**retention))
                else:
                    c.execute(D.cloud_log_retention.insert().values(object_id=object_id, **retention))
            service.audit(c,payload.get("actor_id","system"),"MEGA_OBJECT_VERIFIED",source_id,details={"kind":kind,"sha256":digest,"remote_path":destination})
        count+=1
    with service.db.read() as c:inventory=rows(c,select(D.cloud_objects).where(D.cloud_objects.c.provider=="mega"))
    manifest={"schema":"cbb.cloud-inventory/1","deployment_id":service.deployment["id"],"snapshot_id":snapshot_id,"created_at":now(),"objects":inventory,"protection":"Verified backup; not WORM or an independent witness","excludes":["private signing keys","user credentials","collector credentials","live database"]}
    signed=service.signed("CBB-EXPORT-v1",manifest)
    manifest_path=service.root/"cloud-snapshots"/(snapshot_id+".inventory.json");atomic_write(manifest_path,canon(signed))
    mega_command("mkdir","-p",prefix+"/inventories")
    mega_command("put",str(manifest_path),prefix+"/inventories/")
    with tempfile.TemporaryDirectory(prefix="mega-inventory-",dir=service.root) as temp:
        mega_command("get",prefix+"/inventories/"+manifest_path.name,temp+os.sep)
        if file_sha(Path(temp)/manifest_path.name)!=file_sha(manifest_path):raise DomainError("INVENTORY_MISMATCH","Cloud inventory readback failed",409)
    return {"uploaded_and_verified":count,"previously_verified":already,"expired_not_reuploaded":expired,"inventory_remote_path":prefix+"/inventories/"+manifest_path.name,"protection":"VERIFIED_BACKUP_NOT_WORM","includes":"closed segments, manifests, artifacts, reports, checkpoints and metadata/custody snapshot","database_restore":"Use separate consistent database/key backup for full application recovery"}
