"""Authenticated integration, archival and derived-analysis endpoints."""
import os
from datetime import datetime, timedelta, timezone
from importlib.metadata import version, PackageNotFoundError
from fastapi import Depends, Query
from pydantic import BaseModel, Field, ConfigDict
from typing import Literal
from sqlalchemy import select, update, and_, func
from . import db as D
from .crypto import now, dumps, loads
from .service import DomainError, row, rows
from .cloud import MegaPolicy, queue_backup, save_policy, settings
from .tooling import mega_command, tool_probe

_live_seen={}

class AnalysisRequest(BaseModel):
    model_config=ConfigDict(extra="forbid")
    case_id:str
    question:str=Field(min_length=3,max_length=2000)
    engine:Literal["local","ollama"]="local"

class ReviewRequest(BaseModel):
    decision:Literal["ACCEPTED","REJECTED","NEEDS_REVIEW"]
    reason:str=Field(min_length=3,max_length=4000)

def register_upgrade_routes(app,service,user,admin,investigator):
    @app.get('/api/v1/runtime/status')
    def runtime(u=Depends(admin)):
        from .runtime_status import host_status
        return host_status()

    @app.get('/api/v1/live/events')
    def live_events(source:str='',limit:int=Query(100,ge=1,le=200),u=Depends(user)):
        with service.db.tx() as c:
            query=select(D.evidence.c.id,D.evidence.c.sequence,D.evidence.c.source_type,D.evidence.c.event_type,D.evidence.c.received_at,D.evidence.c.occurred_at,D.evidence.c.severity,D.evidence.c.summary,D.evidence.c.envelope)
            scope=service.scope_evidence(u)
            if scope is not None:query=query.where(scope)
            if source:query=query.where(D.evidence.c.source_type==source)
            items=rows(c,query.order_by(D.evidence.c.sequence.desc()).limit(limit))
            for item in items:
                envelope=loads(item.pop('envelope'))
                item['subject']=envelope['subject']
                item['quality_flags']=envelope['quality_flags']
            # Polling must not flood the immutable custody chain: record a view
            # only when this user's visible result set actually changes.
            returned=[x['id'] for x in items];key=(u['id'],source or '')
            if _live_seen.get(key)!=returned:
                _live_seen[key]=returned
                if len(_live_seen)>1000:_live_seen.clear()
                service.audit(c,u['id'],'LIVE_EVIDENCE_VIEW','live-monitor',details={'returned_ids':returned,'source':source})
            return {'checked_at':now(),'items':items,'scope':'All evidence for investigators; assigned case evidence for other roles','window_limit':limit}

    @app.get("/api/v1/live/volume")
    def live_volume(source: str = Query("", max_length=40), u=Depends(user)):
        checked = datetime.now(timezone.utc)
        start = checked.replace(second=0, microsecond=0) - timedelta(minutes=29)
        buckets = {
            (start + timedelta(minutes=offset)).isoformat(timespec="minutes")[:16]:
                {"windows": 0, "linux": 0, "other": 0}
            for offset in range(30)
        }
        minute = func.substr(D.evidence.c.received_at, 1, 16)
        query = select(minute.label("minute"), D.evidence.c.source_type, func.count().label("count"))
        query = query.where(
            D.evidence.c.received_at >= start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            D.evidence.c.received_at <= checked.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        )
        scope = service.scope_evidence(u)
        if scope is not None:
            query = query.where(scope)
        if source:
            query = query.where(D.evidence.c.source_type == source)
        with service.db.read() as c:
            for result in rows(c, query.group_by(minute, D.evidence.c.source_type)):
                kind = result["source_type"]
                series = ("windows" if kind in {"windows.event", "windows.firewall"}
                          else "linux" if kind == "linux.journal" else "other")
                buckets[result["minute"]][series] += result["count"]
        return {
            "checked_at": checked.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "buckets": [{"minute": key + ":00Z", **values} for key, values in buckets.items()],
        }

    @app.get("/api/v1/integrations")
    def integrations(u=Depends(admin)):
        packages={}
        for name in ("scikit-learn","yara-python","watchdog","psutil","reportlab","python-docx"):
            try:packages[name]={"state":"INSTALLED","version":version(name)}
            except PackageNotFoundError:packages[name]={"state":"NOT_INSTALLED"}
        mega={"state":"NOT_INSTALLED"}
        try:
            mega={"state":"INSTALLED","version":mega_command("version",timeout=10)}
            try:mega_command("whoami",timeout=10);mega["session"]="SIGNED_IN"
            except DomainError:mega["session"]="LOGIN_REQUIRED_OR_UNAVAILABLE"
        except DomainError as ex:mega.update(state="NOT_INSTALLED" if ex.code=="MEGA_NOT_INSTALLED" else "UNAVAILABLE",detail=ex.message)
        from .runtime_status import ollama_status
        with service.db.read() as c:
            collectors=rows(c,select(D.collectors.c.id,D.collectors.c.name,D.collectors.c.last_heartbeat,D.collectors.c.state,D.collectors.c.health))
        for col in collectors:col["health"]=loads(col["health"],{})
        return {"checked_at":now(),"packages":packages,"mega":mega,"suricata":tool_probe("suricata","-V"),"zeek":tool_probe("zeek"),"ollama":ollama_status(),"collectors":collectors,"network_scope":"Server binary probes do not inspect WSL or remote collectors. EVE ingestion health is reported by each enrolled collector. WSL eth0 captures WSL-visible traffic, not all Windows traffic."}

    @app.get("/api/v1/cloud/mega/settings")
    def get_policy(u=Depends(admin)):return settings(service)

    @app.put("/api/v1/cloud/mega/settings")
    def set_mega_policy(body: MegaPolicy, u=Depends(admin)):
        return save_policy(service, body, u["id"])

    @app.post("/api/v1/cloud/mega/backup")
    def backup(u=Depends(admin)):
        return {"job_id": queue_backup(service, u["id"])}

    @app.get("/api/v1/cloud/objects")
    def objects(u=Depends(admin)):
        query = select(D.cloud_objects, D.cloud_log_retention.c.expires_at, D.cloud_log_retention.c.expired_at)
        query = query.outerjoin(D.cloud_log_retention, D.cloud_log_retention.c.object_id == D.cloud_objects.c.id)
        with service.db.read() as c:
            return rows(c, query.order_by(D.cloud_objects.c.verified_at.desc()).limit(500))

    @app.post("/api/v1/cloud/objects/{object_id}/restore-check")
    def restore_check(object_id:str,u=Depends(admin)):
        with service.db.tx() as c:
            obj=row(c,select(D.cloud_objects).where(D.cloud_objects.c.id==object_id))
            if not obj:raise DomainError("NOT_FOUND","Backup object not found",404)
            if obj["state"] == "EXPIRED":
                raise DomainError("MEGA_EXPIRED", "This MEGA log copy expired. Open the preserved local evidence.", 409)
            job=service.create_job(c,"mega-restore-check",u["id"],{"object_id":object_id,"actor_id":u["id"]})
            service.audit(c,u["id"],"MEGA_RESTORE_CHECK_REQUESTED",object_id)
        return {"job_id":job}

    @app.post("/api/v1/ai/analyses")
    def analyze(body:AnalysisRequest,u=Depends(investigator)):
        with service.db.tx() as c:
            case=service.allowed_case(c,u,body.case_id,write=True)
            query=select(D.evidence.c.id).join(D.case_evidence,D.case_evidence.c.evidence_id==D.evidence.c.id).where(and_(D.case_evidence.c.case_id==case['id'],D.case_evidence.c.active==True)).order_by(D.evidence.c.sequence.desc()).limit(300)
            ids=[r['id'] for r in rows(c,query)]
            if not ids:raise DomainError('AI_SCOPE','Add evidence to this case before requesting analysis',422)
            job=service.create_job(c,"ai-assist",u["id"],{**body.model_dump(),"actor_id":u["id"],"evidence_ids":ids,"case_version":case["version"]},case["id"])
            service.audit(c,u["id"],"AI_ANALYSIS_REQUESTED",case["id"],details={"job_id":job,"engine":body.engine,"evidence_count":len(ids)})
        return {"job_id":job}

    @app.get("/api/v1/ai/analyses")
    def analyses(case_id:str,u=Depends(user)):
        with service.db.read() as c:
            service.allowed_case(c,u,case_id)
            result=rows(c,select(D.ai_runs).where(D.ai_runs.c.case_id==case_id).order_by(D.ai_runs.c.created_at.desc()).limit(100))
        return [{**r,"document":loads(r["document"]),"review":loads(r["review"])} for r in result]

    @app.post("/api/v1/ai/analyses/{analysis_id}/review")
    def review_analysis(analysis_id:str,body:ReviewRequest,u=Depends(investigator)):
        with service.db.tx() as c:
            item=row(c,select(D.ai_runs).where(D.ai_runs.c.id==analysis_id))
            if not item:raise DomainError("NOT_FOUND","Analysis not found",404)
            service.allowed_case(c,u,item["case_id"],write=True)
            review={**body.model_dump(),"actor_id":u["id"],"at":now()}
            c.execute(update(D.ai_runs).where(D.ai_runs.c.id==analysis_id).values(review=dumps(review)))
            service.audit(c,u["id"],"AI_ANALYSIS_REVIEWED",item["case_id"],details={"analysis_id":analysis_id,**review})
        return review
