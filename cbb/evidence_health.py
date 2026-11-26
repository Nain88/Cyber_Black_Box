"""Read-only current evidence pipeline health."""
from datetime import datetime, timezone

from sqlalchemy import func, select

from . import db as D
from .crypto import loads
from .service import rows


def _age(value, current):
    try:
        if not value:
            return None
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return max(0, int((current - stamp).total_seconds()))
    except (ValueError, TypeError, AttributeError, OverflowError):
        return None


def evidence_health(connection, delay_seconds, current=None):
    current = current or datetime.now(timezone.utc)
    staged = connection.scalar(select(func.count()).select_from(D.receipts).where(D.receipts.c.state == "STAGED"))
    last_sealed = connection.scalar(select(D.evidence.c.received_at).order_by(D.evidence.c.sequence.desc()).limit(1))
    pending, oldest = connection.execute(
        select(func.count(), func.min(D.jobs.c.created_at))
        .where(D.jobs.c.kind == "analyze", D.jobs.c.state.in_(("QUEUED", "RUNNING")))
    ).one()
    age = _age(oldest, current)
    issues = []
    if age is not None and age >= delay_seconds:
        issues.append({"id": "analysis-delay", "issue": "Analysis delayed", "scope": "Background jobs",
                       "detail": f"Oldest pending analysis job is {age} seconds old."})
    collectors = rows(connection, select(D.collectors.c.id, D.collectors.c.name, D.collectors.c.last_heartbeat,
                                        D.collectors.c.health).where(D.collectors.c.state == "ACTIVE",
                                                                     D.collectors.c.last_heartbeat.is_not(None)))
    for collector in collectors:
        age = _age(collector["last_heartbeat"], current)
        if age is None or age >= 90:
            issues.append({"id": collector["id"] + ":heartbeat", "issue": "Collector heartbeat stale",
                           "scope": collector["name"], "detail": "A recent valid heartbeat is unavailable."})
            continue
        try:
            health = loads(collector["health"], {})
        except (ValueError, TypeError):
            continue
        if not isinstance(health, dict):
            continue
        failed_inputs = 0
        for key in ("firewall_inputs", "network_inputs", "zeek_inputs"):
            inputs = health.get(key)
            if isinstance(inputs, list):
                failed_inputs += sum(isinstance(item, dict) and item.get("state") in
                                     ("MISSING", "UNREADABLE_OR_INVALID_STATUS") for item in inputs)
        errors = health.get("errors")
        if failed_inputs or (isinstance(errors, (dict, list)) and errors):
            issues.append({"id": collector["id"] + ":sources", "issue": "Collector reported errors",
                           "scope": collector["name"], "detail": "Review this collector’s reported inputs and errors."})
    return {"staged_receipts": staged, "last_sealed_received_at": last_sealed, "pending_analysis": pending,
            "oldest_analysis_at": oldest, "analysis_delayed": any(issue["id"] == "analysis-delay" for issue in issues),
            "analysis_delay_seconds": delay_seconds, "issues": issues}
