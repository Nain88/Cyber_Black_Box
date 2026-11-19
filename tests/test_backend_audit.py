"""Regression coverage for Windows event discovery and queue indexing."""
import base64
import json
import time

import pytest
from sqlalchemy import select, text

from cbb import db as D
from cbb.config import Settings
from cbb.crypto import now, sha, uid
from cbb.schema import normalize
from cbb.service import Service, row


def windows_wire(provider="CloudBoxTest", event_id="100", body="<EventData><Data>CBB-CHECK-002: Windows collection test</Data></EventData>"):
    raw = (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="{provider}"/><EventID>{event_id}</EventID><TimeCreated SystemTime="2026-11-18T16:45:00Z"/></System>{body}</Event>').encode()
    return {"boot_id":"windows-test", "source_seq":"1", "source_type":"windows.event", "event_type":"windows.event", "collected_at":now(), "raw_media_type":"application/xml", "raw_base64":base64.b64encode(raw).decode(), "raw_sha256":sha(raw)}, raw


@pytest.mark.parametrize("body", [
    "<EventData><Data>CBB-CHECK-002: Windows collection test</Data></EventData>",
    '<EventData><Data Name="Message">CBB-CHECK-002: Windows collection test</Data></EventData>',
    "<RenderingInfo><Message>CBB-CHECK-002: Windows collection test</Message></RenderingInfo>",
])
def test_windows_messages_are_searchable_and_original_bytes_unchanged(tmp_path, body):
    service = Service(Settings(data=tmp_path, workers=False))
    try:
        with service.db.tx() as c:
            c.execute(D.enrollments.insert().values(id=uid(), token_hash=sha(b"enroll"), name="Windows", os="windows", expires=time.time()+60, used=False))
        credentials = service.enroll("enroll")
        with service.db.read() as c:
            collector = row(c, select(D.collectors).where(D.collectors.c.id == credentials["collector_id"]))
        wire, original = windows_wire(body=body)
        accepted = service.accept(collector, [wire])[0]
        service.seal_pending()
        with service.db.read() as c:
            result = row(c, select(D.evidence).where(D.evidence.c.summary.contains("CBB-CHECK-002", autoescape=True)))
            assert result and result["id"] == accepted["evidence_id"]
            assert service.read_raw(c, result) == original
            assert json.loads(result["envelope"])["parser"]["version"] == "1.1.0"
        service.checkpoint()
        assert service.verify()["status"] == "VALID"
    finally:
        service.db.engine.dispose()


@pytest.mark.parametrize("provider,event_id,expected", [
    ("CloudBoxTest", "104", "windows.event"),
    ("CloudBoxTest", "1102", "windows.event"),
    ("CloudBoxTest", "4688", "windows.event"),
    ("Custom-Sysmon-Lookalike", "1", "windows.event"),
    ("Microsoft-Windows-Eventlog", "104", "log.clear"),
    ("Microsoft-Windows-Eventlog", "1102", "log.clear"),
    ("Microsoft-Windows-Security-Auditing", "4688", "process.create"),
    ("Microsoft-Windows-Sysmon", "1", "process.create"),
])
def test_windows_event_ids_are_scoped_to_their_provider(provider, event_id, expected):
    wire, _ = windows_wire(provider, event_id, "")
    result = normalize(wire, {"id":"collector", "asset_id":"asset"}, "evidence", now(), {})
    assert result["event_type"] == expected


def test_indexes_upgrade_existing_database_and_avoid_queue_scan(tmp_path):
    url = "sqlite:///" + str(tmp_path / "existing.sqlite3").replace("\\", "/")
    first = D.Database(url)
    with first.tx() as c:
        c.execute(D.jobs.insert().values(id="pending", kind="analyze", state="QUEUED", created_at=now(), next_attempt=0, payload="{}"))
        # Model a database created by the previous version, without the new indexes.
        for name in [r[0] for r in c.execute(text("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'ix_cbb_%'"))]:
            c.exec_driver_sql('DROP INDEX "' + name + '"')
    first.engine.dispose()
    upgraded = D.Database(url)
    try:
        with upgraded.read() as c:
            assert c.execute(select(D.jobs.c.id)).scalar() == "pending"
            plan = " ".join(r[3] for r in c.exec_driver_sql("EXPLAIN QUERY PLAN SELECT id FROM jobs WHERE state='QUEUED' AND kind='analyze' AND next_attempt<=100 ORDER BY created_at LIMIT 1"))
            assert "ix_cbb_jobs_lane" in plan and "SCAN jobs" not in plan
            receipts_plan = " ".join(r[3] for r in c.exec_driver_sql("EXPLAIN QUERY PLAN SELECT id FROM receipts WHERE state='STAGED' ORDER BY received_at LIMIT 100"))
            assert "ix_cbb_receipts_pending" in receipts_plan
            assert c.exec_driver_sql("PRAGMA synchronous").scalar() == 2
            assert c.exec_driver_sql("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'immutable_%'").scalar() == 8
    finally:
        upgraded.engine.dispose()
