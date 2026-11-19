"""Build/test tools must not initialize a live operator database."""
from pathlib import Path
import os
import sqlite3
import pytest
from scripts._isolated_runtime import clean_environment, isolated_settings
from cbb.service import Service


def test_script_fixture_ignores_live_deployment_environment(tmp_path, monkeypatch):
    live_db = tmp_path / "live.sqlite3"
    with sqlite3.connect(live_db) as conn:
        conn.execute("CREATE TABLE sentinel (value TEXT)")
        conn.execute("INSERT INTO sentinel VALUES ('preserve me')")
    original = live_db.read_bytes()
    live_settings = {
        "CBB_DATA": str(tmp_path / "live-data"),
        "CBB_DATABASE_URL": "sqlite:///" + live_db.as_posix(),
        "CBB_MODE": "cloud",
        "CBB_SIGNER_URL": "http://127.0.0.1:1/must-not-contact",
        "CBB_WITNESS_URL": "http://127.0.0.1:1/must-not-contact",
        "CBB_PUBLIC_URL": "https://live.invalid",
        "CBB_SECURE_COOKIES": "true",
        "CBB_REQUIRE_MTLS": "true",
    }
    for key, value in live_settings.items():
        monkeypatch.setenv(key, value)
    settings = isolated_settings(tmp_path / "fixture", workers=False)
    service = Service(settings)
    try:
        assert settings.mode == "virtual"
        assert not settings.signer_url and not settings.witness_url
        assert settings.public_url == "http://127.0.0.1:8765"
        assert not settings.secure_cookies and not settings.require_mtls
        assert (tmp_path / "fixture/cbb.sqlite3").is_file()
        assert live_db.read_bytes() == original
        assert not (tmp_path / "live-data").exists()
        assert all(os.environ[key] == value for key, value in live_settings.items())
        assert not any(key.upper().startswith("CBB_") for key in clean_environment())
    finally:
        service.db.engine.dispose()


def test_isolated_settings_restores_environment_after_error(tmp_path, monkeypatch):
    monkeypatch.setenv("CBB_DATABASE_URL", "sqlite:///unchanged.sqlite3")
    with pytest.raises(TypeError):
        isolated_settings(tmp_path, unknown_setting=True)
    assert os.environ["CBB_DATABASE_URL"] == "sqlite:///unchanged.sqlite3"
