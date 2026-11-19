"""Isolate build and acceptance fixtures from an operator's live deployment.

Only use this helper during single-threaded script setup, before workers start.
"""
import os
from pathlib import Path
from cbb.config import Settings


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if not key.upper().startswith("CBB_")}


def isolated_settings(data: Path, **overrides):
    saved = {key: value for key, value in os.environ.items()
             if key.upper().startswith("CBB_")}
    try:
        for key in saved:
            os.environ.pop(key, None)
        return Settings(data=data, **overrides)
    finally:
        os.environ.update(saved)
