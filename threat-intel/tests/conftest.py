"""Shared test fixtures and helpers. No network access anywhere in this suite."""
import importlib.util
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
PARSERS_DIR = PROJECT_ROOT / "parsers"


def _load_module(name: str, filename: str):
    """Load a hyphenated script (fetch-urlhaus.py) as an importable module."""
    path = PROJECT_ROOT / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def urlhaus_mod():
    return _load_module("fetch_urlhaus", "fetch-urlhaus.py")


@pytest.fixture(scope="session")
def feodo_mod():
    return _load_module("fetch_feodo", "fetch-feodo.py")
