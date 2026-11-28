import pytest


class _OfflineASN:
    def __init__(self, *a, **kw):
        pass

    async def lookup(self, ip):
        return {}


@pytest.fixture(autouse=True)
def offline_asn(monkeypatch):
    """Tests must never hit the real Team Cymru DNS service."""
    monkeypatch.setattr("ipscope.engine.ASNResolver", _OfflineASN)
