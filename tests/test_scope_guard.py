"""
Unit Tests for Scope Guard
Proves that non-localhost targets are blocked (fail closed), while localhost targets are permitted.
"""

import pytest
from engine.scope_guard import ScopeGuard, ScopeViolationException

def test_scope_guard_permits_localhost():
    assert ScopeGuard.is_allowed("http://localhost:8001") is True
    assert ScopeGuard.is_allowed("http://localhost:8000/api/reports") is True
    assert ScopeGuard.is_allowed("http://127.0.0.1:8001") is True
    assert ScopeGuard.is_allowed("https://127.0.0.1:8443/test") is True

def test_scope_guard_blocks_external_domains():
    external_targets = [
        "https://example.com",
        "https://google.com",
        "http://192.168.1.100:8080",
        "http://10.0.0.5",
        "http://target.worldmonitor.gov",
        "https://8.8.8.8",
        "http://attacker.com/malicious"
    ]
    for target in external_targets:
        assert ScopeGuard.is_allowed(target) is False
        with pytest.raises(ScopeViolationException):
            ScopeGuard.enforce(target)

def test_scope_guard_blocks_malformed_and_empty():
    assert ScopeGuard.is_allowed("") is False
    assert ScopeGuard.is_allowed("javascript:alert(1)") is False
    with pytest.raises(ScopeViolationException):
        ScopeGuard.enforce("")
