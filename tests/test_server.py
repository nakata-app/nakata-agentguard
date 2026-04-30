"""Tests for FastAPI server (requires [serve] extras)."""
import pytest

try:
    from fastapi.testclient import TestClient
    from agentguard.server import create_app
    from agentguard.guard import GuardConfig
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

pytestmark = pytest.mark.skipif(not _AVAILABLE, reason="fastapi not installed")


@pytest.fixture
def client():
    app = create_app(GuardConfig(exact_threshold=3, halt_on_severity=9))
    return TestClient(app)


class TestHealth:
    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


class TestRecord:
    def test_safe_call_continues(self, client):
        r = client.post("/record", json={"tool": "bash", "args": {"cmd": "ls"}})
        assert r.status_code == 200
        assert r.json()["action"] == "continue"

    def test_dangerous_call_halts(self, client):
        r = client.post("/record", json={"tool": "bash", "args": {"cmd": "rm -rf /"}})
        assert r.status_code == 200
        assert r.json()["action"] == "halt"
        assert r.json()["danger_count"] > 0

    def test_loop_halts(self, client):
        for _ in range(2):
            client.post("/record", json={"tool": "bash", "args": {"cmd": "loop"}})
        r = client.post("/record", json={"tool": "bash", "args": {"cmd": "loop"}})
        assert r.json()["action"] == "halt"
        assert r.json()["loop_detected"] is True

    def test_session_isolation(self, client):
        client.post("/record?session=a", json={"tool": "bash", "args": {"cmd": "s"}})
        client.post("/record?session=a", json={"tool": "bash", "args": {"cmd": "s"}})
        client.post("/record?session=a", json={"tool": "bash", "args": {"cmd": "s"}})
        # Session b should have no calls
        r = client.get("/status?session=b")
        assert r.json()["total_calls"] == 0

    def test_token_count_accumulates(self, client):
        client.post("/record", json={"tool": "llm", "args": {}, "tokens": 100})
        r = client.post("/record", json={"tool": "llm", "args": {}, "tokens": 200})
        assert r.json()["total_tokens"] == 300


class TestStatus:
    def test_status_empty(self, client):
        r = client.get("/status?session=fresh_" + __name__)
        assert r.json()["total_calls"] == 0
        assert r.json()["action"] == "continue"


class TestStats:
    def test_stats_endpoint(self, client):
        client.post("/record?session=stats_test", json={"tool": "bash", "args": {"cmd": "x"}})
        r = client.get("/stats?session=stats_test")
        assert r.status_code == 200
        data = r.json()
        assert data["total_calls"] == 1
        assert "bash" in data["tool_frequency"]


class TestReset:
    def test_reset_clears_session(self, client):
        client.post("/record?session=r", json={"tool": "bash", "args": {}})
        client.post("/reset?session=r")
        r = client.get("/status?session=r")
        assert r.json()["total_calls"] == 0

    def test_reset_all(self, client):
        client.post("/record?session=x1", json={"tool": "bash", "args": {}})
        client.post("/record?session=x2", json={"tool": "bash", "args": {}})
        r = client.post("/reset?session=all")
        assert r.json()["sessions_cleared"] == "all"
