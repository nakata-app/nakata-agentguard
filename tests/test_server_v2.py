"""Tests for webhook, prometheus metrics, and multi-session server features."""
import pytest

try:
    from fastapi.testclient import TestClient
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

from agentguard.guard import GuardConfig  # noqa: E402
from agentguard.server import create_app  # noqa: E402

pytestmark = pytest.mark.skipif(not _AVAILABLE, reason="FastAPI not installed")


@pytest.fixture
def client():
    app = create_app(GuardConfig())
    return TestClient(app)


class TestMetricsEndpoint:
    def test_metrics_returns_200(self, client):
        r = client.get("/metrics")
        assert r.status_code == 200

    def test_metrics_has_gauge_lines(self, client):
        r = client.get("/metrics")
        text = r.text
        assert "agentguard_uptime_seconds" in text
        assert "agentguard_active_sessions" in text

    def test_metrics_counts_records(self, client):
        client.post("/record", json={"tool": "bash", "args": {"cmd": "ls"}})
        client.post("/record", json={"tool": "bash", "args": {"cmd": "pwd"}})
        r = client.get("/metrics")
        assert "agentguard_records_total 2" in r.text

    def test_metrics_aggregates_sessions(self, client):
        client.post("/record?session=a", json={"tool": "bash", "args": {"cmd": "ls"}, "tokens": 100})
        client.post("/record?session=b", json={"tool": "read", "args": {"path": "/tmp"}, "tokens": 200})
        r = client.get("/metrics")
        assert "agentguard_total_tokens 300" in r.text


class TestWebhookFiring:
    def test_no_webhook_no_crash(self, client):
        # Dangerous call — webhook not set, should still return normally
        r = client.post("/record", json={"tool": "bash", "args": {"cmd": "rm -rf /"}})
        assert r.status_code == 200
        assert r.json()["action"] == "halt"

    def test_webhook_fires_on_halt(self, tmp_path):
        """Use a local HTTP server to verify webhook receives payload."""
        import http.server
        import json as _json
        import threading

        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                received.append(_json.loads(body))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        t = threading.Thread(target=server.handle_request, daemon=True)
        t.start()

        app = create_app(GuardConfig(), webhook_url=f"http://127.0.0.1:{port}/hook")
        c = TestClient(app)
        c.post("/record", json={"tool": "bash", "args": {"cmd": "rm -rf /"}})
        t.join(timeout=2)

        assert len(received) == 1
        assert received[0]["action"] == "halt"
        assert "session" in received[0]


class TestHealthUptime:
    def test_health_has_uptime(self, client):
        r = client.get("/health")
        data = r.json()
        assert "uptime_seconds" in data
        assert data["uptime_seconds"] >= 0


class TestMultiSession:
    def test_sessions_isolated(self, client):
        # Trigger loop in session A
        for _ in range(3):
            client.post("/record?session=A", json={"tool": "bash", "args": {"cmd": "ls"}})
        r_a = client.get("/status?session=A").json()
        r_b = client.get("/status?session=B").json()
        assert r_a["action"] == "halt"
        assert r_b["action"] == "continue"

    def test_reset_all(self, client):
        client.post("/record?session=x", json={"tool": "bash", "args": {"cmd": "ls"}})
        client.post("/reset?session=all", json={})
        r = client.get("/sessions").json()
        assert r["sessions"] == []
