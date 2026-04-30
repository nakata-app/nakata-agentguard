"""Tests for init, hooks, explain CLI commands."""
import json
import subprocess
import sys
import tempfile
import pathlib

import pytest


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "agentguard", *args],
        capture_output=True,
        text=True,
    )


class TestInit:
    def test_init_creates_toml(self, tmp_path):
        dest = tmp_path / "agentguard.toml"
        r = _run("init", "--output", str(dest))
        assert r.returncode == 0
        assert dest.exists()
        content = dest.read_text()
        assert "[guard]" in content
        assert "halt_on_severity" in content
        assert "[rate]" in content
        assert "[[patterns]]" in content  # example in comment

    def test_init_no_overwrite_without_force(self, tmp_path):
        dest = tmp_path / "agentguard.toml"
        dest.write_text("existing")
        r = _run("init", "--output", str(dest))
        assert r.returncode != 0
        assert dest.read_text() == "existing"

    def test_init_force_overwrites(self, tmp_path):
        dest = tmp_path / "agentguard.toml"
        dest.write_text("existing")
        r = _run("init", "--output", str(dest), "--force")
        assert r.returncode == 0
        assert "[guard]" in dest.read_text()


class TestHooks:
    def test_hooks_prints_json(self):
        r = _run("hooks")
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert "hooks" in data
        events = {h["event"] for h in data["hooks"]}
        assert "PreToolUse" in events
        assert "PostToolUse" in events

    def test_hooks_custom_cmd(self):
        r = _run("hooks", "--cmd", "my-checker run")
        data = json.loads(r.stdout)
        cmds = {h["hooks"][0]["command"] for h in data["hooks"]}
        assert "my-checker run" in cmds

    def test_hooks_install(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        r = _run("hooks", "--install")
        hooks_file = tmp_path / ".claude" / "hooks.json"
        assert hooks_file.exists()
        data = json.loads(hooks_file.read_text())
        assert "hooks" in data


class TestExplain:
    def test_explain_halt(self):
        r = _run("explain", "bash", '{"cmd": "rm -rf /"}')
        assert r.returncode == 0
        assert "HALT" in r.stdout
        assert "rm" in r.stdout.lower() or "destructive" in r.stdout.lower()

    def test_explain_warn(self):
        r = _run("explain", "bash", '{"cmd": "sudo apt update"}')
        assert r.returncode == 0
        assert "WARN" in r.stdout

    def test_explain_continue(self):
        r = _run("explain", "bash", '{"cmd": "ls -la"}')
        assert r.returncode == 0
        assert "CONTINUE" in r.stdout
        assert "No danger patterns matched" in r.stdout
