"""Shared pytest fixtures.

Config and the backup directory are redirected to a throwaway temp workspace at
import time (before app.main is imported), so tests never touch a real config.
"""
import base64
import os
import tempfile
import threading
import http.server
import socketserver
from pathlib import Path

import pytest

# --- redirect config to a temp workspace BEFORE anything imports app.main ---
import app.config as cfg

_TMP = Path(tempfile.mkdtemp(prefix="magikup-tests-"))
cfg.CONFIG_FILE = _TMP / "config.ini"
cfg.ENCRYPTION_KEY_FILE = _TMP / ".encryption_key"
cfg.ensure_config_exists()

BACKUPS = _TMP / "backups"
BACKUPS.mkdir(exist_ok=True)


@pytest.fixture(autouse=True)
def reset_state():
    """Give each test a clean config (default template + temp backup_dir) and an
    empty backup directory, so tests are order-independent."""
    cfg.CONFIG_FILE.write_text(cfg.get_default_config())
    c = cfg.read_config()
    c.set("settings", "backup_dir", str(BACKUPS))
    cfg.write_config(c)
    for f in BACKUPS.glob("*"):
        if f.is_file():
            f.unlink()
    yield


@pytest.fixture
def backup_dir():
    return BACKUPS


@pytest.fixture
def sample_backup():
    """Create a small valid local .backup file and return its path."""
    p = BACKUPS / "db_20260101_120000.backup"
    p.write_bytes(b"PGDMP-fake-backup" * 512)
    return p


@pytest.fixture
def client():
    """TestClient with auth dependencies overridden (acts as an admin)."""
    import app.main as main
    from app import auth
    from fastapi.testclient import TestClient

    fake = {"username": "tester", "role": "admin", "endpoints": ["*"]}
    main.app.dependency_overrides[auth.require_auth] = lambda: fake
    main.app.dependency_overrides[auth.require_operator] = lambda: fake
    main.app.dependency_overrides[auth.require_admin] = lambda: fake
    with TestClient(main.app) as c:
        yield c
    main.app.dependency_overrides.clear()


class _DAVHandler(http.server.BaseHTTPRequestHandler):
    """Minimal WebDAV/HTTP server: PROPFIND(207), PUT(store), GET(serve).
    Records the last Authorization header seen on GET into server.seen_auth."""
    def log_message(self, *a):
        pass

    def do_PROPFIND(self):
        self.send_response(207)
        self.end_headers()
        self.wfile.write(b"<multistatus/>")

    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(n)
        (self.server.store_root / os.path.basename(self.path)).write_bytes(data)
        self.send_response(201)
        self.end_headers()

    def do_GET(self):
        self.server.seen_auth = self.headers.get("Authorization")
        f = self.server.store_root / os.path.basename(self.path)
        if not f.exists():
            self.send_response(404)
            self.end_headers()
            return
        data = f.read_bytes()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def webdav():
    """Local WebDAV/HTTP server. Yields an object with .base_url, .store_root,
    and .seen_auth (Authorization header from the last GET)."""
    store_root = Path(tempfile.mkdtemp(prefix="dav-"))
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _DAVHandler)
    httpd.store_root = store_root
    httpd.seen_auth = None
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    class Server:
        base_url = f"http://127.0.0.1:{port}/dav"
        pass
    srv = Server()
    srv.store_root = store_root
    srv._httpd = httpd

    def _seen_auth():
        return httpd.seen_auth
    srv.seen_auth = _seen_auth
    yield srv
    httpd.shutdown()


@pytest.fixture
def fake_s3(monkeypatch):
    """Replace remote_storage._s3_client with an in-memory fake. Yields the
    dict backing the bucket (key -> bytes)."""
    import app.remote_storage as rs
    import datetime

    bucket = {}

    class FakeS3:
        def head_bucket(self, Bucket):
            return {}

        def upload_file(self, filename, Bucket, Key):
            bucket[Key] = Path(filename).read_bytes()

        def head_object(self, Bucket, Key):
            return {"ContentLength": len(bucket[Key])}

        def download_file(self, Bucket, Key, filename):
            Path(filename).write_bytes(bucket[Key])

        def get_paginator(self, op):
            class P:
                def paginate(self, Bucket, Prefix=""):
                    contents = [
                        {"Key": k, "Size": len(v),
                         "LastModified": datetime.datetime(2026, 1, 1, 12, 0, 0)}
                        for k, v in bucket.items() if k.startswith(Prefix)
                    ]
                    return [{"Contents": contents}]
            return P()

    monkeypatch.setattr(rs, "_s3_client", lambda store: FakeS3())
    return bucket
