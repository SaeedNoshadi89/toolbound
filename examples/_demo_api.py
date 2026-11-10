"""A tiny local REST API used by the offline examples (stdlib only).

It imitates a GitHub-style issue tracker and a document search service with
synthetic data. Nothing here is part of the library.
"""

from __future__ import annotations

import contextlib
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

ISSUES = [
    {
        "id": 1000 + n,
        "number": n,
        "title": f"Issue {n}: {'Crash when saving' if n % 2 else 'Improve docs'}",
        "state": "open" if n % 3 else "closed",
        "user": {
            "login": f"user{n % 4}",
            "id": 50 + n,
            "site_admin": False,
            "avatar_url": f"https://avatars.example.com/u/{50 + n}",
        },
        "labels": [{"name": "bug", "color": "d73a4a"}] if n % 2 else [{"name": "docs"}],
        "body": ("Steps to reproduce the problem in detail. " * 30).strip(),
        "comments": n % 5,
        "html_url": f"https://tracker.example.com/acme/widgets/issues/{n}",
        "node_id": f"I_kwDO{n:08d}",
        "reactions": {"+1": n % 3, "-1": 0, "laugh": 0, "url": "https://example.com/r"},
        "created_at": f"2026-0{1 + n % 9}-1{n % 9}T10:00:00Z",
    }
    for n in range(1, 61)
]

DOCUMENTS = [
    {
        "doc_id": f"RULING-1404-{i:03d}",
        "court": "دادگاه تجدیدنظر استان تهران",
        "date": f"1404/0{1 + i % 9}/1{i % 9}",
        "title": "رأی در خصوص فسخ قرارداد اجاره به دلیل عدم پرداخت اجاره‌بها",
        "text": (
            "با عنایت به محتویات پرونده و دفاعیات طرفین، دادگاه تجدیدنظر خواسته را "
            "وارد دانسته و قرارداد اجاره را فسخ شده اعلام می‌نماید. "
        )
        * 12,
        "internal_reviewer": "reviewer@example.com",
    }
    for i in range(1, 13)
]


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass

    def _json(self, status: int, payload: object, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Request-Id", "demo-req-1")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        parts = [p for p in url.path.split("/") if p]
        if parts[:1] == ["repos"] and len(parts) == 4 and parts[3] == "issues":
            page = int(query.get("page", ["1"])[0])
            per_page = min(int(query.get("per_page", ["30"])[0]), 100)
            start = (page - 1) * per_page
            items = ISSUES[start : start + per_page]
            headers = {}
            if start + per_page < len(ISSUES):
                host = self.headers["Host"]
                headers["Link"] = (
                    f'<http://{host}{url.path}?page={page + 1}&per_page={per_page}>; rel="next"'
                )
            self._json(200, items, headers)
        elif parts[:1] == ["repos"] and len(parts) == 5 and parts[3] == "issues":
            number = int(parts[4]) if parts[4].isdigit() else -1
            issue = next((i for i in ISSUES if i["number"] == number), None)
            if issue is None:
                self._json(404, {"message": "Not Found"})
            else:
                self._json(200, issue)
        elif url.path == "/legal/search":
            q = query.get("q", [""])[0]
            hits = [d for d in DOCUMENTS if q in d["title"] or q in d["text"]] if q else DOCUMENTS
            self._json(200, {"total": len(hits), "results": hits})
        elif url.path == "/moved":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/iam/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._json(404, {"message": "Not Found"})

    def do_DELETE(self) -> None:
        if "/comments/" in self.path:
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._json(404, {"message": "Not Found"})


@contextlib.contextmanager
def run_demo_api() -> Iterator[str]:
    """Start the demo API on 127.0.0.1 with a random port; yields its base URL."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
