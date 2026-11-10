"""Deterministic benchmark fixtures.

`github_issues()` produces synthetic data shaped like the public GitHub REST API issue
object (same field names and nesting; the values are generated). `legal_documents()`
produces synthetic Persian court-ruling records. No real user data is included.
"""

from __future__ import annotations

import random
from typing import Any

WORDS = (
    "the build fails when the cache directory is missing and the retry logic does not "
    "recover so users see a stack trace instead of a helpful error message"
).split()


def _user(rng: random.Random, login: str) -> dict[str, Any]:
    uid = rng.randint(1000, 9_999_999)
    base = f"https://api.github.com/users/{login}"
    return {
        "login": login,
        "id": uid,
        "node_id": f"MDQ6VXNlcj{uid}",
        "avatar_url": f"https://avatars.githubusercontent.com/u/{uid}?v=4",
        "gravatar_id": "",
        "url": base,
        "html_url": f"https://github.com/{login}",
        "followers_url": f"{base}/followers",
        "following_url": f"{base}/following{{/other_user}}",
        "gists_url": f"{base}/gists{{/gist_id}}",
        "starred_url": f"{base}/starred{{/owner}}{{/repo}}",
        "subscriptions_url": f"{base}/subscriptions",
        "organizations_url": f"{base}/orgs",
        "repos_url": f"{base}/repos",
        "events_url": f"{base}/events{{/privacy}}",
        "received_events_url": f"{base}/received_events",
        "type": "User",
        "user_view_type": "public",
        "site_admin": False,
    }


def github_issues(count: int = 30, seed: int = 7) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    repo = "https://api.github.com/repos/acme/widgets"
    issues = []
    for i in range(count):
        number = 5000 - i
        labels = [
            {
                "id": rng.randint(10**8, 10**9),
                "node_id": f"LA_kwDO{number}{j}",
                "url": f"{repo}/labels/{name}",
                "name": name,
                "color": "d73a4a",
                "default": False,
                "description": f"Label {name}",
            }
            for j, name in enumerate(
                rng.sample(["bug", "docs", "triage", "p1", "ui", "infra"], rng.randint(0, 3))
            )
        ]
        body = " ".join(rng.choice(WORDS) for _ in range(rng.randint(40, 400)))
        issues.append(
            {
                "url": f"{repo}/issues/{number}",
                "repository_url": repo,
                "labels_url": f"{repo}/issues/{number}/labels{{/name}}",
                "comments_url": f"{repo}/issues/{number}/comments",
                "events_url": f"{repo}/issues/{number}/events",
                "html_url": f"https://github.com/acme/widgets/issues/{number}",
                "id": rng.randint(10**9, 10**10),
                "node_id": f"I_kwDOAB{number}",
                "number": number,
                "title": " ".join(
                    rng.choice(WORDS) for _ in range(rng.randint(4, 12))
                ).capitalize(),
                "user": _user(rng, f"user{rng.randint(1, 500)}"),
                "labels": labels,
                "state": rng.choice(["open", "open", "closed"]),
                "locked": False,
                "assignee": None,
                "assignees": [],
                "milestone": None,
                "comments": rng.randint(0, 40),
                "created_at": f"2026-0{rng.randint(1, 9)}-1{rng.randint(0, 9)}T0{rng.randint(0, 9)}:00:00Z",
                "updated_at": "2026-10-01T12:00:00Z",
                "closed_at": None,
                "author_association": "CONTRIBUTOR",
                "type": None,
                "active_lock_reason": None,
                "sub_issues_summary": {"total": 0, "completed": 0, "percent_completed": 0},
                "body": body,
                "closed_by": None,
                "reactions": {
                    "url": f"{repo}/issues/{number}/reactions",
                    "total_count": 3,
                    "+1": 2,
                    "-1": 0,
                    "laugh": 0,
                    "hooray": 1,
                    "confused": 0,
                    "heart": 0,
                    "rocket": 0,
                    "eyes": 0,
                },
                "timeline_url": f"{repo}/issues/{number}/timeline",
                "performed_via_github_app": None,
                "state_reason": None,
            }
        )
    return issues


PERSIAN = (
    "با عنایت به محتویات پرونده و دفاعیات طرفین و نظر به اینکه خوانده دلیلی بر پرداخت "
    "اجاره‌بها ارائه ننموده است دادگاه دعوای خواهان را وارد تشخیص داده و حکم به فسخ "
    "قرارداد اجاره صادر می‌نماید"
).split()


def legal_documents(count: int = 20, seed: int = 11) -> dict[str, Any]:
    rng = random.Random(seed)
    results = []
    for i in range(count):
        results.append(
            {
                "doc_id": f"RULING-1404-{i:04d}",
                "court": "دادگاه تجدیدنظر استان تهران",
                "branch": f"شعبه {rng.randint(1, 60)}",
                "date": f"1404/{rng.randint(1, 12):02d}/{rng.randint(1, 29):02d}",
                "title": " ".join(rng.choice(PERSIAN) for _ in range(10)),
                "text": " ".join(rng.choice(PERSIAN) for _ in range(rng.randint(300, 900))),
                "parties": [
                    {"role": "خواهان", "name": "طرف الف"},
                    {"role": "خوانده", "name": "طرف ب"},
                ],
                "keywords": rng.sample(PERSIAN, 5),
                "internal": {"reviewer": "reviewer@example.com", "score": rng.random()},
            }
        )
    return {"total": count, "results": results}
