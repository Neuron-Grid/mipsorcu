"""Reject PR edits to CI, verification, and audit criteria using trusted base policy."""

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

PAGE_SIZE = 100
MAX_PAGES = 30  # GitHub's pull request files endpoint caps results at 3,000.
PROTECTED_PREFIXES = (
    ".github/workflows/",
    ".github/actions/",
    "scripts/",
    "tests/",
    "supabase/tests/",
    "supply-chain/",
    ".cargo/",
)
PROTECTED_FILES = {"Cargo.toml", "Cargo.lock", "deny.toml", "supabase/config.toml"}
PROTECTED_BASENAMES = {"AGENTS.md", "CODEOWNERS"}


def protected(path: str) -> bool:
    return (
        path in PROTECTED_FILES
        or path.startswith(PROTECTED_PREFIXES)
        or path.rsplit("/", 1)[-1] in PROTECTED_BASENAMES
    )


def response_paths(batch: object) -> list[str]:
    if not isinstance(batch, list) or any(
        not isinstance(item, dict)
        or not isinstance(item.get("filename"), str)
        or ("previous_filename" in item and not isinstance(item["previous_filename"], str))
        for item in batch
    ):
        raise ValueError("unexpected pull request files response")
    paths = []
    for item in batch:
        paths.append(item["filename"])
        if "previous_filename" in item:
            paths.append(item["previous_filename"])
    return paths


def verify_revision(pr: object, expected_base: str, expected_head: str) -> None:
    if not isinstance(pr, dict) or pr.get("state") != "open":
        raise ValueError("pull request is unavailable or closed")
    try:
        base = pr["base"]["sha"]
        head = pr["head"]["sha"]
    except (KeyError, TypeError):
        raise ValueError("unexpected pull request revision response") from None
    if base != expected_base or head != expected_head:
        raise ValueError("pull request revision changed; rerun policy check")


def api_json(url: str, token: str) -> object:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "mipsorcu-ci-policy",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def changed_files(repository: str, pr_number: str, token: str, expected_base: str, expected_head: str) -> list[str]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid repository identifier")
    if not re.fullmatch(r"[1-9][0-9]*", pr_number):
        raise ValueError("invalid pull request number")
    if not token:
        raise ValueError("missing GitHub token")

    pr_url = f"https://api.github.com/repos/{repository}/pulls/{pr_number}"
    verify_revision(api_json(pr_url, token), expected_base, expected_head)
    paths = []
    files_url = f"{pr_url}/files"
    for page in range(1, MAX_PAGES + 1):
        batch = api_json(f"{files_url}?per_page={PAGE_SIZE}&page={page}", token)
        paths.extend(response_paths(batch))
        if len(batch) < PAGE_SIZE:
            verify_revision(api_json(pr_url, token), expected_base, expected_head)
            return paths

    raise ValueError("pull request file limit reached; cannot verify complete change set")


def main() -> int:
    try:
        paths = changed_files(
            os.environ.get("GITHUB_REPOSITORY", ""),
            os.environ.get("PR_NUMBER", ""),
            os.environ.get("GITHUB_TOKEN", ""),
            os.environ.get("BASE_SHA", ""),
            os.environ.get("HEAD_SHA", ""),
        )
    except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as error:
        print(f"FAIL: unable to verify pull request files: {error}", file=sys.stderr)
        return 1

    violations = sorted({path for path in paths if protected(path)})
    if violations:
        print("FAIL: protected policy files can be changed only through an administrator-controlled procedure outside this pull request:")
        for path in violations:
            print(f"  {path}")
        return 1
    print(f"PASS: checked all {len(paths)} changed paths against base-branch policy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
