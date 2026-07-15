"""Shared git-history-walking engine used by both backfill_history.py
(full history) and update_incremental.py (bounded commit range).

Key design point: avoid one `git show`/`git log` subprocess per (commit, file)
pair. list_exploitation_commits() makes ONE git-log call (with -G pickaxe
pre-filtering) to enumerate the relevant commits+changed-files in a single
pass, and CatFileBatch wraps a single long-lived `git cat-file --batch`
process so blob lookups are pipe reads/writes rather than new processes."""

import os
import re
import subprocess

from .cve_parser import CVE_PATH_RE

_COMMIT_LINE_RE = re.compile(r"^COMMIT ([0-9a-f]{40}) (.+)$")

# %cI (strict ISO 8601) preserves each commit's ORIGINAL committer timezone
# offset, which breaks lexicographic ordering/comparison of observed_date
# across commits authored in different offsets. Using %cd with
# --date=iso-strict-local under a forced TZ=UTC environment instead
# normalizes every commit date to UTC, so string ordering and datetime
# comparisons are both consistent.
_UTC_ENV = {**os.environ, "TZ": "UTC"}


def run_git(args, cwd, env=None):
    result = subprocess.run(
        ["git"] + args, cwd=cwd, capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def clone_if_missing(repo_dir, remote_url, branch="develop"):
    if (repo_dir / ".git").exists():
        return
    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--branch", branch, remote_url, str(repo_dir)],
        check=True,
    )


def fetch(repo_dir, branch="develop"):
    run_git(["fetch", "origin", branch], cwd=repo_dir)


def get_tip_sha(repo_dir, ref="origin/develop"):
    return run_git(["rev-parse", ref], cwd=repo_dir).strip()


def list_tree_files(repo_dir, ref="origin/develop"):
    output = run_git(["ls-tree", "-r", "--name-only", ref, "--", "*.json"], cwd=repo_dir)
    return [line for line in output.splitlines() if CVE_PATH_RE.match(line)]


def list_touched_files(repo_dir, since_sha, until_ref="origin/develop"):
    output = run_git(["diff", "--name-only", since_sha, until_ref, "--", "*.json"], cwd=repo_dir)
    return [line for line in output.splitlines() if CVE_PATH_RE.match(line)]


def list_exploitation_commits(repo_dir, until_ref="origin/develop", since_sha=None):
    """Returns [(sha, commit_date_iso, [changed_paths]), ...] in chronological
    (oldest-first) order, restricted to commits whose diff touches a line
    matching "Exploitation" in a *.json file."""
    range_arg = f"{since_sha}..{until_ref}" if since_sha else until_ref
    output = run_git(
        [
            "log", range_arg, "--reverse", "--first-parent", "--name-only",
            "--date=iso-strict-local", "--format=COMMIT %H %cd",
            "-G", '"Exploitation"', "--", "*.json",
        ],
        cwd=repo_dir,
        env=_UTC_ENV,
    )
    return _parse_commit_file_log(output)


def _parse_commit_file_log(output):
    commits = []
    current_sha = None
    current_date = None
    current_files = []
    for line in output.splitlines():
        match = _COMMIT_LINE_RE.match(line)
        if match:
            if current_sha is not None:
                commits.append((current_sha, current_date, current_files))
            current_sha, current_date = match.group(1), match.group(2)
            current_files = []
        elif line.strip() and current_sha is not None:
            if CVE_PATH_RE.match(line.strip()):
                current_files.append(line.strip())
    if current_sha is not None:
        commits.append((current_sha, current_date, current_files))
    return commits


class CatFileBatch:
    """Wraps a single long-lived `git cat-file --batch` process so repeated
    blob lookups across thousands of (commit, path) pairs are pipe I/O
    instead of new subprocesses."""

    def __init__(self, repo_dir):
        self._proc = subprocess.Popen(
            ["git", "cat-file", "--batch"],
            cwd=repo_dir, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )

    def get(self, sha, path):
        """Returns the blob bytes for <sha>:<path>, or None if that path
        doesn't exist at that commit (e.g. file deleted/renamed)."""
        query = f"{sha}:{path}\n".encode("utf-8")
        self._proc.stdin.write(query)
        self._proc.stdin.flush()
        header = self._proc.stdout.readline().decode("utf-8", errors="replace").strip()
        parts = header.split()
        if len(parts) >= 2 and parts[-1] == "missing":
            return None
        size = int(parts[2])
        data = self._proc.stdout.read(size)
        self._proc.stdout.read(1)  # consume trailing newline after blob content
        return data

    def close(self):
        self._proc.stdin.close()
        self._proc.wait()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
