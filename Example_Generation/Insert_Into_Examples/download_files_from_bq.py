import os
import re
import sqlite3
import sys
import time
from pathlib import Path

import requests
from google.cloud import bigquery

import CONFIG

BQ_QUERY = """
SELECT repo_name, path FROM `bigquery-public-data.github_repos.files` TABLESAMPLE SYSTEM (2 PERCENT) WHERE ENDS_WITH(LOWER(path), ".v") OR ENDS_WITH(LOWER(path), ".sv")
"""

OUT_DIR = CONFIG.UNFILTERED_FILES_DIR
DB_PATH = CONFIG.DB_PATH

GITHUB_TOKEN = os.environ.get("GITHUB_API_TOKEN") 
GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
if GITHUB_TOKEN:
    GITHUB_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    RAW_HEADERS = dict(GITHUB_HEADERS)
RAW_HEADERS["Accept"] = "application/vnd.github.raw"

SAFE_CHARS = re.compile(r"[^A-Za-z0-9._\-]+")

def init_db(conn: sqlite3.Connection):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS downloaded (
        repo_name TEXT NOT NULL,
        path TEXT NOT NULL,
        PRIMARY KEY (repo_name, path))
    """)
    conn.commit()

def already_downloaded(conn: sqlite3.Connection, repo_name: str, path: str) -> bool:
    cur = conn.execute(
        "SELECT 1 FROM downloaded WHERE repo_name=? AND path=? LIMIT 1",
        (repo_name, path),
    )
    return cur.fetchone() is not None

def mark_downloaded(conn: sqlite3.Connection, repo_name: str, path: str):
    conn.execute(
        "INSERT OR IGNORE INTO downloaded(repo_name, path) VALUES (?, ?)",
        (repo_name, path),
    )
    conn.commit()

def gh_get(url: str, *, headers: dict, params: dict | None = None) -> requests.Response:
    while True:
        r: requests.Response = requests.get(url, headers=headers, params=params, timeout=60)

        if r.status_code in (403, 429):
            reset = r.headers.get("X-RateLimit-Reset")
            remaining = r.headers.get("X-RateLimit-Remaining")

            if reset:
                sleep_s = max(1, int(reset) - int(time.time()) + 2)
                print(f"Rate limited (remaining={remaining}). Sleeping {sleep_s}s...")
                time.sleep(sleep_s)
                continue

            print("Rate/secondary limit hit. Sleeping 15s...")
            time.sleep(15)
            continue
        return r
    
_repo_default_branch_cache: dict[str, str] = {}

def get_default_branch(repo_name: str) -> str:
    if repo_name in _repo_default_branch_cache:
        return _repo_default_branch_cache[repo_name]
    
    owner, repo = repo_name.split("/", 1)
    url = f"https://api.github.com/repos/{owner}/{repo}"
    r = gh_get(url, headers=GITHUB_HEADERS)
    if r.status_code != 200:
        print(f"\nFailed to get repo info for {repo_name}: {r.status_code} {r.text}\n")
        return None
    
    branch = r.json().get("default_branch") or "main"
    _repo_default_branch_cache[repo_name] = branch
    return branch
def download_file_contents_api(repo_name: str, path: str) -> bytes | None:
    owner, repo = repo_name.split("/", 1)
    branch = get_default_branch(repo_name)
    if branch is None:
        return None

    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    r = gh_get(url, headers=RAW_HEADERS, params={"ref": branch})

    if r.status_code == 200:
        return r.content

    #File moved/removed since BigQuery snapshot; skip gracefully
    if r.status_code == 404:
        return None
    
    print(f"Download failed {repo_name}:{path} -> {r.status_code} {r.text[:120]}")
    return None

def safe_filename(s: str) -> str:
    return SAFE_CHARS.sub("_", s)


def main(limit: int = 100):
    start_time = time.perf_counter()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    init_db(conn)

    bq = bigquery.Client()

    if limit <= 0:
        limit = 100
    query = f"{BQ_QUERY} LIMIT {int(limit)};"
    print(f"Executing query with LIMIT {limit}...")
    rows = bq.query(query).result()
    print(f"Query returned {rows.total_rows} rows.")
    seen_this_run = set()

    fetched = 0
    saved = 0
    skipped_dup = 0
    skipped_missing = 0

    for row in rows:
        repo_name = row["repo_name"]
        path = row["path"]
        file_name = path.split("/")[-1]

        key = (repo_name, path)
        if key in seen_this_run:
            skipped_dup += 1
            continue
        seen_this_run.add(key)

        if already_downloaded(conn, repo_name, path):
            skipped_dup += 1
            continue

        fetched += 1
        data = download_file_contents_api(repo_name, path)
        if data is None:
            skipped_missing += 1
            continue

        # OUT_DIR.write_bytes(data)
        file_path = OUT_DIR / file_name
        file_path.write_bytes(data)
        mark_downloaded(conn, repo_name, path)
        saved += 1

        if saved % 25 == 0:
            print(f"Saved {saved} files... (fetched={fetched}, missing={skipped_missing}, dup={skipped_dup})")
    
    print("\nDone.")
    print(f"Fetched candidates: {fetched}")
    print(f"Saved files:       {saved}")
    print(f"Missing/404:       {skipped_missing}")
    print(f"Duplicates skipped:{skipped_dup}")
    print(f"Output dir:        {OUT_DIR.resolve()}")
    print(f"DB:                {DB_PATH.resolve()}")

    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    
    print()
    print(f"Time elapsed: {elapsed_time:.4f} seconds")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            limit = int(sys.argv[1])
        except ValueError:
            limit = 10
            print(f"Invalid limit '{sys.argv[1]}', using default 10.")
    else:
        limit = 10
    main(limit)




