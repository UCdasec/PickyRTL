import os
import re
import CONFIG
import sqlite3
import requests
import time
from InquirerPy import inquirer

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

def fetch_files(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    cur = conn.execute("SELECT repo_name, path FROM downloaded;")
    return cur.fetchall()

def count_rows(conn: sqlite3.Connection) -> int:
    cur = conn.execute("SELECT COUNT(*) FROM downloaded;")
    return cur.fetchone()[0]

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

def main():
    start_time = time.perf_counter()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)

    num_files = count_rows(conn)

    if inquirer.confirm(
        message=f"Are you sure you want to retry downloading all files? This action will download {num_files} files from GitHub.",
        default=True,
    ).execute():
        files = fetch_files(conn)
        saved = 0
        for repo_name, path in files:
            data = download_file_contents_api(repo_name, path)
            if data is None:
                continue
            
            file_name = path.split("/")[-1]
            file_path = OUT_DIR / file_name
            file_path.write_bytes(data)
            saved += 1
            if saved % 25 == 0:
                print(f"Downloaded {saved}/{num_files} files...")

        end_time = time.perf_counter()
        elapsed_time = end_time - start_time
        
        print()
        print(f"Time elapsed: {elapsed_time:.4f} seconds")
    else:
        exit(0)


if __name__ == "__main__":
    main()
