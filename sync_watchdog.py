import os
import json
import subprocess
from elasticsearch import Elasticsearch


def get_git_changes(repo_path):
    """Uses git diff to find added or modified files since the last sync."""
    try:
        # Pull the latest changes from GitHub
        print("[*] Pulling latest changes from GitHub...")
        subprocess.run(["git", "pull"], cwd=repo_path, check=True, capture_output=True)

        # Get the list of changed files (Added 'A' and Modified 'M')
        # HEAD@{1} refers to the state before the pull
        result = subprocess.run(
            ["git", "diff", "HEAD@{1}", "HEAD", "--name-status"],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
        )

        changes = []
        for line in result.stdout.splitlines():
            status, path = line.split(None, 1)
            if path.endswith(".json") and "cves/" in path:
                changes.append((status, path))
        return changes
    except Exception as e:
        print(f"[!] Git Sync Error: {e}")
        return []


def sync_updates():
    es = Elasticsearch("http://localhost:9200")
    repo_path = "cves_data"

    changed_files = get_git_changes(repo_path)

    if not changed_files:
        print("[*] Everything is up to date. No changes detected.")
        return

    print(f"[*] Found {len(changed_files)} updates. Syncing to Elasticsearch...")

    for status, relative_path in changed_files:
        full_path = os.path.join(repo_path, relative_path)
        cve_id = os.path.basename(relative_path).replace(".json", "")
        print("\n", "one iteration ended  ", "\n")

        if status in ["A", "M"]:  # Added or Modified
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Upsert into Elasticsearch
                    es.index(index="cves", id=cve_id, document=data)
                    print(f"    [+] Updated {cve_id}")
            except Exception as e:
                print(f"    [!] Failed to sync {cve_id}: {e}")

    print("[*] Sync complete!")
    print("\n")


if __name__ == "__main__":
    sync_updates()
