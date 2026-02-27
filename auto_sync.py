import os
import json
import subprocess
import time
import schedule
from elasticsearch import Elasticsearch
import urllib.request


def send_ntfy_alert(message):
    """Sends a push notification to your phone directly from Python."""
    try:
        req = urllib.request.Request(
            "https://ntfy.sh/bhard_alerts", data=message.encode("utf-8"), method="POST"
        )
        urllib.request.urlopen(req)
    except Exception as e:
        print(f"[!] Failed to send mobile alert: {e}")


def get_git_changes():
    """Pulls from GitHub and calculates exactly what changed."""
    repo_path = "cves_data"
    try:
        print("[*] Pulling latest changes from GitHub...")
        subprocess.run(["git", "pull"], cwd=repo_path, check=True, capture_output=True)

        result = subprocess.run(
            ["git", "diff", "HEAD@{1}", "HEAD", "--name-status"],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
        )

        changes = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                status, path = parts
                if path.endswith(".json") and "cves/" in path:
                    changes.append((status, path))
        return changes
    except subprocess.CalledProcessError:
        print("[*] No new commits to pull or Git is already up to date.")
        return []
    except Exception as e:
        print(f"[!] Git Sync Error: {e}")
        return []


def sync_updates():
    print("\n[*] Starting Sync Check...")

    # CRITICAL: Notice this says 'elasticsearch' instead of 'localhost'.
    # This is required for Docker containers to talk to each other!
    es = Elasticsearch("http://elasticsearch:9200")
    repo_path = "cves_data"

    changed_files = get_git_changes()

    if not changed_files:
        print("[*] Database is fully up to date. Sleeping until next check.")
        return

    print(f"[*] Found {len(changed_files)} updates. Syncing to local Elasticsearch...")
    success_count = 0

    for status, relative_path in changed_files:
        full_path = os.path.join(repo_path, relative_path)
        cve_id = os.path.basename(relative_path).replace(".json", "")

        # 'A' = Added, 'M' = Modified
        if status in ["A", "M"]:
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    es.index(index="cves", id=cve_id, document=data)
                    print(f"    [+] Updated {cve_id}")
                    success_count += 1
            except Exception as e:
                print(f"    [!] Failed to sync {cve_id}: {e}")

        # 'D' = Deleted
        elif status == "D":
            try:
                es.delete(index="cves", id=cve_id, ignore=[404])
                print(f"    [-] Removed {cve_id}")
            except Exception:
                pass

    print("[*] Sync complete!")
    if success_count > 0:
        send_ntfy_alert(f"CVE Database Sync Complete: {success_count} threats updated!")


if __name__ == "__main__":
    print("=== CVE Auto-Updater Initialized ===")

    # Run a check immediately on startup
    sync_updates()

    # Then schedule it to run every 1 hour
    schedule.every(1).hours.do(sync_updates)

    print("\n[*] Watchdog is now active. Monitoring for changes hourly...")
    while True:
        schedule.run_pending()
        time.sleep(60)
