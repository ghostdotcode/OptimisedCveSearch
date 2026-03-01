import os
import json
import subprocess
import threading
import urllib.request
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify
from elasticsearch import Elasticsearch
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
es = Elasticsearch("http://elasticsearch:9200")

MASTER_TEMPLATE = set()
if os.path.exists("master_template.json"):
    with open("master_template.json", "r", encoding="utf-8") as f:
        MASTER_TEMPLATE = set(json.load(f))


def send_ntfy_alert(message):
    try:
        req = urllib.request.Request(
            "https://ntfy.sh/bhard_alerts", data=message.encode("utf-8"), method="POST"
        )
        urllib.request.urlopen(req)
    except Exception as e:
        print(f"[!] Failed to send mobile alert: {e}")


# --- THE PERSISTENT TRACKER LOGIC ---
def get_git_changes():
    repo_path = "cves_data"
    state_file = "sync_state.txt"

    try:
        last_commit = None
        if os.path.exists(state_file):
            with open(state_file, "r") as f:
                last_commit = f.read().strip()

        if not last_commit:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True,
            )
            last_commit = result.stdout.strip()
            with open(state_file, "w") as f:
                f.write(last_commit)
            print(
                f"[*] Initialized persistent sync state at commit: {last_commit[:7]}",
                flush=True,
            )

        print("[*] Pulling latest changes from GitHub...", flush=True)
        subprocess.run(
            ["git", "pull"], cwd=repo_path, check=True, capture_output=True, text=True
        )

        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
        )
        current_commit = result.stdout.strip()

        if last_commit == current_commit:
            print("[*] No new commits on GitHub. Database is up to date.", flush=True)
            return [], current_commit

        print(
            f"[*] Calculating differences between {last_commit[:7]} and {current_commit[:7]}...",
            flush=True,
        )
        result = subprocess.run(
            ["git", "diff", last_commit, current_commit, "--name-status"],
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

        return changes, current_commit

    except Exception as e:
        print(f"[!] GIT ERROR: {str(e)}", flush=True)
        return [], None


def sync_updates(is_manual=False):
    print("\n[*] --- SYNC JOB INITIATED ---", flush=True)
    repo_path = "cves_data"
    state_file = "sync_state.txt"

    changed_files, new_commit = get_git_changes()

    if not changed_files:
        print("[*] Sync process finished: No new files to inject.", flush=True)
        if is_manual:
            send_ntfy_alert("Manual Sync Triggered: Database is already up to date.")
        return

    print(
        f"[*] Found {len(changed_files)} updates. Syncing to local Elasticsearch...",
        flush=True,
    )
    success_count = 0

    for status, relative_path in changed_files:
        full_path = os.path.join(repo_path, relative_path)
        cve_id = os.path.basename(relative_path).replace(".json", "")

        if status in ["A", "M"]:
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    es.index(index="cves", id=cve_id, document=data)
                    print(f"    [+] Updated {cve_id}", flush=True)
                    success_count += 1
            except Exception as e:
                print(f"    [!] Failed to index {cve_id}: {e}", flush=True)
        elif status == "D":
            try:
                es.delete(index="cves", id=cve_id, ignore=[404])
                print(f"    [-] Removed {cve_id}", flush=True)
            except Exception:
                pass

    if new_commit:
        with open(state_file, "w") as f:
            f.write(new_commit)
        print(
            f"[*] Updated persistent sync state to commit: {new_commit[:7]}", flush=True
        )

    print("[*] Sync complete!", flush=True)
    if success_count > 0:
        trigger_type = "Manual" if is_manual else "Scheduled"
        send_ntfy_alert(
            f"{trigger_type} Sync Complete: {success_count} threats updated!"
        )


scheduler = BackgroundScheduler(timezone=timezone.utc)
scheduler.add_job(
    func=lambda: sync_updates(is_manual=False),
    trigger="interval",
    minutes=60,
    id="auto_sync_job",
    next_run_time=datetime.now(timezone.utc),
)
scheduler.start()


def extract_all_keys(data, parent_key=""):
    keys = set()
    if isinstance(data, dict):
        for k, v in data.items():
            current_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, (dict, list)):
                keys.update(extract_all_keys(v, current_key))
            else:
                keys.add(current_key)
    elif isinstance(data, list):
        for item in data:
            keys.update(extract_all_keys(item, parent_key))
    else:
        if parent_key:
            keys.add(parent_key)
    return keys


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/search", methods=["GET"])
def search_cve():
    cve_id = request.args.get("cve_id", "").strip().upper()
    if not cve_id:
        return jsonify({"error": "No CVE ID provided"}), 400
    try:
        res = es.get(index="cves", id=cve_id)
        data = res["_source"]
        cve_meta = data.get("cveMetadata", {})

        description_value = "No English description available."
        for desc in data.get("containers", {}).get("cna", {}).get("descriptions", []):
            if desc.get("lang") == "en":
                description_value = desc.get("value")
                break

        table_data = {
            "assignerOrgId": cve_meta.get("assignerOrgId", "N/A"),
            "assignerShortName": cve_meta.get("assignerShortName", "N/A"),
            "cveId": cve_meta.get("cveId", "N/A"),
            "datePublished": cve_meta.get("datePublished", "N/A"),
            "dateReserved": cve_meta.get("dateReserved", "N/A"),
            "dateUpdated": cve_meta.get("dateUpdated", "N/A"),
            "state": cve_meta.get("state", "N/A"),
            "description": description_value,
        }

        populated_keys = extract_all_keys(data)
        missing_keys = MASTER_TEMPLATE - populated_keys

        json_output = json.dumps(data, indent=2)
        json_output += (
            "\n\n"
            + "=" * 60
            + "\n                 MISSING DATA (NA FIELDS)\n"
            + "=" * 60
            + "\n\n"
        )
        for mk in sorted(missing_keys):
            json_output += f'"{mk}": "NA"\n'

        return jsonify({"table_data": table_data, "full_json": json_output})

    except Exception:
        return jsonify({"error": f"{cve_id} not found in local database."}), 404


@app.route("/api/status", methods=["GET"])
def get_status():
    job = scheduler.get_job("auto_sync_job")
    if job and job.next_run_time:
        time_remaining = (
            job.next_run_time - datetime.now(timezone.utc)
        ).total_seconds()
        return jsonify({"seconds_remaining": max(0, int(time_remaining))})
    return jsonify({"seconds_remaining": 0})


@app.route("/api/force_sync", methods=["POST"])
def force_sync():
    threading.Thread(target=lambda: sync_updates(is_manual=True)).start()
    return jsonify({"message": "Manual sync initiated in background."})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, use_reloader=False)
