import os
import sys
import json
import urllib.request
import logging
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify
from elasticsearch import Elasticsearch
from celery import Celery
from celery.schedules import crontab
import redis
import time

r_client = redis.Redis(host="redis", port=6379, db=0)

# Ensure /app is on the path so Celery prefork child processes can find
# local modules (backfill.py) regardless of their working directory.
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

import backfill

# Silence the Flask/Werkzeug terminal spam
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)

app = Flask(__name__)
es = Elasticsearch("http://elasticsearch:9200")

# --- CELERY CONFIGURATION ---
app.config["CELERY_BROKER_URL"] = os.environ.get(
    "CELERY_BROKER_URL", "redis://redis:6379/0"
)
celery = Celery(app.name, broker=app.config["CELERY_BROKER_URL"])
celery.conf.update(app.config)

celery.conf.beat_schedule = {
    "hourly-cve-sync": {
        "task": "app.sync_updates_task",
        "schedule": crontab(minute=0),
        "args": (False,),
    },
}
celery.conf.timezone = "UTC"
# Instructs Celery Beat to run the sync task every 3600 seconds (1 hour)
celery.conf.beat_schedule = {
    "run-delta-sync-every-hour": {
        "task": "app.sync_updates_task",
        "schedule": 3600.0,
    },
}

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


GITHUB_API = "https://api.github.com/repos/CVEProject/cvelistV5"


def _github_get(url):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "cve-sync-bot"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode())


def get_git_changes():
    state_file = "sync_state.txt"
    try:
        last_commit = None
        if os.path.exists(state_file):
            with open(state_file, "r") as f:
                last_commit = f.read().strip()

        print("[*] Checking GitHub for latest commit...", flush=True)
        data = _github_get(f"{GITHUB_API}/commits/main")
        current_commit = data["sha"]

        if not last_commit:
            with open(state_file, "w") as f:
                f.write(current_commit)
            return [], current_commit

        if last_commit == current_commit:
            return [], current_commit

        changes = []
        page = 1
        while True:
            compare_url = f"{GITHUB_API}/compare/{last_commit}...{current_commit}?per_page=300&page={page}"
            compare_data = _github_get(compare_url)
            files = compare_data.get("files", [])
            for f_info in files:
                path = f_info["filename"]
                gh_status = f_info["status"]
                if path.endswith(".json") and "cves/" in path:
                    if gh_status in ("added", "modified", "renamed"):
                        changes.append(("M", path))
                    elif gh_status == "removed":
                        changes.append(("D", path))

            if len(files) < 300:
                break
            page += 1

        return changes, current_commit

    except Exception as e:
        print(f"[!] GITHUB API ERROR: {str(e)}", flush=True)
        return [], None


# --- CELERY TASKS ---
@celery.task(name="app.sync_updates_task")
def sync_updates_task(is_manual=False):
    print("\n[*] --- CELERY WORKER: SYNC JOB INITIATED ---", flush=True)
    repo_path = "cves_data"
    state_file = "sync_state.txt"

    changed_files, new_commit = get_git_changes()

    if not changed_files:
        print("[*] Sync process finished: No new files to inject.", flush=True)
        return

    success_count = 0
    for status, relative_path in changed_files:
        full_path = os.path.join(repo_path, relative_path)
        cve_id = os.path.basename(relative_path).replace(".json", "")

        if "delta" in cve_id.lower():
            continue

        if status in ["A", "M"]:
            try:
                if os.path.exists(full_path):
                    with open(full_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                else:
                    raw_url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/{relative_path}"
                    headers = {"User-Agent": "cve-sync-bot"}
                    token = os.environ.get("GITHUB_TOKEN")
                    if token:
                        headers["Authorization"] = f"Bearer {token}"
                    req = urllib.request.Request(raw_url, headers=headers)
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        data = json.loads(resp.read().decode())

                es.index(index="cves", id=cve_id, document=data)
                success_count += 1
            except Exception as e:
                print(f"    [!] Failed to index {cve_id}: {e}", flush=True)
        elif status == "D":
            try:
                es.delete(index="cves", id=cve_id, ignore=[404])
            except Exception:
                pass

    if new_commit:
        with open(state_file, "w") as f:
            f.write(new_commit)

    if success_count > 0:
        trigger_type = "Manual" if is_manual else "Scheduled"
        send_ntfy_alert(
            f"{trigger_type} Sync Complete: {success_count} threats updated!"
        )


@celery.task(name="app.run_backfill_task")
def run_backfill_task():
    print("\n[*] --- CELERY WORKER: BACKFILL JOB INITIATED ---", flush=True)
    backfill.run_backfill()


# --- HELPER FUNCTIONS ---
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


def get_cvss_score(data):
    containers = data.get("containers", {})
    metrics = []

    metrics.extend(containers.get("cna", {}).get("metrics", []))
    for adp in containers.get("adp", []):
        metrics.extend(adp.get("metrics", []))

    for cvss_version in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
        for metric in metrics:
            if cvss_version in metric:
                base_score = metric[cvss_version].get("baseScore", "N/A")
                base_severity = metric[cvss_version].get("baseSeverity", "N/A").upper()

                if base_severity == "N/A" and isinstance(base_score, (int, float)):
                    if base_score >= 9.0:
                        base_severity = "CRITICAL"
                    elif base_score >= 7.0:
                        base_severity = "HIGH"
                    elif base_score >= 4.0:
                        base_severity = "MEDIUM"
                    else:
                        base_severity = "LOW"

                return {
                    "score": base_score,
                    "severity": base_severity,
                    "version": cvss_version.replace("cvss", "CVSS "),
                }
    return {"score": "N/A", "severity": "UNKNOWN", "version": "N/A"}


# --- ROUTES ---
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

        cvss_data = get_cvss_score(data)

        table_data = {
            "assignerOrgId": cve_meta.get("assignerOrgId", "N/A"),
            "assignerShortName": cve_meta.get("assignerShortName", "N/A"),
            "cveId": cve_meta.get("cveId", "N/A"),
            "datePublished": cve_meta.get("datePublished", "N/A"),
            "dateReserved": cve_meta.get("dateReserved", "N/A"),
            "dateUpdated": cve_meta.get("dateUpdated", "N/A"),
            "state": cve_meta.get("state", "N/A"),
            "description": description_value,
            "cvssScore": cvss_data["score"],
            "cvssSeverity": cvss_data["severity"],
            "cvssVersion": cvss_data["version"],
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


@app.route("/api/nvd_cvss", methods=["GET"])
def get_nvd_cvss():
    cve_id = request.args.get("cve_id", "").strip().upper()
    if not cve_id:
        return jsonify({"error": "No CVE ID"}), 400

    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"User-Agent": "cve-sync-bot"}

    try:
        req = urllib.request.Request(nvd_url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return jsonify({"score": "N/A", "severity": "UNKNOWN", "version": "N/A"})

        metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})

        for cvss_version in [
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ]:
            if cvss_version in metrics:
                metric_data = metrics[cvss_version][0]
                cvss_data = metric_data.get("cvssData", {})

                base_score = cvss_data.get("baseScore", "N/A")
                base_severity = cvss_data.get(
                    "baseSeverity", metric_data.get("baseSeverity", "N/A")
                ).upper()

                return jsonify(
                    {
                        "score": base_score,
                        "severity": base_severity,
                        "version": cvss_version.replace("cvssMetric", "CVSS "),
                    }
                )

        return jsonify({"score": "N/A", "severity": "UNKNOWN", "version": "N/A"})

    except Exception as e:
        print(f"[!] NVD API Error for {cve_id}: {e}")
        return jsonify({"score": "N/A", "severity": "ERROR", "version": "N/A"})


@app.route("/api/force_sync", methods=["POST"])
def trigger_force_sync():
    """Manually triggers a delta sync and resets the countdown clock."""
    sync_updates_task.delay()
    # Reset the clock in Redis to 1 hour from now
    r_client.set("next_sync_time", str(time.time() + 3600))
    return jsonify({"status": "Delta sync dispatched to worker"}), 202


@app.route("/api/backfill/status", methods=["GET"])
def backfill_status():
    """Polls Redis for the latest worker progress."""
    data = r_client.get("backfill_status")
    if not data:
        return jsonify({"running": False, "message": "No backfill activity recorded."})

    return jsonify(json.loads(data))


@app.route("/api/backfill", methods=["POST"])
def trigger_backfill():
    """Dispatches the full database backfill task to the Celery worker."""
    # This calls the Celery task registered in your app.py
    run_backfill_task.delay()
    return jsonify({"message": "Backfill dispatched to Celery worker."}), 202


@app.route("/api/status", methods=["GET"])
def sync_status():
    """Calculates seconds remaining until the next automated sync using Redis."""
    next_sync = r_client.get("next_sync_time")

    if next_sync:
        remaining = int(float(next_sync)) - int(time.time())
        return jsonify({"seconds_remaining": max(0, remaining)})

    # If the system just booted and hasn't set a time yet, default to 1 hour
    return jsonify({"seconds_remaining": 3600})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
