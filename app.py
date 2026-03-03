import os
import json
import threading
import urllib.request
import logging
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify
from elasticsearch import Elasticsearch
from apscheduler.schedulers.background import BackgroundScheduler

# Silence the Flask/Werkzeug terminal spam so we only see real logs
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)

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
GITHUB_API = "https://api.github.com/repos/CVEProject/cvelistV5"


def _github_get(url):
    """Make a GitHub API GET request with Rate Limit Token. Returns parsed JSON."""
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "cve-sync-bot"}

    # Inject the token from your .env file to boost limit to 5000/hr
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

        print("[*] Checking GitHub for latest commit (via API)...", flush=True)
        data = _github_get(f"{GITHUB_API}/commits/main")
        current_commit = data["sha"]

        if not last_commit:
            with open(state_file, "w") as f:
                f.write(current_commit)
            print(
                f"[*] Initialized sync state at commit: {current_commit[:7]}",
                flush=True,
            )
            return [], current_commit

        if last_commit == current_commit:
            print("[*] No new commits on GitHub. Database is up to date.", flush=True)
            return [], current_commit

        print(
            f"[*] New commits detected! Comparing {last_commit[:7]}...{current_commit[:7]}",
            flush=True,
        )

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

        print(f"[*] Found {len(changes)} modified CVE files to sync.", flush=True)
        return changes, current_commit

    except Exception as e:
        print(f"[!] GITHUB API ERROR: {str(e)}", flush=True)
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
    database_errors = False

    for status, relative_path in changed_files:
        full_path = os.path.join(repo_path, relative_path)
        cve_id = os.path.basename(relative_path).replace(".json", "")

        # Skip non-threat files
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
                print(f"    [+] Updated {cve_id}", flush=True)
                success_count += 1
            except Exception as e:
                print(f"    [!] Failed to index {cve_id}: {e}", flush=True)
                database_errors = True
        elif status == "D":
            try:
                es.delete(index="cves", id=cve_id, ignore=[404])
                print(f"    [-] Removed {cve_id}", flush=True)
            except Exception:
                database_errors = True

    # STRICT CHECK: Only move the bookmark if the database successfully swallowed everything
    if new_commit and not database_errors:
        with open(state_file, "w") as f:
            f.write(new_commit)
        print(
            f"[*] Updated persistent sync state to commit: {new_commit[:7]}", flush=True
        )
    elif new_commit and database_errors:
        print(
            "[!] Sync aborted due to database errors. Bookmark NOT updated. Will retry next cycle.",
            flush=True,
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
    misfire_grace_time=900,  # Gives the worker 15 minutes of grace if the server is busy
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


def get_cvss_score(data):
    """Safely extracts the highest priority CVSS score from a CVE JSON V5 record."""
    containers = data.get("containers", {})
    metrics = []

    # 1. Grab metrics from the original reporter (CNA)
    metrics.extend(containers.get("cna", {}).get("metrics", []))

    # 2. Grab enriched metrics from authorized publishers (ADP, e.g., NVD)
    for adp in containers.get("adp", []):
        metrics.extend(adp.get("metrics", []))

    # 3. Search for scores in order of modern relevance
    for cvss_version in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
        for metric in metrics:
            if cvss_version in metric:
                base_score = metric[cvss_version].get("baseScore", "N/A")
                base_severity = metric[cvss_version].get("baseSeverity", "N/A").upper()

                # Fallback: Older CVSS V2 records sometimes lack an explicit 'baseSeverity' string
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


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/nvd_cvss", methods=["GET"])
def get_nvd_cvss():
    """Fallback route that explicitly queries the NVD API for missing CVSS scores."""
    cve_id = request.args.get("cve_id", "").strip().upper()
    if not cve_id:
        return jsonify({"error": "No CVE ID"}), 400

    # Official NVD API 2.0 Endpoint
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"User-Agent": "cve-sync-bot"}

    try:
        req = urllib.request.Request(nvd_url, headers=headers)
        # 10-second timeout so the background thread doesn't hang forever
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return jsonify({"score": "N/A", "severity": "UNKNOWN", "version": "N/A"})

        metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})

        # Search the NVD payload for the newest scoring standard
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
                # V3/V4 store severity inside cvssData, V2 stores it outside. We check both.
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
