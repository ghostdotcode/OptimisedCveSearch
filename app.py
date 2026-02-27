import os
import json
from flask import Flask, render_template, request, jsonify
from elasticsearch import Elasticsearch

app = Flask(__name__)
es = Elasticsearch("http://elasticsearch:9200")

# Load the master template once when the server starts
MASTER_TEMPLATE = set()
if os.path.exists("master_template.json"):
    with open("master_template.json", "r", encoding="utf-8") as f:
        MASTER_TEMPLATE = set(json.load(f))


def extract_all_keys(data, parent_key=""):
    """Recursively flattens JSON to find existing keys (reused from your schema builder)"""
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
    # This will serve our modern UI HTML file
    return render_template("index.html")


@app.route("/api/search", methods=["GET"])
def search_cve():
    cve_id = request.args.get("cve_id", "").strip().upper()
    if not cve_id:
        return jsonify({"error": "No CVE ID provided"}), 400

    try:
        # 1. Query Elasticsearch
        res = es.get(index="cves", id=cve_id)
        data = res["_source"]

        # 2. Build the exact Table Data you requested
        cve_meta = data.get("cveMetadata", {})

        # Extract the English description (safely navigating the CVE v5 schema)
        description_value = "No English description available."
        descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [])
        for desc in descriptions:
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

        # 3. Build the Full JSON string with NAs appended at the bottom
        populated_keys = extract_all_keys(data)
        missing_keys = MASTER_TEMPLATE - populated_keys

        json_output = json.dumps(data, indent=2)
        json_output += "\n\n" + "=" * 60 + "\n"
        json_output += "                 MISSING DATA (NA FIELDS)\n"
        json_output += "=" * 60 + "\n\n"

        for mk in sorted(missing_keys):
            json_output += f'"{mk}": "NA"\n'

        # Send both views back to the frontend
        return jsonify({"table_data": table_data, "full_json": json_output})

    except Exception as e:
        return jsonify(
            {"error": f"{cve_id} not found in local database. Check ID and try again."}
        ), 404


if __name__ == "__main__":
    # Run the Flask server on port 5000
    app.run(host="0.0.0.0", port=5000, debug=True)
