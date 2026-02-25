import os
import json
from elasticsearch import Elasticsearch, helpers


def generate_bulk_actions(cves_dir, index_name):
    """
    A Python Generator that yields Elasticsearch bulk actions one by one.
    Generators are memory-safe because they don't load everything into RAM at once!
    """
    for root, _, files in os.walk(cves_dir):
        for file in files:
            if file.endswith(".json") and file.startswith("CVE-"):
                file_path = os.path.join(root, file)

                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)

                        # The CVE ID (e.g., "CVE-2024-0005") becomes the exact Database ID
                        cve_id = file.replace(".json", "")

                        # Yield the specific format Elasticsearch Bulk API demands
                        yield {"_index": index_name, "_id": cve_id, "_source": data}
                except Exception as e:
                    print(f"[!] Corrupt or unreadable file {file_path}: {e}")


def pump_data_to_elastic():
    print("[*] Connecting to Elasticsearch...")
    es = Elasticsearch("http://localhost:9200")
    index_name = "cves"
    cves_dir = os.path.join("cves_data", "cves")

    if not os.path.exists(cves_dir):
        print(f"[!] Cannot find {cves_dir}. Exiting.")
        return

    print("[*] Starting Phase 3: Bulk Data Pump...")
    print(
        f"[*] Streaming data from '{cves_dir}' into Elasticsearch index '{index_name}'..."
    )
    print("[*] Pumping in batches of 1000. Sit tight...")

    try:
        # We drop stats_only=True and add the fault tolerance flags
        success_count, failed_items = helpers.bulk(
            es,
            generate_bulk_actions(cves_dir, index_name),
            chunk_size=1000,
            raise_on_error=False,  # <--- The Fault Tolerance Switch
            raise_on_exception=False,  # <--- Ignore generator hiccups
        )

        print("\n" + "=" * 50)
        print("[*] DATA PUMP COMPLETE!")
        print(f"[*] Successfully indexed: {success_count} CVEs")

        if failed_items:
            print(f"[!] Skipped/Failed to index: {len(failed_items)} CVEs")
            print("[*] Debugging the first 3 failures:")
            # This will tell us EXACTLY which files are corrupted and why
            for err in failed_items[:3]:
                err_data = err.get("index", {})
                cve_id = err_data.get("_id", "Unknown ID")
                reason = err_data.get("error", {}).get("reason", "Unknown reason")
                print(f"    -> {cve_id}: {reason}")

        print("=" * 50 + "\n")

    except Exception as e:
        print(f"\n[!] Fatal error during bulk upload: {e}")


if __name__ == "__main__":
    pump_data_to_elastic()
