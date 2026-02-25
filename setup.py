import os
import subprocess
from elasticsearch import Elasticsearch


def configure_elasticsearch():
    print("[*] Connecting to local Elasticsearch engine...")
    es = Elasticsearch("http://localhost:9200")

    index_name = "cves"

    try:
        # EAFP: We just try to create it blindly.
        es.indices.create(
            index=index_name, settings={"index.mapping.total_fields.limit": 5000}
        )
        print(f"[*] Successfully created index '{index_name}' with 5000 field limit.")
    except Exception as e:
        # If it fails, we check if it's just because it already exists
        if "resource_already_exists_exception" in str(e):
            print(f"[*] Index '{index_name}' already exists.")
        else:
            print(f"[!] Unexpected database error: {e}")


def clone_cve_repository():
    target_dir = "cves_data"
    repo_url = "https://github.com/CVEProject/cvelistV5.git"

    if os.path.exists(target_dir):
        print(f"[*] Directory '{target_dir}' already exists. Skipping clone.")
        return

    print(f"[*] Starting shallow clone of {repo_url}...")
    print("[*] Downloading ~250,000 files. This may take a minute or two...")

    try:
        # We use subprocess to trigger the system's Git installation
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, target_dir], check=True
        )
        print("[*] Repository cloned successfully into 'cves_data'!")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error cloning repository: {e}")
        print("[!] Ensure you have Git installed on your Windows machine.")


if __name__ == "__main__":
    print("=== OptimisedCveSearch: Phase 1 Initialization ===\n")
    configure_elasticsearch()
    print("-" * 50)
    clone_cve_repository()
    print("\n=== Setup Complete ===")
