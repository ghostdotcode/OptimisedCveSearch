import os
import json


def extract_all_keys(data, parent_key=""):
    """
    Recursively flattens a JSON object and extracts unique dot-notation keys.
    """
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


def build_master_template():
    # The folder we just cloned
    cves_dir = os.path.join("cves_data", "cves")

    if not os.path.exists(cves_dir):
        print(f"[!] Cannot find {cves_dir}. Did the Git clone finish correctly?")
        return

    master_template = set()
    file_count = 0

    print("[*] Starting Phase 2: Mass Schema Traversal...")
    print("[*] Scanning ~250,000 files. This will take a few minutes.\n")

    # os.walk is highly efficient for digging through nested folders
    for root, _, files in os.walk(cves_dir):
        for file in files:
            if file.endswith(".json") and file.startswith("CVE-"):
                file_path = os.path.join(root, file)

                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        file_keys = extract_all_keys(data)
                        master_template.update(file_keys)

                        file_count += 1
                        # Progress indicator so you know it hasn't crashed
                        if file_count % 10000 == 0:
                            print(f"    ... processed {file_count} files ...")
                except Exception as e:
                    print(f"[!] Error reading {file_path}: {e}")

    print(f"\n[*] Scan complete! Processed {file_count} valid CVE files.")

    # Save the final deduplicated set to a JSON file
    sorted_keys = sorted(list(master_template))
    output_file = "master_template.json"

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(sorted_keys, f, indent=4)

    print(f"[*] Schema generated successfully!")
    print(
        f"[*] Found {len(sorted_keys)} perfectly unique keys across 25 years of data."
    )
    print(f"[*] Saved to -> {output_file}")


if __name__ == "__main__":
    build_master_template()
