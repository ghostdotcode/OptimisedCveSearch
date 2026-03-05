import os
import json
import logging
import redis
from elasticsearch import Elasticsearch, helpers

logging.basicConfig(level=logging.INFO, format="[*] %(message)s")
logging.getLogger("elasticsearch").setLevel(logging.WARNING)
logging.getLogger("elastic_transport").setLevel(logging.WARNING)

r = redis.Redis(host="redis", port=6379, db=0)


def update_redis_status(stats, running=True, done=False):
    """Pushes current progress into Redis for the Web UI to read."""
    status_data = {
        "running": running,
        "indexed": stats["indexed"],
        "skipped": stats["skipped"],
        "failed": stats["failed"],
        "total_found": stats["total_found"],
        "done": done,
    }
    r.set("backfill_status", json.dumps(status_data))


def _cve_generator(cves_dir: str, es: Elasticsearch, index_name: str, stats: dict):
    """Generator that lazily yields ES docs and heartbeats progress."""
    for root, _, files in os.walk(cves_dir):
        for filename in files:
            if not (filename.startswith("CVE-") and filename.endswith(".json")):
                continue

            stats["total_found"] += 1
            file_path = os.path.join(root, filename)
            cve_id = filename[:-5]

            # HEARTBEAT FIX: Update UI every 1,000 files scanned, regardless of outcome
            if stats["total_found"] % 1000 == 0:
                update_redis_status(stats)
                logging.info(
                    f"Progress — indexed: {stats['indexed']} | skipped: {stats['skipped']} | failed: {stats['failed']}"
                )

            # Idempotency check
            try:
                if es.exists(index=index_name, id=cve_id):
                    stats["skipped"] += 1
                    continue
            except Exception as e:
                logging.error(f"ES exists-check failed for {cve_id}: {e}")
                stats["failed"] += 1
                continue

            # Per-file JSON parse
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logging.error(f"Skipping corrupt file {file_path}: {e}")
                stats["failed"] += 1
                continue

            yield {"_index": index_name, "_id": cve_id, "_source": data}


def run_backfill():
    """Entry point called by Celery worker."""
    logging.info("===== BACKFILL STARTED =====")
    index_name = "cves"
    cves_dir = os.path.join("cves_data", "cves")

    if not os.path.exists(cves_dir):
        logging.error(f"BACKFILL ABORTED: directory not found: {cves_dir}")
        return

    es = Elasticsearch("http://elasticsearch:9200")
    stats = {"indexed": 0, "skipped": 0, "failed": 0, "total_found": 0}

    update_redis_status(stats)
    gen = _cve_generator(cves_dir, es, index_name, stats)

    try:
        # The consumer loop only handles actual database insertion now
        for ok, info in helpers.streaming_bulk(
            es, gen, chunk_size=500, raise_on_error=False, raise_on_exception=False
        ):
            if ok:
                stats["indexed"] += 1
            else:
                err_info = info.get("index", info)
                cve_id = err_info.get("_id", "unknown")
                reason = err_info.get("error", {}).get("reason", "unknown reason")
                logging.error(f"ES rejected {cve_id}: {reason}")
                stats["failed"] += 1

    except Exception as e:
        logging.error(f"BACKFILL FATAL ERROR: {e}")
    finally:
        update_redis_status(stats, running=False, done=True)
        logging.info(
            f"===== BACKFILL COMPLETE ===== indexed: {stats['indexed']} | "
            f"skipped: {stats['skipped']} | failed: {stats['failed']}"
        )


if __name__ == "__main__":
    run_backfill()
