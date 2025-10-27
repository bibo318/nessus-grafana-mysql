# -*- coding: utf-8 -*-
import os
import time
import logging
import urllib3

# Disable SSL warning for Nessus self-signed cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from nessus_client import NessusClient
from db import (
    db_conn, init_schema_from_file, upsert_scan, upsert_processed_history,
    already_processed, import_hosts, import_plugins_and_findings, insert_cves_for_finding
)

# Basic logging
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("nessus-sync")

POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "600"))  # Default 10 minutes
BACKFILL_ON_START = os.getenv("BACKFILL_ON_START", "true").lower() == "true"


def list_histories(scan_json):
    return scan_json.get("history", []) or scan_json.get("histories", []) or []


def process_one_history(nc: NessusClient, scan_id: int, history_id: int):
    log.info(f"Processing scan_id={scan_id}, history_id={history_id}")
    scan_json = nc.get_scan(scan_id, history_id=history_id)

    # Determine status
    status = "unknown"
    for h in list_histories(scan_json):
        if h.get("history_id") == history_id:
            status = h.get("status", "unknown")
            break

    if status != "completed":
        log.info(f"Skipping scan_id={scan_id}, history_id={history_id}, status={status}")
        return

    # 1. Save processed history info
    with db_conn() as cn:
        upsert_processed_history(
            cn,
            scan_id,
            {"history_id": history_id, "status": status, "last_modification_date": None},
            scan_json
        )

    # 2. Save hosts
    with db_conn() as cn:
        import_hosts(cn, scan_id, history_id, scan_json)

    # 3. Save plugin findings
    vulnerabilities = scan_json.get("vulnerabilities", []) or []
    with db_conn() as cn:
        import_plugins_and_findings(cn, scan_id, history_id, vulnerabilities)

    # 4. Save CVEs (if any)
    for v in vulnerabilities:
        plugin_id = int(v.get("plugin_id", 0))
        cves = nc.extract_cves_from_vuln(v)
        if cves:
            with db_conn() as cn:
                insert_cves_for_finding(
                    cn, (scan_id, history_id, plugin_id, ""), cves
                )

    log.info(f"Finished scan_id={scan_id}, history_id={history_id}")


def backfill_all(nc: NessusClient):
    log.info("Starting backfill for all past scans...")
    scans = nc.list_scans()

    # Save scan metadata
    with db_conn() as cn:
        for s in scans:
            upsert_scan(cn, s)

    # Loop through each scan & its histories
    for s in scans:
        scan_id = s.get("id")
        if not scan_id:
            continue

        meta = nc.get_scan(scan_id)
        histories = list_histories(meta)
        for h in histories:
            hid = h.get("history_id")
            if not hid:
                continue

            with db_conn() as cn:
                if already_processed(cn, scan_id, hid):
                    continue

            try:
                process_one_history(nc, scan_id, hid)
            except Exception as e:
                log.exception(f"Error while importing scan_id={scan_id}, history_id={hid}: {e}")

    log.info("Backfill completed.")


def poll_loop(nc: NessusClient):
    while True:
        log.info("Polling Nessus for new scans...")
        try:
            scans = nc.list_scans()
            with db_conn() as cn:
                for s in scans:
                    upsert_scan(cn, s)

            for s in scans:
                scan_id = s.get("id")
                if not scan_id:
                    continue

                meta = nc.get_scan(scan_id)
                for h in list_histories(meta):
                    hid = h.get("history_id")
                    if not hid or h.get("status") != "completed":
                        continue

                    with db_conn() as cn:
                        if already_processed(cn, scan_id, hid):
                            continue

                    try:
                        process_one_history(nc, scan_id, hid)
                    except Exception:
                        log.exception(f"Error importing scan_id={scan_id}, history_id={hid}")
        except Exception:
            log.exception("Unexpected error in poll loop")

        time.sleep(POLL_INTERVAL_SECONDS)


def main():
    log.info("Initializing database schema if not exists")
    init_schema_from_file("/app/schema.sql")

    nc = NessusClient()

    if BACKFILL_ON_START:
        backfill_all(nc)

    poll_loop(nc)


if __name__ == "__main__":
    main()
