import os
import mysql.connector
from contextlib import contextmanager

MYSQL_HOST = os.getenv("MYSQL_HOST", "mysql")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_USER = os.getenv("MYSQL_USER", "grafana")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "grafana123")
MYSQL_DB = os.getenv("MYSQL_DB", "nessus_data")

@contextmanager
def db_conn():
    cn = mysql.connector.connect(
        host=MYSQL_HOST, port=MYSQL_PORT, user=MYSQL_USER,
        password=MYSQL_PASSWORD, database=MYSQL_DB
    )
    try:
        yield cn
    finally:
        cn.close()

def init_schema_from_file(path="/app/schema.sql"):
    with db_conn() as cn, open(path, "r", encoding="utf-8") as f:
        cur = cn.cursor()
        for statement in f.read().split(";"):
            stmt = statement.strip()
            if stmt:
                cur.execute(stmt)
        cn.commit()

def upsert_scan(cn, s):
    cur = cn.cursor()
    cur.execute("""
        INSERT INTO scans (scan_id, name, uuid, targets, folder_id, last_seen)
        VALUES (%s,%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE
          name=VALUES(name), uuid=VALUES(uuid), targets=VALUES(targets),
          folder_id=VALUES(folder_id), last_seen=VALUES(last_seen)
    """, (s.get("id"), s.get("name"), s.get("uuid"), s.get("targets") or "", s.get("folder_id"), s.get("last_modification_date")))
    cn.commit()

def upsert_processed_history(cn, scan_id, history, scan_json):
    cur = cn.cursor()
    info = scan_json.get("info", {})
    targets = info.get("targets") or ""
    scan_uuid = info.get("uuid") or ""
    scan_name = info.get("name") or ""
    status = history.get("status")
    scan_start = info.get("scan_start")
    scan_end = info.get("scan_end")
    last_mod = history.get("last_modification_date")
    cur.execute("""
        INSERT INTO processed_history
          (scan_id, history_id, scan_uuid, scan_name, targets, status, scan_start, scan_end, last_modification)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE
          scan_uuid=VALUES(scan_uuid), scan_name=VALUES(scan_name), targets=VALUES(targets),
          status=VALUES(status), scan_start=VALUES(scan_start), scan_end=VALUES(scan_end),
          last_modification=VALUES(last_modification)
    """, (scan_id, history.get("history_id"), scan_uuid, scan_name, targets, status, scan_start, scan_end, last_mod))
    cn.commit()

def already_processed(cn, scan_id, history_id):
    cur = cn.cursor()
    cur.execute("SELECT 1 FROM processed_history WHERE scan_id=%s AND history_id=%s LIMIT 1", (scan_id, history_id))
    return cur.fetchone() is not None

def import_hosts(cn, scan_id, history_id, scan_json):
    cur = cn.cursor()
    for h in scan_json.get("hosts", []):
        cur.execute("""
            INSERT INTO hosts (scan_id, history_id, host_id, hostname, critical, high, medium, low, info)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
              hostname=VALUES(hostname), critical=VALUES(critical), high=VALUES(high),
              medium=VALUES(medium), low=VALUES(low), info=VALUES(info)
        """, (
            scan_id, history_id, h.get("host_id"), h.get("hostname"),
            h.get("critical",0), h.get("high",0), h.get("medium",0), h.get("low",0), h.get("info",0)
        ))
    cn.commit()

def import_plugins_and_findings(cn, scan_id, history_id, vuln_items):
    cur = cn.cursor()
    for v in vuln_items:
        plugin_id = int(v.get("plugin_id"))
        plugin_name = v.get("plugin_name") or ""
        plugin_family = v.get("plugin_family") or ""
        severity = int(v.get("severity", 0))
        count = int(v.get("count", 0))
        cpe = v.get("cpe")
        vpr = v.get("vpr_score")
        epss = v.get("epss_score")
        offline = 1 if v.get("offline") else 0

        # upsert plugin
        cur.execute("""
            INSERT INTO plugins (plugin_id, plugin_name, plugin_family)
            VALUES (%s,%s,%s)
            ON DUPLICATE KEY UPDATE
              plugin_name=VALUES(plugin_name), plugin_family=VALUES(plugin_family)
        """, (plugin_id, plugin_name, plugin_family))

        # upsert finding (aggregate by plugin, hostname NULL)
        cur.execute("""
            INSERT INTO findings (scan_id, history_id, plugin_id, hostname, severity, count, cpe, vpr_score, epss_score, offline)
            VALUES (%s,%s,%s,NULL,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
              severity=VALUES(severity), count=VALUES(count),
              cpe=VALUES(cpe), vpr_score=VALUES(vpr_score), epss_score=VALUES(epss_score), offline=VALUES(offline)
        """, (scan_id, history_id, plugin_id, severity, count, cpe, vpr, epss, offline))
    cn.commit()

def insert_cves_for_finding(cn, finding_key_tuple, cve_list):
    """finding_key_tuple = (scan_id, history_id, plugin_id, hostname or '')"""
    if not cve_list:
        return
    cur = cn.cursor()
    # Lấy id của finding
    cur.execute("""
      SELECT id FROM findings
      WHERE scan_id=%s AND history_id=%s AND plugin_id=%s AND IFNULL(hostname,'')=%s
      LIMIT 1
    """, finding_key_tuple)
    row = cur.fetchone()
    if not row:
        return
    finding_id = row[0]

    for cve in cve_list:
        # insert CVE catalog nếu chưa có
        cur.execute("""
          INSERT INTO cves (cve_id) VALUES (%s)
          ON DUPLICATE KEY UPDATE cve_id=cve_id
        """, (cve,))
        # link finding ↔ CVE
        cur.execute("""
          INSERT IGNORE INTO finding_cves (finding_id, cve_id)
          VALUES (%s, %s)
        """, (finding_id, cve))
    cn.commit()

