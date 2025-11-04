import os
import json
import hashlib
import mysql.connector
from contextlib import contextmanager
from typing import Iterable, Optional, Any

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

def _first_present(values: Iterable[Any]) -> Optional[Any]:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            candidate = value.strip()
            if not candidate:
                continue
            return candidate
        return value
    return None


def _coerce_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int,)):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return default


def _coerce_optional_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None


def _coerce_optional_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            return float(stripped)
        except ValueError:
            return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_to_string(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if isinstance(value, (list, tuple, set)):
        parts = []
        for item in value:
            if item is None:
                continue
            if isinstance(item, str):
                item_text = item.strip()
                if item_text:
                    parts.append(item_text)
            else:
                parts.append(str(item))
        if parts:
            return "; ".join(parts)
        return None
    return str(value)


def _extract_count(host: dict, *keys: str) -> int:
    for key in keys:
        if key in host:
            return _coerce_int(host.get(key))
    return 0


def upsert_host_record(cn, scan_id: int, history_id: int, host: dict):
    """Insert/update a single host entry with normalised fields."""
    if not isinstance(host, dict):
        return

    host_id_raw = _first_present((host.get("host_id"), host.get("id")))
    if host_id_raw is None:
        return

    try:
        host_id = int(host_id_raw)
    except (TypeError, ValueError):
        return

    hostname = _first_present(
        (
            host.get("hostname"),
            host.get("host"),
            host.get("name"),
            host.get("fqdn"),
            host.get("ipaddress"),
            host.get("ip_address"),
        )
    )

    ip_address = _first_present(
        (
            host.get("ip_address"),
            host.get("ip"),
            host.get("host-ip"),
            host.get("ipv4"),
            host.get("host-ipv4"),
            host.get("ipaddress"),
        )
    )

    operating_system = _first_present(
        (
            host.get("operating_system"),
            host.get("operating-system"),
            host.get("os"),
            host.get("system_type"),
        )
    )

    critical = _extract_count(host, "critical", "critical_count", "severity_critical")
    high = _extract_count(host, "high", "high_count", "severity_high")
    medium = _extract_count(host, "medium", "medium_count", "severity_medium")
    low = _extract_count(host, "low", "low_count", "severity_low")
    info = _extract_count(host, "info", "info_count", "severity_info", "informational", "informational_count")

    cur = cn.cursor()
    cur.execute("""
        INSERT INTO hosts (
          scan_id, history_id, host_id, hostname, ip_address, operating_system,
          critical, high, medium, low, info
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE
          hostname=VALUES(hostname),
          ip_address=VALUES(ip_address),
          operating_system=VALUES(operating_system),
          critical=VALUES(critical),
          high=VALUES(high),
          medium=VALUES(medium),
          low=VALUES(low),
          info=VALUES(info)
    """, (
        scan_id,
        history_id,
        host_id,
        hostname,
        ip_address,
        operating_system,
        critical,
        high,
        medium,
        low,
        info,
    ))


def import_hosts(cn, scan_id, history_id, scan_json):
    for h in scan_json.get("hosts", []) or []:
        upsert_host_record(cn, scan_id, history_id, h)
    cn.commit()

def import_plugins_and_findings(cn, scan_id, history_id, vuln_items):
    cur = cn.cursor()
    for v in vuln_items:
        plugin_id = v.get("plugin_id")
        if plugin_id is None:
            continue
        plugin_id = int(plugin_id)
        plugin_name = v.get("plugin_name") or ""
        plugin_family = v.get("plugin_family") or ""
        plugin_type = _first_present((v.get("plugin_type"), v.get("type")))
        plugin_version = _first_present((v.get("plugin_version"), v.get("version")))
        risk_factor = _first_present((v.get("risk_factor"), v.get("riskfactor")))
        synopsis = _normalize_to_string(v.get("synopsis"))
        description = _normalize_to_string(v.get("description"))
        solution = _normalize_to_string(v.get("solution"))
        see_also = _normalize_to_string(
            _first_present((v.get("see_also"), v.get("seealso"), v.get("see also")))
        )
        plugin_publication_date = _coerce_optional_int(
            _first_present((v.get("plugin_publication_date"), v.get("publication_date")))
        )
        plugin_modification_date = _coerce_optional_int(
            _first_present((v.get("plugin_modification_date"), v.get("modification_date")))
        )
        vulnerability_publication_date = _coerce_optional_int(
            _first_present((v.get("vulnerability_publication_date"), v.get("vuln_publication_date")))
        )
        cwe = _normalize_to_string(v.get("cwe"))
        cvss2_base_score = _coerce_optional_float(
            _first_present((v.get("cvss_base_score"), v.get("cvss2_base_score")))
        )
        cvss2_vector = _normalize_to_string(
            _first_present((v.get("cvss_vector"), v.get("cvss2_vector")))
        )
        cvss3_base_score = _coerce_optional_float(
            _first_present((v.get("cvss3_base_score"), v.get("cvssv3_base_score")))
        )
        cvss3_vector = _normalize_to_string(
            _first_present((v.get("cvss3_vector"), v.get("cvssv3_vector")))
        )
        vpr_drivers_raw = v.get("vpr_drivers") or v.get("vpr_key_drivers")
        vpr_drivers = json.dumps(vpr_drivers_raw, ensure_ascii=False) if vpr_drivers_raw else None

        severity = int(v.get("severity", 0))
        count = int(v.get("count", 0))
        cpe = v.get("cpe")
        if isinstance(cpe, list):
            cpe = ",".join(filter(None, map(str, cpe)))
        vpr = v.get("vpr_score")
        epss = v.get("epss_score")
        offline = 1 if v.get("offline") else 0

        # upsert plugin
        cur.execute("""
            INSERT INTO plugins (
              plugin_id, plugin_name, plugin_family, plugin_type, plugin_version, risk_factor,
              synopsis, description, solution, see_also,
              plugin_publication_date, plugin_modification_date, vulnerability_publication_date,
              cwe, cvss2_base_score, cvss2_vector, cvss3_base_score, cvss3_vector, vpr_drivers
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
              plugin_name=VALUES(plugin_name),
              plugin_family=VALUES(plugin_family),
              plugin_type=VALUES(plugin_type),
              plugin_version=VALUES(plugin_version),
              risk_factor=VALUES(risk_factor),
              synopsis=VALUES(synopsis),
              description=VALUES(description),
              solution=VALUES(solution),
              see_also=VALUES(see_also),
              plugin_publication_date=VALUES(plugin_publication_date),
              plugin_modification_date=VALUES(plugin_modification_date),
              vulnerability_publication_date=VALUES(vulnerability_publication_date),
              cwe=VALUES(cwe),
              cvss2_base_score=VALUES(cvss2_base_score),
              cvss2_vector=VALUES(cvss2_vector),
              cvss3_base_score=VALUES(cvss3_base_score),
              cvss3_vector=VALUES(cvss3_vector),
              vpr_drivers=VALUES(vpr_drivers)
        """, (
            plugin_id,
            plugin_name,
            plugin_family,
            plugin_type,
            plugin_version,
            risk_factor,
            synopsis,
            description,
            solution,
            see_also,
            plugin_publication_date,
            plugin_modification_date,
            vulnerability_publication_date,
            cwe,
            cvss2_base_score,
            cvss2_vector,
            cvss3_base_score,
            cvss3_vector,
            vpr_drivers,
        ))

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


def import_host_findings(cn, scan_id, history_id, host_summary, host_vuln_outputs):
    """Persist chi tiết plugin theo host.

    host_vuln_outputs: iterable các tuple (vuln_dict, outputs_list)
    """
    cur = cn.cursor()
    host_id = host_summary.get("host_id")
    hostname = host_summary.get("hostname") or host_summary.get("host")

    for vuln, outputs in host_vuln_outputs:
        plugin_id = vuln.get("plugin_id")
        if plugin_id is None:
            continue
        plugin_id = int(plugin_id)
        severity = int(vuln.get("severity", 0))
        outputs = outputs or []
        count = int(vuln.get("count") or 0)
        if not count:
            count = len(outputs)

        # Aggregate finding cho host cụ thể (hostname != NULL)
        cur.execute("""
            INSERT INTO findings (scan_id, history_id, plugin_id, hostname, severity, count, cpe, vpr_score, epss_score, offline)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
              severity=VALUES(severity), count=VALUES(count)
        """, (scan_id, history_id, plugin_id, hostname, severity, count, None, None, None, 0))

        if not outputs:
            continue

        for detail in outputs:
            port = detail.get("port")
            protocol = detail.get("protocol")
            svc_name = detail.get("svc_name")
            state = detail.get("state")
            plugin_output = detail.get("plugin_output") or ""
            severity_override = detail.get("severity")
            first_found = detail.get("first_found")
            last_found = detail.get("last_found")

            severity_for_record = severity_override if severity_override is not None else severity

            hash_source = "|".join(
                str(x) for x in (
                    scan_id,
                    history_id,
                    host_id,
                    plugin_id,
                    port,
                    protocol or "",
                    svc_name or "",
                    plugin_output
                )
            )
            output_hash = hashlib.sha1(hash_source.encode("utf-8", errors="ignore")).hexdigest()

            cur.execute("""
                INSERT INTO host_findings (
                  scan_id, history_id, host_id, hostname, plugin_id, port, protocol,
                  svc_name, severity, state, output_hash, plugin_output, first_found, last_found
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                  severity=VALUES(severity), state=VALUES(state), plugin_output=VALUES(plugin_output),
                  first_found=VALUES(first_found), last_found=VALUES(last_found)
            """, (
                scan_id,
                history_id,
                host_id,
                hostname,
                plugin_id,
                port,
                protocol,
                svc_name,
                severity_for_record,
                state,
                output_hash,
                plugin_output,
                first_found,
                last_found,
            ))

    cn.commit()

