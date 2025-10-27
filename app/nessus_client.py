import os
import re
from typing import Any, Dict, List, Optional

import requests
from urllib.parse import urljoin

class NessusClient:
    def __init__(self):
        self.base_url = os.getenv("NESSUS_URL", "").rstrip("/")
        self.access_key = os.getenv("NESSUS_ACCESS_KEY", "")
        self.secret_key = os.getenv("NESSUS_SECRET_KEY", "")
        self.verify_ssl = os.getenv("NESSUS_VERIFY_SSL", "false").lower() == "true"
        self.headers = {
            "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}",
            "Content-Type": "application/json",
        }

    # ===== helpers =====
    def _get(self, path, params=None, timeout=60):
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        r = requests.get(url, headers=self.headers, params=params, verify=self.verify_ssl, timeout=timeout)
        r.raise_for_status()
        return r.json()

    def _get_paginated(self, path: str, array_key: str, params: Optional[Dict[str, Any]] = None, page_size: int = 200) -> List[Any]:
        params = dict(params or {})
        limit = int(params.get("limit", page_size))
        items: List[Any] = []
        offset = int(params.get("offset", 0))

        while True:
            page_params = dict(params)
            page_params["limit"] = limit
            page_params["offset"] = offset
            data = self._get(path, params=page_params)
            chunk = data.get(array_key, [])
            if not isinstance(chunk, list):
                chunk = []

            if not chunk:
                break

            items.extend(chunk)

            total = data.get("total")
            if total is not None and len(items) >= int(total):
                break

            if len(chunk) < limit:
                break

            offset += limit

        return items

    def list_scans(self):
        # returns {scans:[{id,name,uuid,...}], ...}
        return self._get_paginated("/scans", "scans")

    def get_scan(self, scan_id, history_id=None):
        params = {}
        if history_id is not None:
            params["history_id"] = history_id
        return self._get(f"/scans/{scan_id}", params=params)

    def list_scan_hosts(self, scan_id: int, history_id: Optional[int] = None) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if history_id is not None:
            params["history_id"] = history_id
        return self._get_paginated(f"/scans/{scan_id}/hosts", "hosts", params=params)

    def list_scan_vulnerabilities(self, scan_id: int, history_id: Optional[int] = None) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if history_id is not None:
            params["history_id"] = history_id
        return self._get_paginated(f"/scans/{scan_id}/vulnerabilities", "vulnerabilities", params=params)

    def get_host_details(self, scan_id: int, host_id: int, history_id: Optional[int] = None) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if history_id is not None:
            params["history_id"] = history_id
        return self._get(f"/scans/{scan_id}/hosts/{host_id}", params=params)

    def get_host_plugin_outputs(self, scan_id: int, host_id: int, plugin_id: int, history_id: Optional[int] = None) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if history_id is not None:
            params["history_id"] = history_id

        data = self._get(f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}", params=params)
        outputs: List[Dict[str, Any]] = []

        def _build_output(entry: Dict[str, Any], base: Dict[str, Any]) -> Dict[str, Any]:
            normalized: Dict[str, Any] = {
                "port": entry.get("port"),
                "protocol": entry.get("protocol"),
                "svc_name": entry.get("svc_name") or entry.get("service"),
                "severity": entry.get("severity") or entry.get("severity_id"),
                "state": entry.get("state"),
                "plugin_output": entry.get("plugin_output") or base.get("plugin_output") or "",
                "first_found": entry.get("first_found") or base.get("first_found"),
                "last_found": entry.get("last_found") or base.get("last_found"),
            }
            if "hostname" in entry:
                normalized["hostname"] = entry.get("hostname")
            if "host_id" in entry:
                normalized["host_id"] = entry.get("host_id")
            if "uuid" in entry:
                normalized["uuid"] = entry.get("uuid")
            return normalized

        for output in data.get("outputs", []) or []:
            if not isinstance(output, dict):
                continue
            base_output = {
                "plugin_output": output.get("plugin_output") or "",
                "first_found": output.get("first_found"),
                "last_found": output.get("last_found"),
            }

            hosts_data = output.get("hosts") if isinstance(output.get("hosts"), list) else []
            ports_data = output.get("ports") if isinstance(output.get("ports"), list) else []

            if hosts_data:
                for host_entry in hosts_data:
                    if isinstance(host_entry, dict):
                        outputs.append(_build_output(host_entry, base_output))
                continue

            if ports_data:
                for port_entry in ports_data:
                    if isinstance(port_entry, dict):
                        outputs.append(_build_output(port_entry, base_output))
                continue

            outputs.append(_build_output(output, base_output))

        return outputs

    # Attempt to extract CVEs from a vulnerability dict using common fields
    CVE_REGEX = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)

    def extract_cves_from_vuln(self, vuln: dict):
        cves = set()

        # Common fields sometimes used
        for key in ("cve", "cves"):
            val = vuln.get(key)
            if isinstance(val, list):
                for x in val:
                    if isinstance(x, str) and self.CVE_REGEX.search(x):
                        cves.add(self.CVE_REGEX.search(x).group(1).upper())
            elif isinstance(val, str):
                for m in self.CVE_REGEX.findall(val):
                    cves.add(m.upper())

        # xref may contain CVE strings
        for key in ("xref", "see_also", "seealso"):
            val = vuln.get(key)
            if isinstance(val, list):
                for x in val:
                    if isinstance(x, str):
                        for m in self.CVE_REGEX.findall(x):
                            cves.add(m.upper())
            elif isinstance(val, str):
                for m in self.CVE_REGEX.findall(val):
                    cves.add(m.upper())

        # Sometimes present inside plugin_output/description/synopsis
        for key in ("plugin_output", "description", "synopsis"):
            val = vuln.get(key)
            if isinstance(val, str):
                for m in self.CVE_REGEX.findall(val):
                    cves.add(m.upper())

        return list(sorted(cves))

