import os
import re
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

    def list_scans(self):
        # returns {scans:[{id,name,uuid,...}], ...}
        return self._get("/scans").get("scans", [])

    def get_scan(self, scan_id, history_id=None):
        params = {}
        if history_id is not None:
            params["history_id"] = history_id
        return self._get(f"/scans/{scan_id}", params=params)

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

