"""
Django management command to recover scan data from result files on disk.

Usage:
    # Dry-run (inspect only, no DB writes):
    python manage.py recover_scan_results

    # Apply — actually write recovered records to the database:
    python manage.py recover_scan_results --apply

    # Limit to one scan folder for testing:
    python manage.py recover_scan_results --apply --scan-dir /usr/src/scan_results/defijn.io_108

What is recovered (when the files exist):
    - Domain              (targetApp.models.Domain)
    - ScanHistory         (startScan.models.ScanHistory)
    - Subdomain           (from *_subdomain_discovery.txt, subdomains_*.txt)
    - IpAddress + Port    (from *_port_scan.txt — naabu JSON format)
    - EndPoint            (from *_fetch_url.txt, urls_*.txt)
    - Vulnerability       (from *_nmap_vulns.json, *_nuclei_*.txt)
    - Waf                 (from *_waf_detection.txt)

Recovery is non-destructive:
    - Records that already exist in the DB are left untouched.
    - Scan folders whose results_dir already matches a ScanHistory are skipped.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone as django_tz

logger = logging.getLogger(__name__)

SCAN_RESULTS_ROOT = "/usr/src/scan_results"

SEVERITY_MAP = {
    "unknown": -1,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class Command(BaseCommand):
    help = "Recover scan data from result files on disk into the database."

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply",
            action="store_true",
            default=False,
            help="Write recovered records to the database (default is dry-run).",
        )
        parser.add_argument(
            "--scan-dir",
            default=None,
            help="Recover only this single scan directory (absolute path).",
        )
        parser.add_argument(
            "--results-root",
            default=SCAN_RESULTS_ROOT,
            help=f"Root directory containing scan result folders (default: {SCAN_RESULTS_ROOT}).",
        )

    def handle(self, *args, **options):
        apply = options["apply"]
        results_root = options["results_root"]
        single_dir = options["scan_dir"]

        if not apply:
            self.stdout.write(
                self.style.WARNING(
                    "DRY-RUN mode — no database writes. Pass --apply to recover data."
                )
            )

        # Lazy imports so Django is fully set up before model imports
        from targetApp.models import Domain
        from startScan.models import (
            ScanHistory,
            Subdomain,
            EndPoint,
            Vulnerability,
            IpAddress,
            Port,
            Waf,
            CveId,
            CweId,
            VulnerabilityTags,
            VulnerabilityReference,
        )
        from scanEngine.models import EngineType

        self._models = dict(
            Domain=Domain,
            ScanHistory=ScanHistory,
            Subdomain=Subdomain,
            EndPoint=EndPoint,
            Vulnerability=Vulnerability,
            IpAddress=IpAddress,
            Port=Port,
            Waf=Waf,
            CveId=CveId,
            CweId=CweId,
            VulnerabilityTags=VulnerabilityTags,
            VulnerabilityReference=VulnerabilityReference,
            EngineType=EngineType,
        )
        self._apply = apply

        # Build set of results_dirs already tracked in the DB
        existing_dirs = set(
            ScanHistory.objects.exclude(results_dir="")
            .exclude(results_dir=None)
            .values_list("results_dir", flat=True)
        )

        if single_dir:
            candidates = [single_dir]
        else:
            candidates = self._find_scan_dirs(results_root)

        totals = dict(
            scans=0, skipped=0, domains=0, subdomains=0,
            endpoints=0, ports=0, vulns=0, wafs=0
        )

        for scan_dir in sorted(candidates):
            result = self._recover_scan(scan_dir, existing_dirs)
            if result is None:
                totals["skipped"] += 1
            else:
                for k, v in result.items():
                    totals[k] = totals.get(k, 0) + v
                totals["scans"] += 1

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("=== Recovery Summary ==="))
        self.stdout.write(f"  Scan folders processed : {totals['scans']}")
        self.stdout.write(f"  Scan folders skipped   : {totals['skipped']}")
        self.stdout.write(f"  Domains recovered      : {totals['domains']}")
        self.stdout.write(f"  Subdomains recovered   : {totals['subdomains']}")
        self.stdout.write(f"  EndPoints recovered    : {totals['endpoints']}")
        self.stdout.write(f"  Ports recovered        : {totals['ports']}")
        self.stdout.write(f"  Vulnerabilities recov. : {totals['vulns']}")
        self.stdout.write(f"  WAFs recovered         : {totals['wafs']}")
        if not apply:
            self.stdout.write(self.style.WARNING("Run with --apply to write these records."))

    # ------------------------------------------------------------------ #
    # Directory discovery                                                  #
    # ------------------------------------------------------------------ #

    def _find_scan_dirs(self, root):
        """Return directories that look like '{domain}_{numeric_id}'."""
        dirs = []
        if not os.path.isdir(root):
            raise CommandError(f"Results root does not exist: {root}")
        for entry in os.scandir(root):
            if not entry.is_dir():
                continue
            # Must end with an underscore-separated numeric scan id
            if re.search(r"_\d+$", entry.name):
                dirs.append(entry.path)
        return dirs

    # ------------------------------------------------------------------ #
    # Per-scan recovery                                                    #
    # ------------------------------------------------------------------ #

    def _recover_scan(self, scan_dir, existing_dirs):
        """
        Recover all data for one scan directory.
        Returns a dict of counts, or None if the scan is already in the DB.
        """
        if scan_dir in existing_dirs:
            self.stdout.write(f"  SKIP (already in DB): {scan_dir}")
            return None

        # Parse scan_id and domain_name from directory name
        basename = os.path.basename(scan_dir)
        match = re.match(r"^(.+)_(\d+)$", basename)
        if not match:
            self.stdout.write(
                self.style.WARNING(f"  SKIP (unexpected name pattern): {scan_dir}")
            )
            return None

        domain_name = match.group(1)
        scan_id_hint = int(match.group(2))

        # Only recover if the folder has at least one meaningful result file
        if not self._has_result_files(scan_dir):
            self.stdout.write(f"  SKIP (no result files): {scan_dir}")
            return None

        self.stdout.write(
            self.style.MIGRATE_HEADING(
                f"\n[RECOVER] {basename}  domain={domain_name} hint_id={scan_id_hint}"
            )
        )

        counts = dict(domains=0, subdomains=0, endpoints=0, ports=0, vulns=0, wafs=0)

        # ---- Domain -------------------------------------------------- #
        domain_obj = self._get_or_create_domain(domain_name)
        if domain_obj is None:
            return None
        if domain_obj[1]:
            counts["domains"] += 1

        domain_obj = domain_obj[0]

        # ---- ScanHistory -------------------------------------------- #
        scan_date = self._folder_mtime(scan_dir)
        scan_history = self._create_scan_history(domain_obj, scan_dir, scan_date)
        if scan_history is None:
            return None

        # ---- Subdomains --------------------------------------------- #
        subdomains_created = self._recover_subdomains(scan_dir, scan_id_hint, domain_obj, scan_history)
        counts["subdomains"] += subdomains_created

        # Build name->obj map for foreign-key use below.
        # Built AFTER _recover_subdomains so newly created records are included.
        # In dry-run mode we use a sentinel dict keyed by name so WAF/port
        # counts are accurate even without real DB objects.
        subdomain_map = {}
        if self._apply:
            from startScan.models import Subdomain
            for sd in Subdomain.objects.filter(scan_history=scan_history):
                subdomain_map[sd.name] = sd
        else:
            # Dry-run: populate map with fake objects so linking logic runs
            DrySubdomain = type("DrySubdomain", (), {})
            for name in self._collect_subdomain_names(scan_dir, scan_id_hint):
                fake = DrySubdomain()
                fake.name = name
                subdomain_map[name] = fake

        # ---- Ports + IpAddresses ------------------------------------ #
        counts["ports"] += self._recover_ports(scan_dir, scan_id_hint, subdomain_map)

        # ---- EndPoints ---------------------------------------------- #
        counts["endpoints"] += self._recover_endpoints(
            scan_dir, scan_id_hint, domain_obj, scan_history, subdomain_map
        )

        # ---- Vulnerabilities ---------------------------------------- #
        counts["vulns"] += self._recover_vulns(
            scan_dir, scan_id_hint, domain_obj, scan_history, subdomain_map
        )

        # ---- WAF ---------------------------------------------------- #
        counts["wafs"] += self._recover_wafs(
            scan_dir, scan_id_hint, subdomain_map
        )

        self.stdout.write(
            f"    subdomains={counts['subdomains']}  endpoints={counts['endpoints']}  "
            f"ports={counts['ports']}  vulns={counts['vulns']}  wafs={counts['wafs']}"
        )
        return counts

    # ------------------------------------------------------------------ #
    # Domain                                                               #
    # ------------------------------------------------------------------ #

    def _get_or_create_domain(self, domain_name):
        Domain = self._models["Domain"]
        if not self._apply:
            existing = Domain.objects.filter(name=domain_name).first()
            created = existing is None
            if created:
                self.stdout.write(f"    [dry] Would create Domain: {domain_name}")
            return (existing or type("FakeDomain", (), {"id": None, "name": domain_name})(), created)
        obj, created = Domain.objects.get_or_create(
            name=domain_name,
            defaults={"name": domain_name},
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f"    Created Domain: {domain_name}"))
        return (obj, created)

    # ------------------------------------------------------------------ #
    # ScanHistory                                                          #
    # ------------------------------------------------------------------ #

    def _create_scan_history(self, domain_obj, scan_dir, scan_date):
        ScanHistory = self._models["ScanHistory"]
        EngineType = self._models["EngineType"]

        # Use "Full Scan" engine if available, otherwise first one
        engine = EngineType.objects.filter(engine_name="Full Scan").first()
        if engine is None:
            engine = EngineType.objects.first()
        if engine is None:
            self.stdout.write(
                self.style.WARNING("    No EngineType found — cannot create ScanHistory")
            )
            return None

        if not self._apply:
            self.stdout.write(f"    [dry] Would create ScanHistory for {scan_dir}")
            return type("FakeScan", (), {"id": None})()

        obj, created = ScanHistory.objects.get_or_create(
            results_dir=scan_dir,
            defaults={
                "domain": domain_obj,
                "scan_type": engine,
                "start_scan_date": scan_date,
                "stop_scan_date": scan_date,
                "scan_status": 2,  # SUCCESS
                "results_dir": scan_dir,
            },
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f"    Created ScanHistory id={obj.id}"))
        return obj

    # ------------------------------------------------------------------ #
    # Subdomains                                                           #
    # ------------------------------------------------------------------ #

    def _collect_subdomain_names(self, scan_dir, scan_id):
        """Return the set of subdomain names from files without any DB access."""
        names = set()
        for fname in [f"#{scan_id}_subdomain_discovery.txt", f"#{scan_id}-subdomain_discovery.txt"]:
            names.update(self._read_plain_lines(os.path.join(scan_dir, fname)))
        for entry in self._list_files(scan_dir, prefix="subdomains_", suffix=".txt"):
            names.update(self._read_plain_lines(entry))
        subscans_dir = os.path.join(scan_dir, "subscans")
        if os.path.isdir(subscans_dir):
            for sub_entry in os.scandir(subscans_dir):
                if sub_entry.is_dir():
                    for fname in os.listdir(sub_entry.path):
                        if "subdomain_discovery" in fname or fname.startswith("subdomains_"):
                            names.update(self._read_plain_lines(os.path.join(sub_entry.path, fname)))
        return {n for n in names if n and not n.startswith("#")}

    def _recover_subdomains(self, scan_dir, scan_id, domain_obj, scan_history):
        """Collect unique subdomain names from discovery files and create DB records."""
        names = set()

        # Primary consolidated file: #{scan_id}_subdomain_discovery.txt
        for fname in [f"#{scan_id}_subdomain_discovery.txt", f"#{scan_id}-subdomain_discovery.txt"]:
            names.update(self._read_plain_lines(os.path.join(scan_dir, fname)))

        # Per-tool files: subdomains_*.txt
        for entry in self._list_files(scan_dir, prefix="subdomains_", suffix=".txt"):
            names.update(self._read_plain_lines(entry))

        # Also look in subscan dirs
        subscans_dir = os.path.join(scan_dir, "subscans")
        if os.path.isdir(subscans_dir):
            for sub_entry in os.scandir(subscans_dir):
                if sub_entry.is_dir():
                    for fname in os.listdir(sub_entry.path):
                        if "subdomain_discovery" in fname or fname.startswith("subdomains_"):
                            names.update(self._read_plain_lines(os.path.join(sub_entry.path, fname)))

        # Filter out empty/comment lines
        names = {n for n in names if n and not n.startswith("#")}

        count = 0
        for name in sorted(names):
            count += self._upsert_subdomain(name, domain_obj, scan_history)
        return count

    def _upsert_subdomain(self, name, domain_obj, scan_history):
        Subdomain = self._models["Subdomain"]
        if not self._apply:
            # Dry-run: just count — don't query DB with fake objects
            self.stdout.write(f"      [dry] Would create Subdomain: {name}")
            return 1

        _, created = Subdomain.objects.get_or_create(
            name=name,
            scan_history=scan_history,
            defaults={
                "target_domain": domain_obj,
                "discovered_date": scan_history.start_scan_date,
            },
        )
        return 1 if created else 0

    # ------------------------------------------------------------------ #
    # Ports + IpAddresses (naabu JSON)                                    #
    # ------------------------------------------------------------------ #

    def _recover_ports(self, scan_dir, scan_id, subdomain_map):
        """Parse #{scan_id}_port_scan.txt into Port + IpAddress records.

        Supports two formats produced by different naabu versions:
          1. JSONL: each line is {"host":"x","ip":"y","port":N,"protocol":"tcp"}
          2. Legacy JSON object: {"hostname": [port, port, ...], ...}
        """
        port_file = os.path.join(scan_dir, f"#{scan_id}_port_scan.txt")
        if not os.path.isfile(port_file):
            return 0

        count = 0

        # Try to load as a full JSON doc first (legacy format)
        full = self._load_json_file(port_file)
        if isinstance(full, dict):
            # Legacy: {"host": [port, ...]}
            for host, ports in full.items():
                if isinstance(ports, list):
                    for port_num in ports:
                        if isinstance(port_num, int):
                            count += self._upsert_port_record(host, "", port_num, "tcp", subdomain_map)
            return count

        # Modern JSONL format
        for rec in self._read_json_lines(port_file):
            if not isinstance(rec, dict):
                continue
            host = rec.get("host", "")
            ip_addr = rec.get("ip", "")
            port_num = rec.get("port")
            protocol = rec.get("protocol", "tcp")
            if not host or not port_num:
                continue
            count += self._upsert_port_record(host, ip_addr, port_num, protocol, subdomain_map)

        return count

    def _upsert_port_record(self, host, ip_addr, port_num, protocol, subdomain_map):
        IpAddress = self._models["IpAddress"]
        Port = self._models["Port"]

        service_name = f"{protocol}/{port_num}"

        if not self._apply:
            # Dry-run: count without DB queries
            return 1

        port_obj, _ = Port.objects.get_or_create(
            number=port_num,
            service_name=service_name,
            defaults={"description": f"Recovered from naabu scan", "is_uncommon": False},
        )

        ip_obj, _ = IpAddress.objects.get_or_create(
            address=ip_addr,
            defaults={"version": 4 if ":" not in ip_addr else 6},
        )
        ip_obj.ports.add(port_obj)

        # Link the ip to the corresponding subdomain if we have it
        subdomain = subdomain_map.get(host)
        if subdomain:
            subdomain.ip_addresses.add(ip_obj)
            return 1

        return 1

    # ------------------------------------------------------------------ #
    # EndPoints                                                            #
    # ------------------------------------------------------------------ #

    def _recover_endpoints(self, scan_dir, scan_id, domain_obj, scan_history, subdomain_map):
        """Collect URLs from fetch_url and urls_* files."""
        urls = set()

        for fname in [f"#{scan_id}_fetch_url.txt", f"#{scan_id}-fetch_url.txt"]:
            urls.update(self._read_plain_lines(os.path.join(scan_dir, fname)))

        for entry in self._list_files(scan_dir, prefix="urls_", suffix=".txt"):
            urls.update(self._read_plain_lines(entry))

        # Filter valid-looking URLs
        urls = {u for u in urls if u.startswith("http")}

        count = 0
        for url in sorted(urls):
            count += self._upsert_endpoint(url, domain_obj, scan_history, subdomain_map)
        return count

    def _upsert_endpoint(self, http_url, domain_obj, scan_history, subdomain_map):
        EndPoint = self._models["EndPoint"]

        # Determine matching subdomain from URL hostname
        from urllib.parse import urlparse
        try:
            hostname = urlparse(http_url).hostname or ""
        except Exception:
            hostname = ""

        subdomain = subdomain_map.get(hostname)

        if not self._apply:
            # Dry-run: count without DB queries
            return 1

        _, created = EndPoint.objects.get_or_create(
            http_url=http_url,
            scan_history=scan_history,
            defaults={
                "target_domain": domain_obj,
                "subdomain": subdomain,
                "discovered_date": scan_history.start_scan_date,
                "is_redirect": False,
            },
        )
        return 1 if created else 0

    # ------------------------------------------------------------------ #
    # Vulnerabilities                                                      #
    # ------------------------------------------------------------------ #

    def _recover_vulns(self, scan_dir, scan_id, domain_obj, scan_history, subdomain_map):
        count = 0

        # 1) nmap_vulns JSON files: [{name, severity, description, source, http_url}]
        for entry in self._list_files(scan_dir, suffix="_nmap_vulns.json"):
            vulns = self._load_json_file(entry)
            if not isinstance(vulns, list):
                continue
            for v in vulns:
                count += self._upsert_vuln_nmap(v, domain_obj, scan_history, subdomain_map)

        # 2) Nuclei JSONL files
        for fname_pat in [
            f"#{scan_id}_nuclei_individual_severity_module.txt",
            f"#{scan_id}-nuclei_individual_severity_module.txt",
        ]:
            for line in self._read_plain_lines(os.path.join(scan_dir, fname_pat)):
                if not line.strip() or line.strip() in ("[]", "{}"):
                    continue
                try:
                    # Could be a single JSON array or JSONL
                    parsed = json.loads(line)
                    if isinstance(parsed, list):
                        for item in parsed:
                            count += self._upsert_vuln_nuclei(item, domain_obj, scan_history, subdomain_map)
                    elif isinstance(parsed, dict):
                        count += self._upsert_vuln_nuclei(parsed, domain_obj, scan_history, subdomain_map)
                except json.JSONDecodeError:
                    pass

        # Also handle nuclei files stored as a full JSON array
        for fname_pat in [
            f"#{scan_id}_nuclei_individual_severity_module.txt",
            f"#{scan_id}-nuclei_individual_severity_module.txt",
        ]:
            fpath = os.path.join(scan_dir, fname_pat)
            data = self._load_json_file(fpath)
            if isinstance(data, list):
                for item in data:
                    count += self._upsert_vuln_nuclei(item, domain_obj, scan_history, subdomain_map)

        return count

    def _upsert_vuln_nmap(self, v, domain_obj, scan_history, subdomain_map):
        name = v.get("name", "Unknown")
        severity_int = v.get("severity", -1)
        description = v.get("description", "")
        http_url = v.get("http_url", "")
        source = v.get("source", "nmap")

        if not name:
            return 0

        from urllib.parse import urlparse
        try:
            hostname = urlparse(http_url).hostname or "" if http_url else ""
        except Exception:
            hostname = ""

        subdomain = subdomain_map.get(hostname)

        return self._write_vuln(
            name=name,
            severity=severity_int,
            description=description,
            http_url=http_url,
            source=source,
            domain_obj=domain_obj,
            scan_history=scan_history,
            subdomain=subdomain,
        )

    def _upsert_vuln_nuclei(self, v, domain_obj, scan_history, subdomain_map):
        if not isinstance(v, dict):
            return 0

        name = v.get("name") or v.get("info", {}).get("name", "")
        severity_str = (
            v.get("severity")
            or v.get("info", {}).get("severity", "unknown")
        ).lower()
        severity_int = SEVERITY_MAP.get(severity_str, -1)
        description = (
            v.get("description")
            or v.get("info", {}).get("description", "")
            or ""
        )
        http_url = v.get("matched-at") or v.get("host", "")
        template_id = v.get("template-id", "")
        template_url = v.get("template-url", "")

        if not name:
            return 0

        from urllib.parse import urlparse
        try:
            hostname = urlparse(http_url).hostname or "" if http_url else ""
        except Exception:
            hostname = ""
        subdomain = subdomain_map.get(hostname)

        vuln_count = self._write_vuln(
            name=name,
            severity=severity_int,
            description=description,
            http_url=http_url,
            source="nuclei",
            domain_obj=domain_obj,
            scan_history=scan_history,
            subdomain=subdomain,
            template_id=template_id,
            template_url=template_url,
        )

        return vuln_count

    def _write_vuln(
        self, name, severity, description, http_url, source,
        domain_obj, scan_history, subdomain,
        template_id="", template_url="",
    ):
        Vulnerability = self._models["Vulnerability"]

        if not self._apply:
            # Dry-run: count without DB queries
            self.stdout.write(f"      [dry] Would create Vuln: [{severity}] {name} @ {http_url}")
            return 1

        _, created = Vulnerability.objects.get_or_create(
            name=name,
            http_url=http_url,
            scan_history=scan_history,
            defaults={
                "severity": severity,
                "description": description,
                "source": source,
                "subdomain": subdomain,
                "target_domain": domain_obj,
                "template_id": template_id,
                "template_url": template_url,
                "discovered_date": scan_history.start_scan_date,
                "open_status": True,
            },
        )
        return 1 if created else 0

    # ------------------------------------------------------------------ #
    # WAF detection                                                        #
    # ------------------------------------------------------------------ #

    def _recover_wafs(self, scan_dir, scan_id, subdomain_map):
        """
        Parse #{scan_id}_waf_detection.txt lines like:
            https://www.example.com   Cloudflare (Cloudflare Inc.)
        """
        waf_file = os.path.join(scan_dir, f"#{scan_id}_waf_detection.txt")
        if not os.path.isfile(waf_file):
            return 0

        Waf = self._models["Waf"]
        count = 0

        for line in self._read_plain_lines(waf_file):
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) < 2:
                continue

            url = parts[0].strip()
            waf_raw = parts[-1].strip()

            # e.g. "Cloudflare (Cloudflare Inc.)"
            m = re.match(r"^(.+?)\s*\((.+)\)\s*$", waf_raw)
            if m:
                waf_name = m.group(1).strip()
                manufacturer = m.group(2).strip()
            else:
                waf_name = waf_raw
                manufacturer = ""

            if waf_name.lower() in ("none", "unknown", ""):
                continue

            from urllib.parse import urlparse
            try:
                hostname = urlparse(url).hostname or ""
            except Exception:
                hostname = ""

            subdomain = subdomain_map.get(hostname)
            if subdomain is None:
                continue

            if not self._apply:
                self.stdout.write(f"      [dry] Would attach WAF {waf_name} to {hostname}")
                count += 1
                continue

            waf_obj, _ = Waf.objects.get_or_create(
                name=waf_name,
                defaults={"manufacturer": manufacturer},
            )
            subdomain.waf.add(waf_obj)
            count += 1

        return count

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _has_result_files(self, scan_dir):
        """Return True if the directory contains at least one non-trivial result file."""
        skip_names = {"commands.txt", "httpx_input.txt"}
        for entry in os.scandir(scan_dir):
            if entry.is_file() and entry.name not in skip_names:
                if entry.name.endswith((".txt", ".json", ".xml")):
                    return True
        return False

    def _folder_mtime(self, path):
        try:
            ts = os.path.getmtime(path)
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except OSError:
            return django_tz.now()

    def _read_plain_lines(self, path):
        """Read a plain-text file and return a set of non-empty stripped lines."""
        if not os.path.isfile(path):
            return set()
        lines = set()
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        lines.add(line)
        except OSError:
            pass
        return lines

    def _read_json_lines(self, path):
        """Read a file where each non-empty line is a JSON object."""
        if not os.path.isfile(path):
            return []
        records = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        except OSError:
            pass
        return records

    def _load_json_file(self, path):
        """Load an entire file as JSON (array or object). Returns None on failure."""
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read().strip()
                if not content or content in ("[]", "{}"):
                    return None
                return json.loads(content)
        except (OSError, json.JSONDecodeError):
            return None

    def _list_files(self, directory, prefix="", suffix=""):
        """Yield full paths of files in directory matching prefix/suffix, non-recursively."""
        try:
            for entry in os.scandir(directory):
                if entry.is_file():
                    if entry.name.startswith(prefix) and entry.name.endswith(suffix):
                        yield entry.path
        except OSError:
            pass
