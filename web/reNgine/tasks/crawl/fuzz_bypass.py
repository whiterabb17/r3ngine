"""Content fuzzing and 4xx bypass tasks (feroxbuster, bup).

Split out of the former reNgine/tasks/crawl.py; re-exported by
reNgine.tasks.crawl for backward compatibility.
"""
import os
import subprocess
from typing import List

from reNgine.utils.logger import get_module_logger

logger = get_module_logger(__name__)

def bup_scan(self, scan_history_id: int, url: str = None,
             urls: List[str] = None) -> bool:
    """Attempt 4xx bypass techniques using bypass-url-parser (bup).

    Saves successful bypasses as Vulnerability records (severity=medium/2).
    Used in: URLBypassWorkflow.
    """
    from startScan.models import Vulnerability
    from django.db import transaction

    targets = urls or ([url] if url else [])
    if not targets:
        return True

    for target in targets:
        cmd = ['bup', '-u', target, '-d']
        logger.log_line("[BUP]", "START", "bypass attempt on %s" % target)
        bypasses = []
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            for line in result.stdout.splitlines():
                if '[BYPASS]' in line or ('200' in line and 'bypass' in line.lower()):
                    bypasses.append(Vulnerability(
                        scan_history_id=scan_history_id,
                        name='4xx Bypass Found',
                        severity=2,  # medium
                        description=line.strip(),
                        source='bup',
                        http_url=target,
                    ))
        except subprocess.TimeoutExpired:
            logger.log_line("[BUP]", "WARN", "timed out for %s" % target)

        if bypasses:
            with transaction.atomic():
                Vulnerability.objects.bulk_create(bypasses, ignore_conflicts=True)
            logger.log_line(
                "[BUP]", "RESULT", "found %d bypasses for %s" % (len(bypasses), target),
            )

    return True


def feroxbuster_scan(self, scan_history_id: int, url: str = None,
                     urls: List[str] = None) -> bool:
    """Recursively fuzz web content using feroxbuster.

    Persists discovered paths as EndPoint records.
    Used in: URLFuzzWorkflow.
    """
    from startScan.models import EndPoint
    from django.db import transaction

    yaml_config = getattr(self, 'yaml_configuration', {}) or {}
    scan_config = yaml_config.get('feroxbuster', {})
    wordlist = scan_config.get(
        'wordlist',
        '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt',
    )

    targets = urls or ([url] if url else [])
    if not targets:
        return True

    for target in targets:
        output_file = f"/tmp/feroxbuster_{scan_history_id}.txt"
        cmd = [
            'feroxbuster', '--url', target,
            '--no-state', '--output', output_file,
            '--auto-calibration', '--follow-redirects', '--silent',
        ]
        if os.path.exists(wordlist):
            cmd += ['--wordlist', wordlist]

        logger.log_line("[FEROXBUSTER]", "START", "fuzzing %s" % target)
        endpoints = []
        try:
            subprocess.run(cmd, capture_output=True, timeout=1800)
            if os.path.exists(output_file):
                with open(output_file) as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0].isdigit():
                            ep_url = parts[-1].strip()
                            if ep_url.startswith('http'):
                                endpoints.append(EndPoint(
                                    scan_history_id=scan_history_id,
                                    http_url=ep_url[:30000],
                                    http_status=int(parts[0]),
                                    is_default=False,
                                    source='feroxbuster',
                                ))
        except subprocess.TimeoutExpired:
            logger.log_line("[FEROXBUSTER]", "WARN", "timed out for %s" % target)
        finally:
            try:
                os.remove(output_file)
            except FileNotFoundError:
                pass

        if endpoints:
            with transaction.atomic():
                EndPoint.objects.bulk_create(endpoints, ignore_conflicts=True, batch_size=500)
            logger.log_line("[FEROXBUSTER]", "RESULT", "saved %d endpoints" % len(endpoints))

    return True
