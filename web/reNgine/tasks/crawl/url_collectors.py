"""Standalone URL collectors used by the URL crawl workflows (xurlfind3r, urlfinder, cariddi).

Split out of the former reNgine/tasks/crawl.py; re-exported by
reNgine.tasks.crawl for backward compatibility.
"""
import subprocess
from typing import List

from reNgine.utils.logger import get_module_logger

logger = get_module_logger(__name__)

#---------------------#
# Notifications tasks #
#---------------------#

#-------------#
# Utils tasks #
#-------------#



def xurlfind3r_scan(self, scan_history_id: int, domain: str = None,
                    domains: List[str] = None) -> bool:
    """Collect passive URLs from multiple sources using xurlfind3r.

    Persists discovered URLs as EndPoint records.
    Used in: URLCrawlWorkflow (passive), DomainReconWorkflow.
    """
    from startScan.models import EndPoint
    from django.db import transaction

    targets = domains or ([domain] if domain else [])
    if not targets:
        return True

    endpoints = []
    for target in targets:
        cmd = ['xurlfind3r', '-d', target, '-silent']
        logger.log_line("[XURLFIND3R]", "START", "passive crawl for %s" % target)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith('http'):
                    endpoints.append(EndPoint(
                        scan_history_id=scan_history_id,
                        http_url=line[:30000],
                        is_default=False,
                        source='xurlfind3r',
                    ))
        except subprocess.TimeoutExpired:
            logger.log_line("[XURLFIND3R]", "WARN", "timed out for %s" % target)

    if endpoints:
        with transaction.atomic():
            EndPoint.objects.bulk_create(endpoints, ignore_conflicts=True, batch_size=500)
        logger.log_line("[XURLFIND3R]", "RESULT", "saved %d URLs" % len(endpoints))
    return True


def urlfinder_scan(self, scan_history_id: int, domain: str = None) -> bool:
    """Collect passive URLs using urlfinder (projectdiscovery).

    Used in: URLCrawlWorkflow (passive).
    """
    from startScan.models import EndPoint
    from django.db import transaction

    if not domain:
        return True

    cmd = ['urlfinder', '-d', domain, '-silent']
    logger.log_line("[URLFINDER]", "START", "passive crawl for %s" % domain)
    endpoints = []
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('http'):
                endpoints.append(EndPoint(
                    scan_history_id=scan_history_id,
                    http_url=line[:30000],
                    is_default=False,
                    source='urlfinder',
                ))
    except subprocess.TimeoutExpired:
        logger.log_line("[URLFINDER]", "WARN", "timed out for %s" % domain)

    if endpoints:
        with transaction.atomic():
            EndPoint.objects.bulk_create(endpoints, ignore_conflicts=True, batch_size=500)
        logger.log_line("[URLFINDER]", "RESULT", "saved %d URLs" % len(endpoints))
    return True


def cariddi_scan(self, scan_history_id: int, url: str = None,
                 urls: List[str] = None) -> bool:
    """Crawl endpoints and discover secrets using cariddi.

    Persists discovered endpoints as EndPoint records.
    Used in: URLCrawlWorkflow (active).
    """
    from startScan.models import EndPoint
    from django.db import transaction

    targets = urls or ([url] if url else [])
    if not targets:
        return True

    for target in targets:
        cmd = ['cariddi', '-i', target, '-info', '-secrets', '-e', '-s', '1']
        logger.log_line("[CARIDDI]", "START", "crawling %s" % target)
        endpoints = []
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            for line in result.stdout.splitlines():
                line = line.strip()
                # cariddi outputs "url\t[tag]..." format
                ep_url = line.split('\t')[0].strip() if '\t' in line else line
                if ep_url.startswith('http'):
                    endpoints.append(EndPoint(
                        scan_history_id=scan_history_id,
                        http_url=ep_url[:30000],
                        is_default=False,
                        source='cariddi',
                    ))
        except subprocess.TimeoutExpired:
            logger.log_line("[CARIDDI]", "WARN", "timed out for %s" % target)

        if endpoints:
            with transaction.atomic():
                EndPoint.objects.bulk_create(endpoints, ignore_conflicts=True, batch_size=500)
            logger.log_line(
                "[CARIDDI]", "RESULT",
                "saved %d endpoints for %s" % (len(endpoints), target),
            )

    return True
