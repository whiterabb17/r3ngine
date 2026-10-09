"""Parameter discovery tasks (arjun, unfurl).

Split out of the former reNgine/tasks/crawl.py; re-exported by
reNgine.tasks.crawl for backward compatibility.
"""
import os
import json
import subprocess
from typing import List, Optional

from reNgine.utils.logger import get_module_logger

logger = get_module_logger(__name__)

def arjun_scan(self, scan_history_id: int, urls: List[str] = None,
               url: str = None) -> bool:
    """Discover hidden HTTP parameters using arjun.

    Saves discovered parameters to the Parameter model via EndPoint FK.
    Creates EndPoint records for any URLs that don't already have one.
    Used in: URLParamsFuzzWorkflow.
    """
    from startScan.models import Parameter, EndPoint
    from django.db import transaction

    targets = urls or ([url] if url else [])
    if not targets:
        return True

    output_file = f"/tmp/arjun_output_{scan_history_id}.json"
    cmd = ['arjun', '-i', '/dev/stdin', '-oJ', output_file, '-q']
    logger.log_line("[ARJUN]", "START", "parameter discovery for %d URLs" % len(targets))

    try:
        result = subprocess.run(
            cmd,
            input='\n'.join(targets),
            capture_output=True, text=True, timeout=600,
        )
        if os.path.exists(output_file):
            with open(output_file) as f:
                data = json.load(f)
            params = []
            for ep_url, param_list in data.items():
                # Get or create an EndPoint for this URL
                endpoint, _ = EndPoint.objects.get_or_create(
                    scan_history_id=scan_history_id,
                    http_url=ep_url[:30000],
                    defaults={'source': 'arjun', 'is_default': False},
                )
                for param_name in param_list:
                    params.append(Parameter(
                        endpoint=endpoint,
                        name=param_name,
                        type='query',
                    ))
            if params:
                with transaction.atomic():
                    Parameter.objects.bulk_create(params, ignore_conflicts=True)
                logger.log_line("[ARJUN]", "RESULT", "saved %d parameters" % len(params))
    except subprocess.TimeoutExpired:
        logger.log_line("[ARJUN]", "WARN", "arjun timed out")
    except (json.JSONDecodeError, Exception) as exc:
        logger.log_line("[ARJUN]", "WARN", "arjun parse error: %s" % str(exc))
    finally:
        try:
            os.remove(output_file)
        except FileNotFoundError:
            pass

    return True


def urlparser_scan(self, scan_history_id: int, domain_id: int,
                   urls: Optional[List[str]] = None) -> bool:
    """Extract unique query-string parameters from URLs using unfurl.

    Pipes URLs through `unfurl -u keypairs`, parses key=value output,
    and stores each pair as a Parameter record on the matching EndPoint.
    Falls back to loading EndPoint URLs from the scan when urls is not given.
    Used in: URLParamsFuzzWorkflow, URLCrawlWorkflow.
    """
    from startScan.models import EndPoint, Parameter
    from django.db import transaction

    targets = urls or []
    if not targets and scan_history_id:
        targets = list(
            EndPoint.objects.filter(
                scan_history_id=scan_history_id
            ).values_list('http_url', flat=True)[:2000]
        )

    if not targets:
        logger.log_line("[URLPARSER]", "SKIP", "no URLs to parse")
        return True

    input_file = '/tmp/urlparser_input_%s.txt' % scan_history_id
    try:
        with open(input_file, 'w') as f:
            f.write('\n'.join(t for t in targets if t))

        logger.log_line("[URLPARSER]", "START", "parsing %d URLs" % len(targets))
        with open(input_file, 'rb') as stdin_f:
            result = subprocess.run(
                ['unfurl', '-u', 'keypairs'],
                stdin=stdin_f,
                capture_output=True, text=True, timeout=120,
            )

        # Build lookup: http_url → EndPoint for fast matching
        ep_map = {
            ep.http_url: ep
            for ep in EndPoint.objects.filter(
                scan_history_id=scan_history_id,
                http_url__in=targets,
            )
        }

        params_to_create: List[Parameter] = []
        seen: set = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or '=' not in line:
                continue
            key, _, value = line.partition('=')
            key = key.strip()
            value = value.strip()
            for url, ep in ep_map.items():
                if ('?%s=' % key) in url or ('&%s=' % key) in url:
                    dedup_key = (ep.id, key)
                    if dedup_key in seen:
                        continue
                    params_to_create.append(
                        Parameter(endpoint=ep, name=key, value=value, type='GET')
                    )
                    seen.add(dedup_key)

        if params_to_create:
            with transaction.atomic():
                Parameter.objects.bulk_create(params_to_create, ignore_conflicts=True)
            logger.log_line("[URLPARSER]", "RESULT",
                            "saved %d parameters" % len(params_to_create))
        else:
            logger.log_line("[URLPARSER]", "RESULT", "no new parameters found")

    except subprocess.TimeoutExpired:
        logger.log_line("[URLPARSER]", "WARN", "unfurl timed out")
    finally:
        if os.path.exists(input_file):
            os.remove(input_file)

    return True
