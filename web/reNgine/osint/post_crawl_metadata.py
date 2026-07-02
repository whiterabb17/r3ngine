import json
import logging
import os
import subprocess

from scanEngine.models import Proxy
from reNgine.common_func import get_random_proxy
from startScan.models import MetaFinderDocument

logger = logging.getLogger(__name__)


def run_post_crawl_exifray(self, host: str, ctx: dict, results_dir: str) -> None:
    """Find and extract metadata from publicly indexed documents for host using exifray.

    exifray is a domain-level Go tool — no need to download discovered files locally.
    It Google-searches for documents (pdf, docx, etc.) indexed for the target domain
    and extracts their metadata.
    """
    output_file = os.path.join(results_dir, 'exifray_output.json')
    cmd = ['exifray', '-d', host, '--show-urls', '--timeout', '30', '-o', output_file]
    env = os.environ.copy()

    proxy_obj = Proxy.objects.first()
    proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None
    if proxy:
        env['HTTPS_PROXY'] = proxy
        env['HTTP_PROXY'] = proxy

    logger.info("exifray starting for %s", host)
    try:
        result = subprocess.run(cmd, capture_output=True, env=env, timeout=300)
        if result.returncode != 0:
            logger.warning(
                "exifray non-zero exit for %s: %s",
                host,
                result.stderr.decode('utf-8', errors='replace')[:200],
            )
    except Exception as exc:
        logger.warning("exifray failed for %s: %s", host, exc)
        return

    if not os.path.exists(output_file):
        logger.info("exifray: no output file for %s", host)
        return

    try:
        with open(output_file) as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("exifray: failed to parse output for %s: %s", host, exc)
        return

    # data is expected to be a list of document metadata dicts
    docs = data if isinstance(data, list) else data.get('documents', [])
    saved = 0
    for doc in docs:
        url = doc.get('url', '')
        if not url:
            continue
        doc_name = os.path.basename(url.split('?')[0]) or 'unknown'
        defaults = {
            'doc_name': doc_name,
            'title': doc.get('title', ''),
            'author': doc.get('author', ''),
            'producer': doc.get('producer', ''),
            'creator': doc.get('creator', ''),
        }
        MetaFinderDocument.objects.get_or_create(
            scan_history=self.scan,
            url=url,
            defaults=defaults,
        )
        saved += 1

    logger.info("exifray finished for %s — %d documents found", host, saved)
