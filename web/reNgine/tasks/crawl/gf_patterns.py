"""GF pattern filtering of URLs.

Split out of the former reNgine/tasks/crawl.py; re-exported by
reNgine.tasks.crawl for backward compatibility.
"""
import subprocess
from typing import List

from reNgine.utils.logger import get_module_logger

logger = get_module_logger(__name__)

def gf_scan(self, scan_history_id: int, pattern: str,
            urls: List[str] = None) -> List[str]:
    """Filter URLs by vulnerability pattern using gf (grep for URLs).

    Returns list of matched URL strings.
    Patterns: xss, lfi, ssrf, rce, idor, debug_logic, interestingparams.
    Used in: URLVulnWorkflow.
    """
    if not urls:
        return []

    cmd = ['gf', pattern]
    logger.log_line("[GF]", "START", "pattern=%s targets=%d" % (pattern, len(urls)))

    try:
        result = subprocess.run(
            cmd,
            input='\n'.join(urls),
            capture_output=True, text=True, timeout=60,
        )
        matched = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        logger.log_line("[GF]", "RESULT", "pattern=%s matched=%d" % (pattern, len(matched)))
        return matched
    except subprocess.TimeoutExpired:
        logger.log_line("[GF]", "WARN", "gf timed out for pattern %s" % pattern)
        return []
