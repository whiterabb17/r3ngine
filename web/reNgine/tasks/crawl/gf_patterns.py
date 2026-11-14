"""GF pattern filtering of URLs.

Split out of the former reNgine/tasks/crawl.py; re-exported by
reNgine.tasks.crawl for backward compatibility.
"""
import os
import shlex
import uuid
from typing import List

from reNgine.settings import RENGINE_RESULTS
from reNgine.utils.logger import get_module_logger
from reNgine.utils.task import run_command

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

    logger.log_line("[GF]", "START", "pattern=%s targets=%d" % (pattern, len(urls)))
    # Shared scan_results volume so go-executor can read the input file.
    os.makedirs(RENGINE_RESULTS, exist_ok=True)
    tmp_path = os.path.join(RENGINE_RESULTS, f"gf-input-{scan_history_id}-{uuid.uuid4().hex[:8]}.urls")

    try:
        with open(tmp_path, 'w', encoding='utf-8') as tmp:
            tmp.write('\n'.join(urls))
        # Route through run_command so gf runs on go-executor when in ROUTED_TOOLS.
        cmd = f"gf {shlex.quote(pattern)} < {shlex.quote(tmp_path)}"
        _code, stdout = run_command(
            cmd,
            shell=True,
            scan_id=scan_history_id,
            timeout=60,
        )
        matched = [line.strip() for line in (stdout or '').splitlines() if line.strip()]
        logger.log_line("[GF]", "RESULT", "pattern=%s matched=%d" % (pattern, len(matched)))
        return matched
    except Exception:
        logger.log_line("[GF]", "WARN", "gf failed for pattern %s" % pattern)
        return []
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
