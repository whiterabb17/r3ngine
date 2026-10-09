"""
Proxy management activities: per-scan proxy list files, target blocking
checks, proxy policy lookup and the background proxy fetch.
"""

import os

from temporalio import activity
from reNgine.temporal.heartbeat import keep_alive

from reNgine.utils.logger import get_module_logger

logger = get_module_logger(__name__)


# Per-scan proxy list files live on the github_repos volume, which the tool
# containers share with the orchestrator.
PROXY_LIST_ROOT = '/usr/src/github/scan_results'


# ===========================================================================
# Tier 6 — Assessment
# ===========================================================================

@activity.defn(name="CreateProxyListActivity")
def create_proxy_list_activity(ctx: dict) -> str:
    """Create a proxies.txt file if normal proxies are enabled.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        str: Path to the created proxies.txt file, or None if no proxies are configured.
    """
    from reNgine.common_func import get_proxy_list
    import os
    import uuid

    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", f"task=create_proxy_list scan_id={scan_id}")

    # Write the full pool (HTTP + SOCKS). Nuclei accepts socks5:// and http://
    # entries in a -proxy list file. Stripping SOCKS previously left a single
    # HTTP proxy on SOCKS-heavy pools and caused "all proxies are dead" timeouts.
    proxies = get_proxy_list()
    if not proxies:
        logger.log_line("[TEMPORAL]", "COMPLETE", f"task=create_proxy_list scan_id={scan_id} result=no_proxies")
        return None

    results_dir = os.path.join(PROXY_LIST_ROOT, str(scan_id))
    os.makedirs(results_dir, exist_ok=True)
    
    file_path = os.path.join(results_dir, f"proxies_{uuid.uuid4().hex}.txt")
    with open(file_path, 'w') as f:
        f.write('\n'.join(proxies))
    # The list can hold authenticated proxies, so the file holds live credentials
    # for the duration of the scan. Keep it readable only by the owning process.
    try:
        os.chmod(file_path, 0o600)
    except OSError as exc:
        activity.logger.warning(
            "[CreateProxyListActivity] could not restrict %s: %s", file_path, exc
        )

    activity.logger.info("[CreateProxyListActivity] scan_id=%s wrote %s proxies to %s", scan_id, len(proxies), file_path)
    logger.log_line("[TEMPORAL]", "COMPLETE", f"task=create_proxy_list scan_id={scan_id} result=created count={len(proxies)}")
    return file_path


@activity.defn(name="CheckTargetBlockingActivity")
def check_target_blocking_activity(ctx: dict) -> bool:
    """Probe a sample of the target's own endpoints directly, without a proxy.

    Answers one question for NucleiPlannerWorkflow: is this target blocking us?
    Routing nuclei through the proxy pool costs most of its speed, and most
    targets do not block at all, so that price should only be paid when it buys
    something.

    A ban shows up two ways and both are counted: a hard block drops or resets
    the connection, and a soft block answers 403 or 429. nuclei's own error
    counter sees only the first kind, which is why this probe exists instead of
    reading nuclei's statistics.

    Returns:
        bool: True when the blocked share of the sample crosses the threshold,
              or when the target could not be sampled at all (fail safe: use the
              proxy rather than hammer a target that may already be refusing us).
    """
    import requests as _requests
    from reNgine.common_func import get_http_urls, get_random_user_agent
    from startScan.models import ScanHistory

    scan_id = ctx.get('scan_history_id')
    sample_size = int(os.environ.get('BAN_PROBE_SAMPLE_SIZE', 10))
    threshold = float(os.environ.get('BAN_PROBE_THRESHOLD', 0.5))

    urls = get_http_urls(is_alive=False, ignore_files=True, ctx=ctx) or []
    if not urls:
        scan = ScanHistory.objects.filter(pk=scan_id).first()
        if scan and scan.domain:
            urls = [f'https://{scan.domain.name}']
    if not urls:
        activity.logger.warning(
            "[BANPROBE] scan_id=%s no endpoints to sample — assuming blocked so "
            "the proxy pool is used.", scan_id,
        )
        return True

    sample = urls[:sample_size]
    blocked = 0
    for url in sample:
        try:
            resp = _requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                headers={'User-Agent': get_random_user_agent()},
            )
            if resp.status_code in (403, 429):
                blocked += 1
        except _requests.exceptions.RequestException:
            # Reset, refused or timed out — the hard-block shape.
            blocked += 1

    ratio = blocked / len(sample)
    is_blocked = ratio >= threshold
    activity.logger.warning(
        "[BANPROBE] scan_id=%s sampled=%d blocked=%d ratio=%.2f threshold=%.2f "
        "-> %s", scan_id, len(sample), blocked, ratio, threshold,
        "USE PROXY" if is_blocked else "SCAN DIRECT",
    )
    return is_blocked


@activity.defn(name="GetProxyPolicyActivity")
def get_proxy_policy_activity(ctx: dict) -> dict:
    """Return how the proxy pool should be engaged for this scan.

    Kept as its own activity because workflow code must not touch the database.
    """
    from scanEngine.models import Proxy

    proxy_obj = Proxy.objects.first()
    policy = {
        'use_proxy': bool(proxy_obj and (proxy_obj.use_proxy or proxy_obj.use_tor)),
        'only_after_ban': bool(
            proxy_obj and getattr(proxy_obj, 'proxy_only_after_ban', False)
        ),
    }
    activity.logger.info("[BANPROBE] proxy policy: %s", policy)
    return policy


@activity.defn(name="CleanupProxyListActivity")
def cleanup_proxy_list_activity(file_path: str) -> bool:
    """Clean up the proxies.txt file.

    Args:
        file_path (str): Path to the proxies.txt file.

    Returns:
        bool: True if cleanup was successful or file didn't exist.
    """
    import os
    logger.log_line("[TEMPORAL]", "START", f"task=cleanup_proxy_list file_path={file_path}")
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
            activity.logger.info("[CleanupProxyListActivity] removed %s", file_path)
        except Exception as e:
            activity.logger.error("[CleanupProxyListActivity] failed to remove %s: %s", file_path, e)
    
    logger.log_line("[TEMPORAL]", "COMPLETE", f"task=cleanup_proxy_list file_path={file_path}")
    return True


@activity.defn(name="FetchProxiesActivity")
@keep_alive
def fetch_proxies_activity(limit: int, job_id: str) -> None:
    logger.log_line("[TEMPORAL]", "START", "task=fetch_proxies limit=%d" % limit)
    activity.logger.info("[FetchProxies] Starting proxy fetch (limit=%d, job_id=%s)", limit, job_id)
    from reNgine.tasks import fetch_proxies_task
    fetch_proxies_task(limit=limit, job_id=job_id)
    activity.logger.info("[FetchProxies] Proxy fetch activity complete")
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=fetch_proxies limit=%d" % limit)
