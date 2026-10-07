"""Hosts that serve the same site as another host of the scan.

Heavy per-host tools (directory fuzzing, Acunetix) run once per site rather than
once per name: a host whose root redirects to the root of another live host of
the scan, or `www.X` next to a live `X`, is marked a duplicate of that host.

A redirect counts only when it lands on the other host's root. Many unrelated
applications redirect to one shared login or SSO host at some path; treating
those as duplicates would skip every one of them.
"""
from urllib.parse import urlparse

REDIRECT = 'redirect'
WWW = 'www'
DEFAULT_GROUP_BY = (REDIRECT, WWW)
_MAX_CHAIN = 10


def target_dedup_config(yaml_configuration: dict | None) -> tuple[bool, tuple]:
    """(enabled, rules) from the engine's `target_dedup` section; on by default."""
    section = (yaml_configuration or {}).get('target_dedup')
    section = section if isinstance(section, dict) else {}
    rules = section.get('group_by', DEFAULT_GROUP_BY)
    if not isinstance(rules, (list, tuple)):
        rules = DEFAULT_GROUP_BY
    return section.get('enabled', True) is not False, tuple(r for r in rules if r in DEFAULT_GROUP_BY)


def www_twin(host: str, live_hosts) -> str | None:
    """The bare host when `host` is `www.<bare>` and the bare host is live."""
    host = host.lower()
    if host.startswith('www.') and host[4:] in live_hosts:
        return host[4:]
    return None


def redirect_target(host: str, final_url: str | None, live_hosts) -> str | None:
    """The other live host whose root `host`'s root redirects to."""
    if not final_url:
        return None
    parsed = urlparse(final_url)
    target = (parsed.hostname or '').lower()
    if target and target != host.lower() and target in live_hosts and parsed.path in ('', '/'):
        return target
    return None


def compute_duplicates(hosts: dict, rules=DEFAULT_GROUP_BY) -> dict:
    """Map each duplicate host to (representative, reason).

    Args:
        hosts: live host name -> final URL of its root probe (or None).
        rules: the grouping rules to apply, in priority order.

    Returns:
        dict: duplicate host -> (host it duplicates, reason). Chains such as
        a -> www.b -> b resolve to the end of the chain; a cycle is left alone.
    """
    live = {name.lower() for name in hosts}
    direct = {}
    for name, final_url in hosts.items():
        name = name.lower()
        target = redirect_target(name, final_url, live) if REDIRECT in rules else None
        reason = REDIRECT
        if target is None and WWW in rules:
            target, reason = www_twin(name, live), WWW
        if target:
            direct[name] = (target, reason)

    resolved = {}
    for name, (target, reason) in direct.items():
        seen = {name}
        while target in direct and target not in seen and len(seen) < _MAX_CHAIN:
            seen.add(target)
            target = direct[target][0]
        if target not in seen:
            resolved[name] = (target, reason)
    return resolved


def apply_target_dedup(scan_id: int, rules=DEFAULT_GROUP_BY) -> dict:
    """Recompute the duplicate links of a scan's live hosts; idempotent.

    Returns:
        dict: duplicate host -> (host it duplicates, reason), as stored.
    """
    from django.db import transaction
    from django.db.models import Q
    from startScan.models import Subdomain

    subdomains = Subdomain.objects.filter(scan_history_id=scan_id)
    live = subdomains.filter(Q(http_status__gt=0) | Q(final_url__isnull=False))
    hosts = dict(live.values_list('name', 'final_url'))
    duplicates = compute_duplicates(hosts, rules)
    ids = {name.lower(): pk for name, pk in subdomains.values_list('name', 'id')}

    with transaction.atomic():
        subdomains.exclude(duplicate_of__isnull=True, dedup_reason__isnull=True).update(
            duplicate_of=None, dedup_reason=None,
        )
        for name, (target, reason) in duplicates.items():
            subdomains.filter(name__iexact=name).update(duplicate_of_id=ids.get(target), dedup_reason=reason)
    return duplicates


def duplicate_hosts(scan_id: int) -> dict:
    """host -> (host it duplicates, reason) as stored by the last dedup run."""
    from startScan.models import Subdomain

    rows = (
        Subdomain.objects
        .filter(scan_history_id=scan_id, duplicate_of__isnull=False)
        .values_list('name', 'duplicate_of__name', 'dedup_reason')
    )
    return {name.lower(): (target, reason) for name, target, reason in rows}


def drop_duplicate_targets(scan_id: int, targets: list, ctx: dict) -> tuple[list, list]:
    """Split URL targets into (kept, dropped) by the scan's duplicate hosts.

    Nothing is dropped for a run aimed at one host (subscan, single-tool run).
    """
    if ctx.get('subdomain_id') or ctx.get('subscan_id') or ctx.get('singular_tool_run'):
        return list(targets), []
    duplicates = duplicate_hosts(scan_id)
    if not duplicates:
        return list(targets), []
    kept, dropped = [], []
    for target in targets:
        host = (urlparse(target if '://' in target else f'http://{target}').hostname or '').lower()
        (dropped if host in duplicates else kept).append(target)
    return kept, dropped
