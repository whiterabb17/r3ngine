"""Split a long per-host tool run into batches.

A single activity running a tool over every live host of a large target can
outlast any reasonable time limit, and a retry then starts it all again. The
scan instead runs the tool over batches of hosts, each its own activity with its
own time limit. This module only plans the batches; it is pure so the plan is
deterministic and testable without a database.
"""
import math
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

DEFAULT_BATCH_SIZE = 25
DEFAULT_MAX_BATCHES = 200
DEFAULT_MAX_PARALLEL = 2
DEFAULT_BATCH_TIMEOUT_MINUTES = 120
DEFAULT_MAX_TOTAL_HOURS = 12


@dataclass(frozen=True)
class BatchingConfig:
    """`batching:` block of a tool's engine YAML section, with every value bounded."""

    enabled: bool = True
    batch_size: int = DEFAULT_BATCH_SIZE
    max_batches: int = DEFAULT_MAX_BATCHES
    # The Python worker runs 10 activities at once for every scan, so keep this low.
    max_parallel: int = DEFAULT_MAX_PARALLEL
    batch_timeout_minutes: int = DEFAULT_BATCH_TIMEOUT_MINUTES
    max_total_hours: int = DEFAULT_MAX_TOTAL_HOURS

    def as_dict(self) -> dict:
        return asdict(self)


_BOUNDS = {
    'batch_size': (1, 500),
    'max_batches': (1, 300),
    'max_parallel': (1, 5),
    'batch_timeout_minutes': (10, 720),
    'max_total_hours': (1, 72),
}


def batching_config(section: dict | None) -> BatchingConfig:
    """Read `section['batching']`, falling back to the default for any bad value."""
    raw = (section or {}).get('batching')
    raw = raw if isinstance(raw, dict) else {}
    values = {'enabled': bool(raw.get('enabled', True))}
    defaults = BatchingConfig()
    for key, (low, high) in _BOUNDS.items():
        try:
            value = int(raw.get(key, getattr(defaults, key)))
        except (TypeError, ValueError):
            value = getattr(defaults, key)
        values[key] = min(max(value, low), high)
    return BatchingConfig(**values)


def target_host(target: str) -> str:
    """`host[:port]` of a URL, or the target itself when it is a bare host."""
    netloc = urlparse(target).netloc if '://' in target else target
    return (netloc or target).lower()


def plan_batches(targets: list[str], batch_size: int, max_batches: int) -> list[list[str]]:
    """Group targets by host and pack the hosts into batches.

    Every target of one host stays in one batch: tools keep per-host state
    (output files, the fuzz signature counters) and per-host politeness depends
    on it. Hosts are sorted, so the same targets always give the same plan. The
    batch size grows when needed so there are never more than `max_batches`.

    Returns:
        Batches of targets, each covering at most the effective batch size of hosts.
    """
    by_host: dict[str, list[str]] = {}
    for target in targets:
        host_targets = by_host.setdefault(target_host(target), [])
        if target not in host_targets:
            host_targets.append(target)
    if not by_host:
        return []

    hosts = sorted(by_host)
    size = max(batch_size, math.ceil(len(hosts) / max(max_batches, 1)), 1)
    return [
        [target for host in hosts[start:start + size] for target in by_host[host]]
        for start in range(0, len(hosts), size)
    ]
