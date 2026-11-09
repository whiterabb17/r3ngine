"""Redis-backed queue + dedupe for OsintStaging writes.

Concurrent OSINT producers (gosearch threads, SpiderFoot batches, Spoofy)
enqueue candidates here. Redis collapses duplicates *before* any DB write:

* ``pending`` hash — one JSON payload per fingerprint waiting to flush
  (HSET last-wins; concurrent producers share a single field)
* flush lock — only one drain at a time per scan

``flush_osint_staging`` drains ``pending`` under a Redis lock and upserts
rows with ``MultipleObjectsReturned`` safety for any pre-existing dupes.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

import redis
from django.conf import settings
from django.core.exceptions import MultipleObjectsReturned
from django.db import IntegrityError

from reNgine.utils.redis_lock import renewed_lock

logger = logging.getLogger(__name__)

_KEY_TTL_SECONDS = 7 * 24 * 60 * 60  # keep keys around for long-running scans
_FLUSH_LOCK_TTL = 120.0


def _redis() -> redis.StrictRedis:
    return redis.StrictRedis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD,
        db=0,
        decode_responses=True,
    )


def _pending_key(scan_id: int) -> str:
    return f"osint:staging:pending:{scan_id}"


def _flush_lock_key(scan_id: int) -> str:
    return f"osint:staging:flush:{scan_id}"


def staging_fingerprint(osint_type: str, content: str) -> str:
    """Stable fingerprint used for Redis dedupe (type + content)."""
    raw = f"{osint_type}\0{content}".encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()


def enqueue_osint_staging(
    *,
    scan_history_id: int,
    target_domain_id: int | None,
    osint_type: str,
    content: str,
    source: str = "",
    confidence: int = 0,
    metadata: dict | None = None,
    status: str = "pending",
    redis_client: redis.StrictRedis | None = None,
) -> bool:
    """Queue a staging candidate. Returns True if newly queued, False if updated.

    Concurrent producers for the same ``(osint_type, content)`` share one pending
    hash field. A later enqueue overwrites the payload (last-wins metadata /
    confidence) without creating a second queue entry.
    """
    if not content:
        return False

    r = redis_client or _redis()
    scan_id = int(scan_history_id)
    fp = staging_fingerprint(osint_type, content)
    pending = _pending_key(scan_id)

    payload = {
        "scan_history_id": scan_id,
        "target_domain_id": target_domain_id,
        "osint_type": osint_type,
        "content": content,
        "source": source or "",
        "confidence": int(confidence or 0),
        "metadata": metadata or {},
        "status": status or "pending",
        "fingerprint": fp,
    }
    # HSET collapses concurrent producers onto one pending field.
    created = r.hset(pending, fp, json.dumps(payload, default=str))
    r.expire(pending, _KEY_TTL_SECONDS)
    return bool(created)


def _resolve_target_domain_id(payload: dict[str, Any]) -> int | None:
    """Prefer payload domain; fall back to the scan's domain for non-null FK."""
    domain_id = payload.get("target_domain_id")
    if domain_id is not None:
        return int(domain_id)

    from startScan.models import ScanHistory

    scan_id = payload.get("scan_history_id")
    if not scan_id:
        return None
    return (
        ScanHistory.objects.filter(pk=scan_id)
        .values_list("domain_id", flat=True)
        .first()
    )


def _defaults_for_upsert(payload: dict[str, Any], *, existing_status: str | None) -> dict:
    """Build update defaults without downgrading validated/ignored triage."""
    defaults = {
        "source": payload.get("source") or "",
        "confidence": int(payload.get("confidence") or 0),
        "metadata": payload.get("metadata") or {},
    }
    # Never reset operator/agent triage back to pending on a re-flush.
    if existing_status in (None, "pending"):
        defaults["status"] = payload.get("status") or "pending"
    return defaults


def _upsert_staging_row(payload: dict[str, Any]) -> None:
    """Write one pending payload to Postgres, tolerating existing duplicates."""
    from startScan.models import OsintStaging

    scan_id = payload["scan_history_id"]
    domain_id = _resolve_target_domain_id(payload)
    osint_type = payload["osint_type"]
    content = payload["content"]

    if domain_id is None:
        raise ValueError(
            f"OsintStaging flush missing target_domain_id for scan={scan_id}"
        )

    lookup = {
        "scan_history_id": scan_id,
        "target_domain_id": domain_id,
        "osint_type": osint_type,
        "content": content,
    }

    existing = OsintStaging.objects.filter(**lookup).order_by("id").first()
    defaults = _defaults_for_upsert(
        payload,
        existing_status=existing.status if existing else None,
    )

    try:
        OsintStaging.objects.update_or_create(**lookup, defaults=defaults)
    except MultipleObjectsReturned:
        pass
    except IntegrityError:
        # Concurrent insert won the race; fall through to update the survivor.
        pass
    else:
        return

    qs = OsintStaging.objects.filter(**lookup).order_by("id")
    row = qs.first()
    if row is None:
        # Extremely unlikely: IntegrityError without a surviving row.
        create_defaults = _defaults_for_upsert(payload, existing_status=None)
        OsintStaging.objects.create(
            scan_history_id=scan_id,
            target_domain_id=domain_id,
            osint_type=osint_type,
            content=content,
            **create_defaults,
        )
        return

    defaults = _defaults_for_upsert(payload, existing_status=row.status)
    for field, value in defaults.items():
        setattr(row, field, value)
    row.save(update_fields=list(defaults.keys()))

    # Collapse leftover duplicates left by the old race-prone path.
    dup_ids = list(qs.exclude(pk=row.pk).values_list("pk", flat=True))
    if dup_ids:
        OsintStaging.objects.filter(pk__in=dup_ids).delete()
        logger.info(
            "Collapsed %d duplicate OsintStaging row(s) for scan=%s type=%s",
            len(dup_ids),
            scan_id,
            osint_type,
        )


def flush_osint_staging(
    scan_history_id: int,
    *,
    redis_client: redis.StrictRedis | None = None,
) -> int:
    """Drain the pending hash for ``scan_history_id`` into OsintStaging rows.

    Returns the number of payloads written (including updates).
    """
    r = redis_client or _redis()
    scan_id = int(scan_history_id)
    pending = _pending_key(scan_id)
    written = 0

    with renewed_lock(r, _flush_lock_key(scan_id), ttl=_FLUSH_LOCK_TTL, renew_every=30):
        items = r.hgetall(pending) or {}
        if not items:
            return 0

        for fp, raw in items.items():
            try:
                payload = json.loads(raw)
            except (TypeError, json.JSONDecodeError):
                logger.warning(
                    "Dropping corrupt OsintStaging queue item scan=%s fp=%s",
                    scan_id,
                    fp,
                )
                r.hdel(pending, fp)
                continue

            try:
                _upsert_staging_row(payload)
            except Exception:
                logger.exception(
                    "Failed to flush OsintStaging item scan=%s type=%s",
                    scan_id,
                    payload.get("osint_type"),
                )
                # Leave in pending for a later flush retry.
                continue

            r.hdel(pending, fp)
            written += 1

    return written


def enqueue_and_flush_osint_staging(**kwargs) -> bool:
    """Enqueue one candidate and immediately flush that scan's pending set."""
    redis_client = kwargs.pop("redis_client", None)
    queued = enqueue_osint_staging(redis_client=redis_client, **kwargs)
    scan_id = kwargs["scan_history_id"]
    flush_osint_staging(scan_id, redis_client=redis_client)
    return queued
