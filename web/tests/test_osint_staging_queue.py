"""Redis queue + dedupe for OsintStaging writes."""
from __future__ import annotations

import json
import threading

from django.test import TestCase
from django.utils import timezone

from reNgine.osint.staging_queue import (
    enqueue_osint_staging,
    flush_osint_staging,
    staging_fingerprint,
)
from scanEngine.models import EngineType
from startScan.models import OsintStaging, ScanHistory
from targetApp.models import Domain
from tests.redis_fakes import FakeRedis, patch_osint_staging_redis

# Synthetic fixture URLs only — no real social profiles or personal identifiers.
_FIXTURE_URL_A = "https://social.example/presence/fixture-a"
_FIXTURE_URL_B = "https://social.example/presence/fixture-b"
_FIXTURE_URL_SHARED = "https://social.example/presence/shared"


class OsintStagingQueueTests(TestCase):
    def setUp(self) -> None:
        self.domain = Domain.objects.create(
            name="staging-queue.example.com",
            insert_date=timezone.now(),
        )
        engine = EngineType.objects.create(engine_name="SQ", yaml_configuration="")
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=engine,
            scan_status=0,
            start_scan_date=timezone.now(),
        )
        self.redis = FakeRedis()
        patch_osint_staging_redis(self, self.redis)

    def test_fingerprint_stable(self) -> None:
        a = staging_fingerprint("Social/Web Presence", _FIXTURE_URL_A)
        b = staging_fingerprint("Social/Web Presence", _FIXTURE_URL_A)
        c = staging_fingerprint("Social/Web Presence", _FIXTURE_URL_B)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_enqueue_dedupes_pending_last_wins(self) -> None:
        kwargs = dict(
            scan_history_id=self.scan.id,
            target_domain_id=self.domain.id,
            osint_type="Social/Web Presence",
            content=_FIXTURE_URL_A,
            source="gosearch",
            confidence=80,
            metadata={"username": "fixture-user"},
            redis_client=self.redis,
        )
        self.assertTrue(enqueue_osint_staging(**kwargs))
        # Same fingerprint while pending: HSET update, not a new field.
        self.assertFalse(
            enqueue_osint_staging(
                **{
                    **kwargs,
                    "confidence": 90,
                    "metadata": {"username": "fixture-user-2"},
                }
            )
        )
        pending = self.redis.hgetall(f"osint:staging:pending:{self.scan.id}")
        self.assertEqual(len(pending), 1)
        payload = json.loads(next(iter(pending.values())))
        self.assertEqual(payload["confidence"], 90)
        self.assertEqual(payload["metadata"]["username"], "fixture-user-2")

        written = flush_osint_staging(self.scan.id, redis_client=self.redis)
        self.assertEqual(written, 1)
        self.assertEqual(OsintStaging.objects.filter(scan_history=self.scan).count(), 1)

        # After flush, a later enqueue can refresh the row (update, not duplicate).
        self.assertTrue(
            enqueue_osint_staging(
                **{
                    **kwargs,
                    "confidence": 95,
                    "metadata": {"username": "fixture-user-3"},
                }
            )
        )
        flush_osint_staging(self.scan.id, redis_client=self.redis)
        rows = OsintStaging.objects.filter(scan_history=self.scan)
        self.assertEqual(rows.count(), 1)
        self.assertEqual(rows.first().confidence, 95)
        self.assertEqual(rows.first().metadata["username"], "fixture-user-3")

    def test_flush_preserves_validated_status(self) -> None:
        OsintStaging.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            osint_type="Social/Web Presence",
            content=_FIXTURE_URL_A,
            source="gosearch",
            confidence=50,
            status="validated",
            metadata={"kept": True},
        )
        enqueue_osint_staging(
            scan_history_id=self.scan.id,
            target_domain_id=self.domain.id,
            osint_type="Social/Web Presence",
            content=_FIXTURE_URL_A,
            source="gosearch",
            confidence=90,
            metadata={"username": "fixture-user"},
            status="pending",
            redis_client=self.redis,
        )
        flush_osint_staging(self.scan.id, redis_client=self.redis)

        row = OsintStaging.objects.get(
            scan_history=self.scan,
            content=_FIXTURE_URL_A,
        )
        self.assertEqual(row.status, "validated")
        self.assertEqual(row.confidence, 90)
        self.assertEqual(row.metadata["username"], "fixture-user")

    def test_flush_falls_back_to_scan_domain_when_payload_domain_missing(self) -> None:
        enqueue_osint_staging(
            scan_history_id=self.scan.id,
            target_domain_id=None,
            osint_type="domain_security",
            content=self.domain.name,
            source="spoofy",
            confidence=95,
            metadata={"spoofcheck": {"spoofable": False}},
            redis_client=self.redis,
        )
        written = flush_osint_staging(self.scan.id, redis_client=self.redis)
        self.assertEqual(written, 1)
        row = OsintStaging.objects.get(scan_history=self.scan)
        self.assertEqual(row.target_domain_id, self.domain.id)

    def test_flush_collapses_preexisting_db_duplicates(self) -> None:
        OsintStaging.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            osint_type="Social/Web Presence",
            content=_FIXTURE_URL_B,
            source="old",
            confidence=10,
        )
        OsintStaging.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            osint_type="Social/Web Presence",
            content=_FIXTURE_URL_B,
            source="old2",
            confidence=20,
        )
        self.assertEqual(
            OsintStaging.objects.filter(
                scan_history=self.scan,
                content=_FIXTURE_URL_B,
            ).count(),
            2,
        )

        enqueue_osint_staging(
            scan_history_id=self.scan.id,
            target_domain_id=self.domain.id,
            osint_type="Social/Web Presence",
            content=_FIXTURE_URL_B,
            source="gosearch",
            confidence=80,
            redis_client=self.redis,
        )
        flush_osint_staging(self.scan.id, redis_client=self.redis)

        rows = OsintStaging.objects.filter(
            scan_history=self.scan,
            content=_FIXTURE_URL_B,
        )
        self.assertEqual(rows.count(), 1)
        self.assertEqual(rows.first().source, "gosearch")
        self.assertEqual(rows.first().confidence, 80)

    def test_concurrent_enqueue_single_row(self) -> None:
        errors: list[BaseException] = []

        def worker(n: int) -> None:
            try:
                enqueue_osint_staging(
                    scan_history_id=self.scan.id,
                    target_domain_id=self.domain.id,
                    osint_type="Social/Web Presence",
                    content=_FIXTURE_URL_SHARED,
                    source="gosearch",
                    confidence=70 + n,
                    metadata={"n": n},
                    redis_client=self.redis,
                )
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        pending = self.redis.hgetall(f"osint:staging:pending:{self.scan.id}")
        self.assertEqual(len(pending), 1)

        flush_osint_staging(self.scan.id, redis_client=self.redis)
        self.assertEqual(
            OsintStaging.objects.filter(
                scan_history=self.scan,
                content=_FIXTURE_URL_SHARED,
            ).count(),
            1,
        )
