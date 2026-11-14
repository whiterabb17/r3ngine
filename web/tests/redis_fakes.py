"""In-memory Redis stand-in for unit tests that exercise staging_queue."""
from __future__ import annotations

import threading
from contextlib import contextmanager
from unittest.mock import patch


class FakeRedis:
    """Minimal Redis subset: hashes, expire, and lock."""

    def __init__(self) -> None:
        self.hashes: dict[str, dict[str, str]] = {}
        self._lock = threading.Lock()

    def hset(self, key: str, field: str, value: str) -> int:
        bucket = self.hashes.setdefault(key, {})
        created = 0 if field in bucket else 1
        bucket[field] = value
        return created

    def hgetall(self, key: str) -> dict[str, str]:
        return dict(self.hashes.get(key, {}))

    def hdel(self, key: str, *fields: str) -> int:
        bucket = self.hashes.get(key, {})
        deleted = 0
        for field in fields:
            if field in bucket:
                del bucket[field]
                deleted += 1
        return deleted

    def expire(self, key: str, _ttl: int) -> bool:
        return True

    def lock(self, name: str, timeout: float = 300, thread_local: bool = True):
        class _Lock:
            def acquire(self_inner) -> bool:
                self._lock.acquire()
                return True

            def reacquire(self_inner) -> bool:
                return True

            def release(self_inner) -> None:
                self._lock.release()

        return _Lock()


@contextmanager
def passthrough_renewed_lock(client, name, ttl=300, renew_every=60):
    lock = client.lock(name, timeout=ttl, thread_local=False)
    lock.acquire()
    try:
        yield lock
    finally:
        lock.release()


def patch_osint_staging_redis(test_case, redis_client: FakeRedis | None = None) -> FakeRedis:
    """Point staging_queue at an in-memory Redis for the lifetime of ``test_case``."""
    client = redis_client or FakeRedis()
    redis_patch = patch("reNgine.osint.staging_queue._redis", return_value=client)
    lock_patch = patch(
        "reNgine.osint.staging_queue.renewed_lock",
        passthrough_renewed_lock,
    )
    redis_patch.start()
    lock_patch.start()
    test_case.addCleanup(redis_patch.stop)
    test_case.addCleanup(lock_patch.stop)
    return client
