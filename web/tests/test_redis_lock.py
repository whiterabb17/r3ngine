"""renewed_lock keeps a Redis lock for as long as the work under it runs."""
import threading
import unittest
from unittest.mock import MagicMock

from redis.exceptions import LockError, LockNotOwnedError

from reNgine.utils.redis_lock import renewed_lock


def _client():
    lock = MagicMock()
    client = MagicMock()
    client.lock.return_value = lock
    return client, lock


class RenewedLockTests(unittest.TestCase):

    def test_lock_is_shared_with_the_renewal_thread_and_released(self) -> None:
        client, lock = _client()
        with renewed_lock(client, 'fuzz-key', ttl=300):
            lock.acquire.assert_called_once()
        client.lock.assert_called_once_with('fuzz-key', timeout=300, thread_local=False)
        lock.release.assert_called_once()

    def test_lock_is_renewed_while_the_work_runs(self) -> None:
        client, lock = _client()
        renewed = threading.Event()
        lock.reacquire.side_effect = lambda: renewed.set()
        with renewed_lock(client, 'fuzz-key', renew_every=0.01):
            self.assertTrue(renewed.wait(5), 'the lock was never renewed')

    def test_an_expired_lock_does_not_fail_the_work(self) -> None:
        # The bug this replaces: a 1800 s TTL ran out under a 70-minute fuzz and
        # release() raised LockNotOwnedError after all the work was done.
        client, lock = _client()
        lock.release.side_effect = LockNotOwnedError("Cannot release a lock that's no longer owned")
        with self.assertLogs('reNgine.utils.redis_lock', level='WARNING'):
            with renewed_lock(client, 'fuzz-key'):
                pass

    def test_losing_the_lock_mid_run_is_logged_not_raised(self) -> None:
        client, lock = _client()
        lost = threading.Event()

        def reacquire() -> None:
            lost.set()
            raise LockError('Cannot reacquire a lock that is no longer owned')

        lock.reacquire.side_effect = reacquire
        with self.assertLogs('reNgine.utils.redis_lock', level='WARNING'):
            with renewed_lock(client, 'fuzz-key', renew_every=0.01):
                self.assertTrue(lost.wait(5))

    def test_errors_from_the_work_propagate_and_the_lock_is_still_released(self) -> None:
        client, lock = _client()
        with self.assertRaises(RuntimeError):
            with renewed_lock(client, 'fuzz-key'):
                raise RuntimeError('ffuf failed')
        lock.release.assert_called_once()
