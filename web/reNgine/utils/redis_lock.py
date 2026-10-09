"""A Redis lock that stays held for as long as the work under it runs."""
import contextlib
import logging
import threading
from typing import Iterator

from redis import Redis
from redis.exceptions import LockError
from redis.lock import Lock

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def renewed_lock(client: Redis, name: str, ttl: float = 300, renew_every: float = 60) -> Iterator[Lock]:
    """Hold ``name`` while the block runs, however long that takes.

    A fixed TTL has to guess the run time: too short and the lock expires under
    the work (and releasing it then raises LockNotOwnedError), too long and a
    killed worker blocks the retry until it runs out. Here a background thread
    renews the lock every ``renew_every`` seconds, so ``ttl`` only bounds how
    long a dead holder keeps it. Losing the lock anyway (Redis restart) is
    logged; it does not fail the work under it.
    """
    # The renewal thread needs the token, which thread_local=True would hide from it.
    lock = client.lock(name, timeout=ttl, thread_local=False)
    lock.acquire()
    stop = threading.Event()

    def renew() -> None:
        while not stop.wait(renew_every):
            try:
                lock.reacquire()
            except LockError:
                logger.warning("Lost Redis lock %s while the work under it was still running", name)
                return

    renewer = threading.Thread(target=renew, name=f"lock-renew-{name}", daemon=True)
    renewer.start()
    try:
        yield lock
    finally:
        stop.set()
        renewer.join()
        try:
            lock.release()
        except LockError:
            logger.warning("Redis lock %s had already expired when it was released", name)
