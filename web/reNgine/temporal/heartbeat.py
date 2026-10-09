"""Background heartbeats for sync activities whose work cannot heartbeat itself.

A workflow that sets ``heartbeat_timeout`` expects the activity to heartbeat at
least that often; one that never does is timed out by the server after that
interval however healthy it is, then retried by its retry policy. Activities
that wrap a long call with no progress hook (a task function, a blocking wait on
another workflow) use ``keep_alive`` instead.
"""
import contextvars
import functools
import logging
import threading
from typing import Callable, TypeVar

from temporalio import activity
from temporalio.exceptions import CancelledError

logger = logging.getLogger(__name__)

HEARTBEAT_INTERVAL_SECONDS = 30

F = TypeVar('F', bound=Callable)


def keep_alive(func: F) -> F:
    """Heartbeat every HEARTBEAT_INTERVAL_SECONDS while ``func`` runs.

    Apply it under ``@activity.defn``. The heartbeat thread runs in a copy of
    the caller's contextvars, which is what carries the activity context;
    a plain thread would fail every heartbeat with "Not in activity context".
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        done = threading.Event()
        activity_context = contextvars.copy_context()

        def beat():
            while not done.wait(HEARTBEAT_INTERVAL_SECONDS):
                try:
                    activity.heartbeat()
                except CancelledError:
                    # The wrapped call has no cancellation hook; stop beating so
                    # the server can time the attempt out.
                    logger.warning('Activity %s cancelled; heartbeats stopped', func.__name__)
                    return
                except Exception:
                    logger.warning('Heartbeat failed for activity %s', func.__name__, exc_info=True)

        thread = threading.Thread(target=activity_context.run, args=(beat,), daemon=True)
        thread.start()
        try:
            return func(*args, **kwargs)
        finally:
            done.set()
            thread.join(timeout=5)

    return wrapper  # type: ignore[return-value]
