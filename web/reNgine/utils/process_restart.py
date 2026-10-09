"""Restart the service this process belongs to without a Docker API.

Every application container runs under ``init: true`` with ``restart: always``
(``docker/docker-compose.yml``). Terminating the service's root process — the
gunicorn master under tini, or the entrypoint shell in DEBUG mode — makes the
container exit, and Docker's restart policy starts it again from its
entrypoint. That is the same effect the old ``docker restart`` had, minus the
need to mount ``/var/run/docker.sock`` into the container.

The Temporal orchestrator already restarts itself this way (``os.kill(SIGTERM)``
on an ``orchestrator_control`` Redis message); this module gives the web
container the same mechanism.

Leaf module: stdlib only.
"""
from __future__ import annotations

import logging
import os
import signal
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# PID-1 programs that only supervise and forward signals to their child. When
# one of these is PID 1 the service root is the process directly under it.
_INIT_COMMS = frozenset({'docker-init', 'tini', 'dumb-init', 'init', 'systemd', 's6-svscan'})

DEFAULT_RESTART_DELAY_SECONDS = 3.0


def _read_proc(pid: int, name: str) -> Optional[str]:
    try:
        with open(f'/proc/{pid}/{name}', encoding='utf-8', errors='replace') as fh:
            return fh.read()
    except OSError:
        return None


def parent_pid(pid: int) -> Optional[int]:
    """Parent of ``pid`` from /proc, or None when it cannot be read."""
    stat = _read_proc(pid, 'stat')
    if not stat:
        return None
    # "pid (comm) state ppid ..." — comm may contain spaces and parentheses.
    tail = stat.rsplit(')', 1)[-1].split()
    try:
        return int(tail[1])
    except (IndexError, ValueError):
        return None


def process_comm(pid: int) -> str:
    comm = _read_proc(pid, 'comm')
    return (comm or '').strip()


def service_root_pid(pid: Optional[int] = None) -> int:
    """PID whose termination ends the container's main process.

    Walks up from ``pid`` (default: this process) to the ancestor directly
    below PID 1. When PID 1 is a plain init (tini, docker-init) that ancestor
    is the service root: gunicorn's master, or the entrypoint shell that is
    still waiting on ``runserver``. When there is no init layer, PID 1 is the
    service itself (gunicorn started with ``exec`` and no ``init: true``) and
    the target is PID 1.
    """
    start = os.getpid() if pid is None else pid
    if start == 1:
        return 1
    current = start
    while True:
        parent = parent_pid(current)
        if parent in (None, 0, 1):
            break
        current = parent
    if current == start and process_comm(1) not in _INIT_COMMS:
        # Our parent is PID 1 and PID 1 is not an init: it is the master that
        # would simply respawn us, so it has to be the one that stops.
        return 1
    return current


def restart_service_now(*, kill: Callable[[int, int], None] = os.kill) -> int:
    """Send SIGTERM to the service root and return the PID that was signalled.

    gunicorn treats SIGTERM as a graceful shutdown (in-flight requests get
    ``graceful_timeout`` to finish); the container then exits and
    ``restart: always`` brings it back.
    """
    target = service_root_pid()
    logger.warning('Restarting service: SIGTERM to pid %s (%s)', target, process_comm(target) or 'unknown')
    kill(target, signal.SIGTERM)
    return target


def schedule_service_restart(
    delay_seconds: float = DEFAULT_RESTART_DELAY_SECONDS,
    *,
    reason: str = '',
    kill: Callable[[int, int], None] = os.kill,
    sleep: Callable[[float], None] = time.sleep,
) -> threading.Thread:
    """Restart the service after ``delay_seconds`` from a daemon thread.

    The delay lets the HTTP response that requested the restart reach the
    client before the connection is severed.
    """

    def _run() -> None:
        sleep(max(0.0, delay_seconds))
        try:
            restart_service_now(kill=kill)
        except Exception:
            logger.exception('Service restart failed (%s)', reason or 'no reason given')

    thread = threading.Thread(target=_run, name='service-restart', daemon=True)
    thread.start()
    return thread
