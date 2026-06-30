"""
Temporal Client Provider for r3ngine.

Creates a fresh Temporal client per operation. Callers wrap operations in
asyncio.new_event_loop(); a temporalio Client is bound to the event loop it
was created in, so caching across loop boundaries raises gRPC errors. The
SDK manages its own gRPC channel pool — per-operation Client() costs ~5ms
locally and is the correct pattern for synchronous Django callers.
"""
import asyncio
import logging
import os

from temporalio.client import Client

logger = logging.getLogger(__name__)


class TemporalConnectionError(RuntimeError):
    """Raised when the Temporal client cannot connect within the timeout."""


def run_and_close(loop: asyncio.AbstractEventLoop, coro):
    """Run coro synchronously from a non-async context (Django view, activity thread).

    Uses asyncio.run() which internally:
      1. Creates its own managed event loop
      2. Runs the coroutine to completion
      3. Cancels ALL remaining tasks (including Temporal gRPC background tasks)
      4. Awaits their cancellation before closing the loop

    The `loop` argument is kept for call-site compatibility but is immediately
    closed unused — asyncio.run() must manage its own loop to guarantee cleanup.
    Passing a pre-created loop caused 'Task was destroyed but it is pending!'
    because gRPC-backed futures cannot be cancelled synchronously via task.cancel().
    """
    try:
        loop.close()
    except Exception:
        pass
    return asyncio.run(coro)


class TemporalClientProvider:
    """Factory for Temporal client connections.

    Always creates a fresh connection. Do not add caching — see module
    docstring for why caching fails across asyncio.run() boundaries.
    """

    @classmethod
    async def get_client(cls) -> Client:
        temporal_host = os.environ.get("TEMPORAL_HOST", "temporal:7233")
        namespace = os.environ.get("TEMPORAL_NAMESPACE", "default")
        try:
            return await asyncio.wait_for(
                Client.connect(temporal_host, namespace=namespace),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            logger.error(
                f"Connection to Temporal host '{temporal_host}' timed out after 10 seconds."
            )
            raise TemporalConnectionError(
                f"Temporal connection to '{temporal_host}' timed out after 10s."
            )

    @classmethod
    def cancel_workflow(cls, workflow_id: str) -> None:
        """Cancel a running Temporal workflow synchronously (safe for Django views)."""
        loop = asyncio.new_event_loop()

        async def _cancel():
            client = await cls.get_client()
            handle = client.get_workflow_handle(workflow_id)
            await handle.cancel()

        run_and_close(loop, _cancel())

    @classmethod
    def pause_workflow(cls, workflow_id: str) -> None:
        """Send a pause signal to a running Temporal workflow synchronously."""
        loop = asyncio.new_event_loop()

        async def _pause():
            client = await cls.get_client()
            handle = client.get_workflow_handle(workflow_id)
            await handle.signal("pause")

        run_and_close(loop, _pause())

    @classmethod
    def resume_workflow(cls, workflow_id: str) -> None:
        """Send a resume signal to a running Temporal workflow synchronously."""
        loop = asyncio.new_event_loop()

        async def _resume():
            client = await cls.get_client()
            handle = client.get_workflow_handle(workflow_id)
            await handle.signal("resume")

        run_and_close(loop, _resume())
