"""
Temporal Schedule helpers for scan scheduling.

Called from synchronous Django views (schedule_scan, schedule_organization_scan)
to create Temporal Schedules in place of django_celery_beat PeriodicTask rows.

Each helper:
  1. Creates a Temporal Schedule via asyncio.run() (sync→async bridge).
  2. Writes a TemporalSchedule DB record for the management views (Phase 4E).
  3. Returns the TemporalSchedule instance.
"""

import asyncio
import datetime
import logging
import uuid

from temporalio.client import (
    Schedule,
    ScheduleActionStartWorkflow,
    ScheduleCalendarSpec,
    ScheduleIntervalSpec,
    ScheduleOverlapPolicy,
    SchedulePolicy,
    ScheduleRange,
    ScheduleSpec,
    ScheduleState,
)
from temporalio.service import RPCError, RPCStatusCode
from reNgine.temporal_client import TemporalClientProvider

logger = logging.getLogger(__name__)

_FREQUENCY_TO_SECONDS = {
    'minutes': 60,
    'hours': 3600,
    'days': 86400,
    'weeks': 7 * 86400,
    'months': 30 * 86400,
}


def interval_to_seconds(frequency_value: int, frequency_type: str) -> int:
    """Convert a (value, type) pair from the schedule form to total seconds."""
    return frequency_value * _FREQUENCY_TO_SECONDS.get(frequency_type, 3600)


def _create_periodic_temporal_schedule(
    name: str,
    interval_seconds: int,
    workflow_args: dict,
    domain_id: int = None,
) -> object:
    """Create a repeating Temporal Schedule and a TemporalSchedule DB record.

    The schedule fires every `interval_seconds` seconds and starts
    ScheduledScanWorkflow with `workflow_args` as its input.

    Args:
        name: Human-readable schedule name (shown in UI).
        interval_seconds: Repeat interval in seconds.
        workflow_args: Dict passed to ScheduledScanWorkflow (domain_id, engine_id, etc.).
        domain_id: Optional FK for the TemporalSchedule DB record.

    Returns:
        TemporalSchedule: The newly created DB record.
    """
    from startScan.models import TemporalSchedule

    schedule_id = f"scan-periodic-{uuid.uuid4().hex[:12]}"

    async def _create():
        client = await TemporalClientProvider.get_client()
        await client.create_schedule(
            schedule_id,
            Schedule(
                action=ScheduleActionStartWorkflow(
                    "ScheduledScanWorkflow",
                    args=[workflow_args],
                    id=f"{schedule_id}-run",
                    task_queue="python-orchestrator-queue",
                ),
                spec=ScheduleSpec(
                    intervals=[ScheduleIntervalSpec(
                        every=datetime.timedelta(seconds=interval_seconds)
                    )],
                ),
                policy=SchedulePolicy(overlap=ScheduleOverlapPolicy.SKIP),
                state=ScheduleState(note=f"Periodic scan: {name}"),
            ),
        )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_create())
    finally:
        loop.close()

    domain = None
    if domain_id:
        from targetApp.models import Domain
        try:
            domain = Domain.objects.get(id=domain_id)
        except Domain.DoesNotExist:
            pass

    record = TemporalSchedule.objects.create(
        schedule_id=schedule_id,
        name=name,
        workflow_type='ScheduledScanWorkflow',
        workflow_args=workflow_args,
        interval_seconds=interval_seconds,
        is_active=True,
        domain=domain,
    )
    logger.info("[ScheduleUtils] Created periodic schedule '%s' every %ss", schedule_id, interval_seconds)
    return record


def _create_clocked_temporal_schedule(
    name: str,
    clocked_time,
    workflow_args: dict,
    domain_id: int = None,
) -> object:
    """Create a one-shot clocked Temporal Schedule and a TemporalSchedule DB record.

    The schedule fires once at `clocked_time` then exhausts itself.

    Args:
        name: Human-readable schedule name.
        clocked_time: datetime or ISO-format string for when to fire.
        workflow_args: Dict passed to ScheduledScanWorkflow.
        domain_id: Optional FK for the TemporalSchedule DB record.

    Returns:
        TemporalSchedule: The newly created DB record.
    """
    from startScan.models import TemporalSchedule

    if isinstance(clocked_time, str):
        clocked_dt = datetime.datetime.fromisoformat(clocked_time)
    else:
        clocked_dt = clocked_time

    # Strip timezone for ScheduleCalendarSpec (uses server-side timezone)
    if hasattr(clocked_dt, 'tzinfo') and clocked_dt.tzinfo is not None:
        clocked_dt = clocked_dt.replace(tzinfo=None)

    schedule_id = f"scan-clocked-{uuid.uuid4().hex[:12]}"

    async def _create():
        client = await TemporalClientProvider.get_client()
        await client.create_schedule(
            schedule_id,
            Schedule(
                action=ScheduleActionStartWorkflow(
                    "ScheduledScanWorkflow",
                    args=[workflow_args],
                    id=f"{schedule_id}-run",
                    task_queue="python-orchestrator-queue",
                ),
                spec=ScheduleSpec(
                    calendars=[ScheduleCalendarSpec(
                        year=[ScheduleRange(clocked_dt.year)],
                        month=[ScheduleRange(clocked_dt.month)],
                        day_of_month=[ScheduleRange(clocked_dt.day)],
                        hour=[ScheduleRange(clocked_dt.hour)],
                        minute=[ScheduleRange(clocked_dt.minute)],
                    )],
                ),
                policy=SchedulePolicy(overlap=ScheduleOverlapPolicy.SKIP),
                state=ScheduleState(
                    limited_actions=True,
                    remaining_actions=1,
                    note=f"Clocked scan: {name}",
                ),
            ),
        )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_create())
    finally:
        loop.close()

    domain = None
    if domain_id:
        from targetApp.models import Domain
        try:
            domain = Domain.objects.get(id=domain_id)
        except Domain.DoesNotExist:
            pass

    record = TemporalSchedule.objects.create(
        schedule_id=schedule_id,
        name=name,
        workflow_type='ScheduledScanWorkflow',
        workflow_args=workflow_args,
        clocked_time=clocked_dt,
        one_off=True,
        is_active=True,
        domain=domain,
    )
    logger.info("[ScheduleUtils] Created clocked schedule '%s' at %s", schedule_id, clocked_dt)
    return record


async def delete_schedule_if_exists(client, schedule_id: str) -> bool:
    """Delete a Temporal Schedule; return False if it did not exist.

    Only not-found is ignored. Anything else (Temporal unreachable, permission
    denied) is raised, since a schedule that survives keeps starting workflows.
    """
    try:
        await client.get_schedule_handle(schedule_id).delete()
    except RPCError as exc:
        if exc.status == RPCStatusCode.NOT_FOUND:
            return False
        raise
    return True


def _delete_temporal_schedule_by_id(schedule_id: str) -> None:
    """Delete a Temporal Schedule by ID. Ignores not-found, raises other errors."""
    async def _delete():
        client = await TemporalClientProvider.get_client()
        await delete_schedule_if_exists(client, schedule_id)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_delete())
    finally:
        loop.close()
    logger.info("[ScheduleUtils] Deleted schedule '%s'", schedule_id)


def _pause_temporal_schedule(schedule_id: str) -> None:
    """Pause a Temporal Schedule (stops future firings without deleting it)."""
    async def _pause():
        client = await TemporalClientProvider.get_client()
        handle = client.get_schedule_handle(schedule_id)
        await handle.pause(note="Paused via r3ngine UI")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_pause())
    finally:
        loop.close()
    logger.info("[ScheduleUtils] Paused schedule '%s'", schedule_id)


def _unpause_temporal_schedule(schedule_id: str) -> None:
    """Unpause a Temporal Schedule (resumes future firings)."""
    async def _unpause():
        client = await TemporalClientProvider.get_client()
        handle = client.get_schedule_handle(schedule_id)
        await handle.unpause(note="Unpaused via r3ngine UI")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_unpause())
    finally:
        loop.close()
    logger.info("[ScheduleUtils] Unpaused schedule '%s'", schedule_id)


_MONITORING_FREQUENCY_SECONDS = {
    'hourly': 3600,
    'daily': 86400,
    'weekly': 7 * 86400,
    'monthly': 30 * 86400,
}


def _upsert_monitoring_temporal_schedule(domain) -> object:
    """Create or replace the Temporal Schedule for domain monitoring.

    Uses a deterministic schedule_id keyed on domain.id so the same domain
    always has a single well-known schedule. On update (e.g. frequency change),
    the old schedule is deleted and a fresh one is created.

    Args:
        domain: Domain model instance (is_monitored=True, monitor_frequency set).

    Returns:
        TemporalSchedule: The DB record (created or updated).
    """
    from startScan.models import TemporalSchedule

    interval_seconds = _MONITORING_FREQUENCY_SECONDS.get(
        domain.monitor_frequency, 86400
    )
    schedule_id = f"monitoring-{domain.id}"
    workflow_args = domain.id  # MonitoringWorkflow.run(domain_id: int)

    async def _recreate():
        client = await TemporalClientProvider.get_client()
        # Delete stale schedule if present (frequency may have changed)
        await delete_schedule_if_exists(client, schedule_id)
        await client.create_schedule(
            schedule_id,
            Schedule(
                action=ScheduleActionStartWorkflow(
                    "MonitoringWorkflow",
                    args=[workflow_args],
                    id=f"{schedule_id}-run",
                    task_queue="python-orchestrator-queue",
                ),
                spec=ScheduleSpec(
                    intervals=[ScheduleIntervalSpec(
                        every=datetime.timedelta(seconds=interval_seconds)
                    )],
                ),
                policy=SchedulePolicy(overlap=ScheduleOverlapPolicy.SKIP),
                state=ScheduleState(note=f"Monitoring: {domain.name}"),
            ),
        )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_recreate())
    finally:
        loop.close()

    # Update existing DB record or create new one
    record, _ = TemporalSchedule.objects.update_or_create(
        schedule_id=schedule_id,
        defaults=dict(
            name=f"Monitoring: {domain.name}",
            workflow_type='MonitoringWorkflow',
            workflow_args={'domain_id': domain.id},
            interval_seconds=interval_seconds,
            is_active=True,
            domain=domain,
        ),
    )
    logger.info(
        "[ScheduleUtils] Upserted monitoring schedule '%s' every %ss for domain=%s", schedule_id, interval_seconds, domain.name
    )
    return record


def _delete_monitoring_temporal_schedule(domain) -> None:
    """Delete the Temporal Schedule for domain monitoring and clean up the DB record.

    Args:
        domain: Domain model instance whose monitoring is being disabled.
    """
    from startScan.models import TemporalSchedule

    schedule_id = f"monitoring-{domain.id}"

    async def _delete():
        client = await TemporalClientProvider.get_client()
        await delete_schedule_if_exists(client, schedule_id)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_delete())
    except Exception:
        # Monitoring is being switched off either way; the schedule left behind
        # keeps firing MonitoringWorkflow until it is removed in the Temporal UI.
        logger.exception("Could not delete monitoring schedule %s; remove it in Temporal", schedule_id)
    finally:
        loop.close()

    TemporalSchedule.objects.filter(schedule_id=schedule_id).delete()
    logger.info("[ScheduleUtils] Deleted monitoring schedule '%s' for domain=%s", schedule_id, domain.name)
