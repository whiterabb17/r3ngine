"""Target Deduplication: mark hosts that serve the same site as another one."""
import logging

from django.utils import timezone

from reNgine.host_dedup import apply_target_dedup, target_dedup_config

logger = logging.getLogger(__name__)


def target_dedup(self, ctx=None, description=None) -> bool:
    """Link each duplicate live host of the scan to the host it duplicates.

    Every skipped host gets a line on this step's timeline row, so the operator
    can see which hosts the heavy tools will leave out and why.
    """
    from startScan.models import Command

    ctx = ctx or {}
    enabled, rules = target_dedup_config(self.yaml_configuration)
    if not enabled or ctx.get('subdomain_id') or ctx.get('subscan_id'):
        return True

    duplicates = apply_target_dedup(self.scan_id, rules)
    now = timezone.now()
    rows = [
        Command(
            command=f"target_dedup {name}",
            output=f"SKIPPED for heavy tools — same site as {target} ({reason})",
            return_code=0, time=now, scan_history_id=self.scan_id, activity_id=self.activity_id,
        )
        for name, (target, reason) in sorted(duplicates.items())
    ]
    rows.append(Command(
        command="target_dedup summary",
        output=f"{len(duplicates)} duplicate host(s) found by {', '.join(rules) or 'no rule'}",
        return_code=0, time=now, scan_history_id=self.scan_id, activity_id=self.activity_id,
    ))
    Command.objects.bulk_create(rows)
    logger.info("Target dedup for scan %s: %d duplicate hosts", self.scan_id, len(duplicates))
    return True
