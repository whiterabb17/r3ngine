from django.db.models.signals import pre_delete
from django.dispatch import receiver
import logging
from startScan.models import ScanHistory, SubScan
from reNgine.temporal_client import TemporalClientProvider
from reNgine.utils.results_fs import remove_results_dir

logger = logging.getLogger(__name__)

@receiver(pre_delete, sender=ScanHistory)
def cancel_scan_workflows_and_cleanup(sender, instance, **kwargs):
    """Cancel all running Temporal workflows associated with this ScanHistory and delete results directory."""
    logger.info("Pre-delete signal triggered for ScanHistory ID: %s", instance.id)
    # Cancel running workflows
    try:
        if hasattr(instance, 'temporal_executions'):
            for te in instance.temporal_executions.filter(status="RUNNING"):
                try:
                    logger.info("Cancelling Temporal workflow %s for ScanHistory ID %s", te.workflow_id, instance.id)
                    TemporalClientProvider.cancel_workflow(te.workflow_id)
                    te.status = "CANCELLED"
                    te.save()
                except Exception as e:
                    logger.warning("Failed to cancel workflow %s during ScanHistory deletion: %s", te.workflow_id, e)
    except Exception as e:
        logger.warning("Failed to query temporal executions for ScanHistory ID %s: %s", instance.id, e)

    # The one place a scan's results directory is removed; views only delete the row.
    try:
        if remove_results_dir(instance.results_dir):
            logger.info("Removed scan results directory %s", instance.results_dir)
    except OSError:
        logger.warning(
            "Failed to remove results directory %s during ScanHistory deletion",
            instance.results_dir, exc_info=True,
        )


@receiver(pre_delete, sender=SubScan)
def cancel_subscan_workflows(sender, instance, **kwargs):
    """Cancel running Temporal workflows associated with this SubScan."""
    logger.info("Pre-delete signal triggered for SubScan ID: %s", instance.id)
    if instance.workflow_ids:
        for wf_id in instance.workflow_ids:
            try:
                logger.info("Cancelling Temporal workflow %s for SubScan ID %s", wf_id, instance.id)
                TemporalClientProvider.cancel_workflow(wf_id)
            except Exception as e:
                logger.warning("Failed to cancel subscan workflow %s during SubScan deletion: %s", wf_id, e)
