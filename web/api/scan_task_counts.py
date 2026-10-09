from reNgine.definitions import SUCCESS_TASK, FAILED_TASK


def get_task_counts(scan):
    """Return (successful, failed, total) task counts for a ScanHistory instance.

    A task is counted as failed only if it has a FAILED_TASK record with no
    matching SUCCESS_TASK record for the same name — this excludes Temporal
    retry artifacts where an activity fails then succeeds on a later attempt.
    """
    # One pass over the related manager rather than three filtered queries.
    # Under prefetch_related this costs no query at all; without it, one
    # instead of three. The caller may be serializing hundreds of scans.
    activities = scan.scanactivity_set.all()

    success_names = set()
    failed_names = set()
    all_names = set()
    for activity in activities:
        all_names.add(activity.name)
        if activity.status == SUCCESS_TASK:
            success_names.add(activity.name)
        elif activity.status == FAILED_TASK:
            failed_names.add(activity.name)

    failed_names -= success_names
    total = len(all_names) if all_names else len(scan.tasks or [])
    return len(success_names), len(failed_names), total

