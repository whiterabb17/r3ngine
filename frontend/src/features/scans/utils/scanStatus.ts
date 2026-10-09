/** Scan statuses the backend resumes from the unfinished tasks: failed (0),
 * aborted (3) and partially complete (4). A running, pending or paused scan
 * still has a workflow, so the backend refuses to start a second one. */
const RESUMABLE_SCAN_STATUSES: readonly number[] = [0, 3, 4];

export const isResumableScanStatus = (status: number | null | undefined): boolean =>
  status != null && RESUMABLE_SCAN_STATUSES.includes(status);
