import type { ScanActivity } from '../types';

/**
 * Operator-facing wording for the categories produced by `classify_failure()`
 * in `web/reNgine/failure_reasons.py`. Keep the keys in sync with that module.
 *
 * A `Map` rather than an object literal: the key arrives from the API, so it
 * must not be able to reach a prototype member (security rule 5.1).
 */
const FAILURE_CATEGORY_LABELS = new Map<string, string>([
  ['temporal_cancelled', 'Cancelled'],
  ['heartbeat_timeout', 'Heartbeat timeout'],
  ['activity_timeout', 'Time limit exceeded'],
  ['worker_restart', 'Worker restart'],
  ['missing_configuration', 'Missing configuration'],
  ['proxy_failure', 'Proxy failure'],
  ['database_error', 'Datastore error'],
  ['network_error', 'Network error'],
  ['tool_failure', 'Tool failure'],
  ['unknown', 'Unclassified failure'],
]);

/**
 * Causes that are usually environmental rather than a problem with the task
 * itself — a reboot, a dead proxy, a flaky link. Re-running the tier is worth a
 * try for these; for the rest the operator has to fix something first.
 */
const TRANSIENT_FAILURE_CATEGORIES = new Set<string>([
  'heartbeat_timeout',
  'activity_timeout',
  'worker_restart',
  'proxy_failure',
  'database_error',
  'network_error',
]);

/** Human label for a failure category, or `null` when the API sent none. */
export const getFailureCategoryLabel = (category?: string | null): string | null => {
  if (!category) return null;
  return FAILURE_CATEGORY_LABELS.get(category) ?? 'Unclassified failure';
};

export const isTransientFailureCategory = (category?: string | null): boolean =>
  !!category && TRANSIENT_FAILURE_CATEGORIES.has(category);

export type TierStatus = 'FAILED' | 'NOT_RUN' | 'RUNNING' | 'PENDING' | 'COMPLETE' | 'EMPTY';

export interface TierSummary {
  status: TierStatus;
  total: number;
  /** Rows that ran and failed (FAILED only — ABORTED is not tier-retryable). */
  failedCount: number;
  /**
   * Rows that did not complete as a real failure: finalizer-flipped FAILED
   * without ever starting, or ABORTED on stop/cancel. When a scan stops, the
   * finalizer flips every still-planned task to FAILED with the scan's own
   * error message, so one real failure can leave a dozen tiers reporting
   * failures of their own.
   */
  notRunCount: number;
  runningCount: number;
  pendingCount: number;
  successCount: number;
  /** Distinct failure categories seen in the group, in first-seen order. */
  failureCategories: string[];
  /** True when every failure in the group looks environmental. */
  allFailuresTransient: boolean;
}

/** A row the finalizer flipped to FAILED without it ever having started. */
const neverStarted = (activity: ScanActivity): boolean => !activity.time_started;

/**
 * A FAILED row that never started: the scan stopped before reaching it, so its
 * error is the scan's, not the task's own.
 */
export const isNotRunActivity = (activity: ScanActivity): boolean =>
  activity.status === 'FAILED' && neverStarted(activity);

/** Roll a tier group's activities up into one status the header can show. */
export const summariseTier = (activities: ScanActivity[]): TierSummary => {
  const failureCategories: string[] = [];
  let failedCount = 0;
  let notRunCount = 0;
  let runningCount = 0;
  let pendingCount = 0;
  let successCount = 0;
  let transientFailures = 0;

  activities.forEach((activity) => {
    // Retry Tier posts to ScanTierRetryAPIView, which only selects FAILED_TASK
    // rows. ABORTED (operator stop / cancel) must not inflate failedCount or the
    // header offers a retry that no-ops.
    if (activity.status === 'FAILED') {
      if (neverStarted(activity)) {
        notRunCount += 1;
        return;
      }
      failedCount += 1;
      const category = activity.failure_category;
      if (category && !failureCategories.includes(category)) {
        failureCategories.push(category);
      }
      if (isTransientFailureCategory(category)) transientFailures += 1;
    } else if (activity.status === 'ABORTED') {
      // Stopped mid-flight or cancelled before start — same operator message as
      // never-started: the scan did not finish this work, but it is not retryable
      // via the tier endpoint.
      notRunCount += 1;
    } else if (activity.status === 'RUNNING') {
      runningCount += 1;
    } else if (activity.status === 'PENDING') {
      pendingCount += 1;
    } else if (activity.status === 'SUCCESS') {
      successCount += 1;
    }
  });

  // A single failed row makes the whole tier read as failed: that is the
  // question the operator opens the timeline with. A tier whose rows were only
  // swept up by the finalizer (or aborted on stop) reads as not run, so one
  // real failure does not look like a dozen.
  const status: TierStatus = activities.length === 0
    ? 'EMPTY'
    : failedCount > 0
      ? 'FAILED'
      : runningCount > 0
        ? 'RUNNING'
        : notRunCount > 0
          ? 'NOT_RUN'
          : successCount === activities.length
            ? 'COMPLETE'
            : 'PENDING';

  return {
    status,
    total: activities.length,
    failedCount,
    notRunCount,
    runningCount,
    pendingCount,
    successCount,
    failureCategories,
    allFailuresTransient: failedCount > 0 && transientFailures === failedCount,
  };
};
