import { describe, expect, it } from 'vitest';
import type { ScanActivity } from '../../types';
import { isNotRunActivity } from '../failureCategories';

const activity = (overrides: Partial<ScanActivity>): ScanActivity => ({
  id: 1,
  task_uid: null,
  title: 'Nuclei Vulnerability Scan',
  name: 'nuclei_scan',
  status: 'FAILED',
  time: '2026-10-01T10:38:27Z',
  time_started: null,
  time_ended: null,
  tier: 6,
  has_commands: false,
  error_message: 'Activity task timed out',
  ...overrides,
});

describe('isNotRunActivity', () => {
  it('is true for a failed row that never started (the scan stopped first)', () => {
    expect(isNotRunActivity(activity({}))).toBe(true);
  });

  it('is false for a row that started and then failed', () => {
    expect(isNotRunActivity(activity({ time_started: '2026-10-01T10:40:00Z' }))).toBe(false);
  });

  it('is false for rows that did not fail', () => {
    expect(isNotRunActivity(activity({ status: 'ABORTED' }))).toBe(false);
    expect(isNotRunActivity(activity({ status: 'SUCCESS' }))).toBe(false);
  });
});
