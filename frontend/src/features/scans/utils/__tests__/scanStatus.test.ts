import { describe, expect, it } from 'vitest';
import { isResumableScanStatus } from '../scanStatus';

describe('isResumableScanStatus', () => {
  it('offers resume for failed, aborted and partially complete scans', () => {
    expect([0, 3, 4].map(isResumableScanStatus)).toEqual([true, true, true]);
  });

  it('does not offer it while a workflow still owns the scan, or once it succeeded', () => {
    // -1 pending, 1 running, 2 success, 5 paused
    expect([-1, 1, 2, 5, null, undefined].map(isResumableScanStatus)).toEqual([false, false, false, false, false, false]);
  });
});
