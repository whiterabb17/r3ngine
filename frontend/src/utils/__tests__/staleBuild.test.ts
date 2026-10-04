import { beforeEach, describe, expect, it, vi } from 'vitest';
import { isStaleBuildError, reloadOnceForStaleBuild } from '../staleBuild';

describe('isStaleBuildError', () => {
  it('recognises a chunk from another build or a chunk that is gone', () => {
    for (const message of [
      "The requested module './ScanReportModal.js' does not provide an export named 'n'",
      'Failed to fetch dynamically imported module: https://host/staticfiles/assets/ScanDetailPage-abc.js',
      'error loading dynamically imported module',
      'Importing a module script failed.',
    ]) {
      expect(isStaleBuildError(new Error(message))).toBe(true);
    }
  });

  it('leaves other errors alone', () => {
    expect(isStaleBuildError(new Error("Cannot read properties of undefined (reading 'id')"))).toBe(false);
    expect(isStaleBuildError(undefined)).toBe(false);
  });
});

describe('reloadOnceForStaleBuild', () => {
  beforeEach(() => sessionStorage.clear());

  it('reloads once, then not again within the guard window', () => {
    const reload = vi.fn();
    expect(reloadOnceForStaleBuild(reload, 1_000_000)).toBe(true);
    expect(reloadOnceForStaleBuild(reload, 1_010_000)).toBe(false);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('reloads again for a later deploy', () => {
    const reload = vi.fn();
    reloadOnceForStaleBuild(reload, 1_000_000);
    expect(reloadOnceForStaleBuild(reload, 1_000_000 + 60_000)).toBe(true);
    expect(reload).toHaveBeenCalledTimes(2);
  });

  it('does not reload when storage is unavailable, since nothing could stop a loop', () => {
    const reload = vi.fn();
    const getItem = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('blocked', 'SecurityError');
    });
    expect(reloadOnceForStaleBuild(reload)).toBe(false);
    expect(reload).not.toHaveBeenCalled();
    getItem.mockRestore();
  });
});
