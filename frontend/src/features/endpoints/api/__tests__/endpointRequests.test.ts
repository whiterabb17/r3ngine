import { beforeEach, describe, expect, it, vi } from 'vitest';

const axiosMock = vi.hoisted(() => ({
  get: vi.fn(),
  defaults: {},
  interceptors: { request: { use: vi.fn() } },
}));
vi.mock('axios', () => ({ default: axiosMock }));

import { fetchScanEndpoints } from '..';

beforeEach(() => axiosMock.get.mockReset());

describe('fetchScanEndpoints', () => {
  it('filters by project and scan', async () => {
    axiosMock.get.mockResolvedValue({ data: { count: 1, results: [{ id: 1 }] } });
    await expect(fetchScanEndpoints('default', '9')).resolves.toEqual([{ id: 1 }]);
    expect(axiosMock.get).toHaveBeenCalledWith('/api/listEndpoints/', {
      params: { project: 'default', scan_history: '9' },
    });
  });

  it('accepts an unpaginated list', async () => {
    axiosMock.get.mockResolvedValue({ data: [{ id: 2 }] });
    await expect(fetchScanEndpoints('default', 9)).resolves.toEqual([{ id: 2 }]);
  });

  it('returns an empty list for an empty body', async () => {
    axiosMock.get.mockResolvedValue({ data: null });
    await expect(fetchScanEndpoints('default', 9)).resolves.toEqual([]);
  });
});
