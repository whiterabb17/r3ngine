import { beforeEach, describe, expect, it, vi } from 'vitest';

const axiosMock = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  defaults: {},
  interceptors: { request: { use: vi.fn() } },
}));
vi.mock('axios', () => ({ default: axiosMock }));

import {
  createStressReport,
  fetchStressReportStatus,
  startStressTest,
  stopStressTest,
} from '../stress';
import type { StressStartPayload } from '../../../../types/stressTesting';

beforeEach(() => {
  axiosMock.get.mockReset();
  axiosMock.post.mockReset();
});

describe('stress test control', () => {
  it('starts a run with the given payload', async () => {
    axiosMock.post.mockResolvedValue({ data: { status: 'started' } });
    const payload: StressStartPayload = {
      action: 'start',
      config: { concurrency: 10, duration: '30s', uses_tools: ['k6'], selected_endpoints: [] },
    };
    await expect(startStressTest('7', payload)).resolves.toBeUndefined();
    expect(axiosMock.post).toHaveBeenCalledWith('/api/stress/7/control/', payload);
  });

  it('stops a run', async () => {
    axiosMock.post.mockResolvedValue({ data: { status: 'stopping' } });
    await stopStressTest(7);
    expect(axiosMock.post).toHaveBeenCalledWith('/api/stress/7/control/', { action: 'stop' });
  });

  it('propagates control errors', async () => {
    axiosMock.post.mockRejectedValue(new Error('404'));
    await expect(stopStressTest(7)).rejects.toThrow('404');
  });
});

describe('stress reports', () => {
  it('requests a report and returns the body', async () => {
    const body = { status: true, report_id: 3, message: 'Report generation initiated' };
    axiosMock.post.mockResolvedValue({ data: body });
    const request = {
      report_template: 'stress_modern' as const,
      include_endpoints: true,
      include_timeline: true,
    };
    await expect(createStressReport('7', request)).resolves.toEqual(body);
    expect(axiosMock.post).toHaveBeenCalledWith('/api/stress/7/report/', request);
  });

  it('polls the report status by id', async () => {
    const body = { status: 2, error_message: null, report_url: '/media/r.pdf', completed_at: null };
    axiosMock.get.mockResolvedValue({ data: body });
    await expect(fetchStressReportStatus('7', 3)).resolves.toEqual(body);
    expect(axiosMock.get).toHaveBeenCalledWith('/api/stress/7/report/', {
      params: { report_id: 3 },
    });
  });
});
