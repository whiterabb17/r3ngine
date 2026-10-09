import { beforeEach, describe, expect, it, vi } from 'vitest';

const axiosMock = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  defaults: {},
  interceptors: { request: { use: vi.fn() } },
}));
vi.mock('axios', () => ({ default: axiosMock }));

import {
  exportConfigBackup,
  exportScanResultsBackup,
  fetchToolFileContent,
  importConfigBackup,
} from '..';
import {
  abortFollowupPlan,
  approveFollowupPlan,
  fetchFollowupPlans,
  retryFollowupPlan,
  updateFollowupPlan,
  type FollowupPlan,
} from '../mcp';

const plan: FollowupPlan = {
  id: 4,
  project_slug: 'default',
  scan_id: null,
  status: 'proposed',
  rationale: 'probe',
  steps: [{ id: 's1', kind: 'tool', tool: 'httpx' }],
  retry_count: 0,
};

beforeEach(() => {
  axiosMock.get.mockReset();
  axiosMock.post.mockReset();
});

describe('fetchToolFileContent', () => {
  it('sends the bare selector for single files', async () => {
    axiosMock.get.mockResolvedValue({ data: { status: true, content: 'a: 1' } });
    await expect(fetchToolFileContent('nuclei_config')).resolves.toEqual({
      status: true,
      content: 'a: 1',
    });
    expect(axiosMock.get).toHaveBeenCalledWith('/api/getFileContents/?nuclei_config');
  });

  it('adds the entry name for list-type selectors', async () => {
    axiosMock.get.mockResolvedValue({ data: { status: false, content: '' } });
    await fetchToolFileContent('gf_pattern', 'xss');
    expect(axiosMock.get).toHaveBeenCalledWith('/api/getFileContents/?gf_pattern&name=xss');
  });
});

describe('backup export and import', () => {
  it('downloads the configuration archive as a blob', async () => {
    const blob = new Blob(['zip']);
    axiosMock.get.mockResolvedValue({ data: blob });
    await expect(exportConfigBackup()).resolves.toBe(blob);
    expect(axiosMock.get).toHaveBeenCalledWith('/api/settings/export/', { responseType: 'blob' });
  });

  it('downloads the scan results archive as a blob', async () => {
    const blob = new Blob(['zip']);
    axiosMock.get.mockResolvedValue({ data: blob });
    await expect(exportScanResultsBackup()).resolves.toBe(blob);
    expect(axiosMock.get).toHaveBeenCalledWith('/api/settings/export/scan-results/', {
      responseType: 'blob',
    });
  });

  it('uploads the archive as multipart form data', async () => {
    axiosMock.post.mockResolvedValue({ data: { status: true } });
    const file = new File(['zip'], 'backup.zip');
    await expect(importConfigBackup(file, true)).resolves.toEqual({ status: true });

    const [url, body, config] = axiosMock.post.mock.calls[0];
    expect(url).toBe('/api/settings/import/');
    expect(body).toBeInstanceOf(FormData);
    expect((body as FormData).get('file')).toBeInstanceOf(File);
    expect((body as FormData).get('overwrite_existing')).toBe('true');
    expect(config).toEqual({ headers: { 'Content-Type': 'multipart/form-data' } });
  });

  it('sends overwrite_existing=false when not overwriting', async () => {
    axiosMock.post.mockResolvedValue({ data: { status: false, message: 'bad archive' } });
    await expect(importConfigBackup(new File([''], 'b.zip'), false)).resolves.toEqual({
      status: false,
      message: 'bad archive',
    });
    expect((axiosMock.post.mock.calls[0][1] as FormData).get('overwrite_existing')).toBe('false');
  });
});

describe('follow-up plan requests', () => {
  it('lists plans for the project and status', async () => {
    axiosMock.get.mockResolvedValue({ data: { results: [plan], count: 1 } });
    await expect(fetchFollowupPlans('default', 'proposed')).resolves.toEqual([plan]);
    expect(axiosMock.get).toHaveBeenCalledWith('/api/action/followups/', {
      params: { project_slug: 'default', status: 'proposed', limit: 30 },
    });
  });

  it('drops an empty status filter and tolerates a missing results key', async () => {
    axiosMock.get.mockResolvedValue({ data: {} });
    await expect(fetchFollowupPlans('default', '')).resolves.toEqual([]);
    expect(axiosMock.get).toHaveBeenCalledWith('/api/action/followups/', {
      params: { project_slug: 'default', status: undefined, limit: 30 },
    });
  });

  it('approves with optional edited steps', async () => {
    axiosMock.post.mockResolvedValue({ data: { status: true, plan } });
    await expect(approveFollowupPlan(4, plan.steps)).resolves.toEqual({ status: true, plan });
    expect(axiosMock.post).toHaveBeenCalledWith('/api/action/followups/4/approve/', {
      steps: plan.steps,
    });

    await approveFollowupPlan(4);
    expect(axiosMock.post).toHaveBeenLastCalledWith('/api/action/followups/4/approve/', {
      steps: undefined,
    });
  });

  it('aborts, retries and updates by plan id', async () => {
    axiosMock.post.mockResolvedValue({ data: { status: true, plan } });

    await abortFollowupPlan(4);
    expect(axiosMock.post).toHaveBeenLastCalledWith('/api/action/followups/4/abort/', {});

    await retryFollowupPlan(4, ['s1']);
    expect(axiosMock.post).toHaveBeenLastCalledWith('/api/action/followups/4/retry/', {
      step_ids: ['s1'],
    });

    await retryFollowupPlan(4);
    expect(axiosMock.post).toHaveBeenLastCalledWith('/api/action/followups/4/retry/', {
      step_ids: undefined,
    });

    await updateFollowupPlan(4, plan.steps);
    expect(axiosMock.post).toHaveBeenLastCalledWith('/api/action/followups/4/update/', {
      steps: plan.steps,
    });
  });
});
