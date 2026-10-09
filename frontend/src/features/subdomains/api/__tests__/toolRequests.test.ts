import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const axiosMock = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  defaults: {},
  interceptors: { request: { use: vi.fn() } },
}));
vi.mock('axios', () => ({ default: axiosMock }));

import { createAdAssessmentFromSubdomain, refreshToolArgs } from '..';

beforeEach(() => {
  axiosMock.get.mockReset();
  axiosMock.post.mockReset();
});

describe('refreshToolArgs', () => {
  it('forces a schema refresh for the encoded tool name', async () => {
    const payload = { tool: 'a/b', fields: [] };
    axiosMock.get.mockResolvedValue({ data: payload });
    await expect(refreshToolArgs('a/b')).resolves.toBe(payload);
    expect(axiosMock.get).toHaveBeenCalledWith('/api/action/tool/a%2Fb/args/', {
      params: { refresh: 1 },
    });
  });
});

describe('createAdAssessmentFromSubdomain', () => {
  const fetchMock = vi.fn();
  const jsonResponse = (body: unknown, ok = true, status = 201) =>
    ({ ok, status, json: () => Promise.resolve(body) }) as Response;

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    document.cookie = 'csrftoken=tok-123';
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    document.cookie = 'csrftoken=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
  });

  it('posts the subdomain id with credentials and the CSRF token', async () => {
    const body = {
      assessment_id: 4,
      assessment_name: 'AD Assessment — example.test',
      target_domain: 'example.test',
      status: 'created',
    };
    fetchMock.mockResolvedValue(jsonResponse(body));
    await expect(createAdAssessmentFromSubdomain(12)).resolves.toEqual(body);
    expect(fetchMock).toHaveBeenCalledWith('/api/action/ad-assessment/from-subdomain/', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': 'tok-123' },
      body: JSON.stringify({ subdomain_id: 12 }),
    });
  });

  it('rejects with the backend error message', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ error: 'AD Intelligence plugin is not installed.' }, false, 400),
    );
    await expect(createAdAssessmentFromSubdomain(12)).rejects.toThrow(
      'AD Intelligence plugin is not installed.',
    );
  });

  it('falls back to the HTTP status without an error message', async () => {
    fetchMock.mockResolvedValue(jsonResponse({}, false, 500));
    await expect(createAdAssessmentFromSubdomain(12)).rejects.toThrow('HTTP 500');
  });
});
