import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { fetchCveDetails, fetchCweInfo, generateCveDescription } from '../api';

const fetchMock = vi.fn();
const jsonResponse = (body: unknown, ok = true) =>
  ({ ok, json: () => Promise.resolve(body) }) as Response;

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => {
  vi.unstubAllGlobals();
  document.cookie = 'csrftoken=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
});

describe('fetchCweInfo', () => {
  it('requests the encoded CWE name with credentials', async () => {
    const body = { status: true, cwe: 'CWE-79: XSS', name: 'XSS' };
    fetchMock.mockResolvedValue(jsonResponse(body));
    await expect(fetchCweInfo('CWE-79: XSS')).resolves.toEqual(body);
    expect(fetchMock).toHaveBeenCalledWith('/api/cwe-info/?name=CWE-79%3A%20XSS', {
      credentials: 'include',
    });
  });

  it('resolves with the error body on an HTTP error', async () => {
    const body = { status: false, error: 'LLM returned non-JSON response' };
    fetchMock.mockResolvedValue(jsonResponse(body, false));
    await expect(fetchCweInfo('CWE-89')).resolves.toEqual(body);
  });
});

describe('fetchCveDetails', () => {
  it('requests the encoded CVE id with credentials', async () => {
    const body = { status: true, result: { id: 'CVE-2024-0001' } };
    fetchMock.mockResolvedValue(jsonResponse(body));
    await expect(fetchCveDetails('CVE-2024-0001')).resolves.toEqual(body);
    expect(fetchMock).toHaveBeenCalledWith('/api/tools/cve_details/?cve_id=CVE-2024-0001', {
      credentials: 'include',
    });
  });

  it('resolves with the failure body', async () => {
    const body = { status: false, message: 'CVE ID not provided' };
    fetchMock.mockResolvedValue(jsonResponse(body, false));
    await expect(fetchCveDetails('x&y')).resolves.toEqual(body);
    expect(fetchMock.mock.calls[0][0]).toBe('/api/tools/cve_details/?cve_id=x%26y');
  });

  it('propagates network errors', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));
    await expect(fetchCveDetails('CVE-2024-0001')).rejects.toThrow('Failed to fetch');
  });
});

describe('generateCveDescription', () => {
  it('posts the CVE id with the CSRF token', async () => {
    document.cookie = 'csrftoken=tok-456';
    const body = {
      status: true,
      description: 'desc',
      impact: 'impact',
      remediation: 'fix',
      ai_risk_assessment: 'high',
    };
    fetchMock.mockResolvedValue(jsonResponse(body));
    await expect(generateCveDescription('CVE-2024-0001')).resolves.toEqual(body);
    expect(fetchMock).toHaveBeenCalledWith('/api/tools/cve_description_generate/', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': 'tok-456' },
      body: JSON.stringify({ cve_id: 'CVE-2024-0001' }),
    });
  });

  it('sends an empty CSRF header without a cookie', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ status: false, message: 'No active LLM configuration found' }, false));
    await expect(generateCveDescription('CVE-2024-0001')).resolves.toEqual({
      status: false,
      message: 'No active LLM configuration found',
    });
    expect(fetchMock.mock.calls[0][1].headers['X-CSRFToken']).toBe('');
  });
});
