import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const axiosMock = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  defaults: {},
  interceptors: { request: { use: vi.fn() } },
}));
vi.mock('axios', () => ({ default: axiosMock }));

import {
  fetchDirectoryFileAuthLogs,
  fetchScanScreenshotSubdomains,
  fetchScanVisualisation,
} from '../scanResults';
import { createScanReport, fetchScanReportStatus } from '../reports';

const jsonResponse = (body: unknown, ok = true) =>
  ({ ok, json: () => Promise.resolve(body) }) as Response;

describe('fetchScanVisualisation', () => {
  beforeEach(() => axiosMock.get.mockReset());

  it('queries by scan id when given', async () => {
    axiosMock.get.mockResolvedValue({ data: [{ description: 'scan' }] });
    await expect(fetchScanVisualisation({ scanId: 7, targetId: 3 })).resolves.toEqual([
      { description: 'scan' },
    ]);
    expect(axiosMock.get).toHaveBeenCalledWith(
      '/api/queryAllScanResultVisualise/?format=json&scan_id=7',
    );
  });

  it('falls back to the target id', async () => {
    axiosMock.get.mockResolvedValue({ data: [] });
    await fetchScanVisualisation({ targetId: 3 });
    expect(axiosMock.get).toHaveBeenCalledWith(
      '/api/queryAllScanResultVisualise/?format=json&target_id=3',
    );
  });

  it('sends no filter without ids', async () => {
    axiosMock.get.mockResolvedValue({ data: [] });
    await fetchScanVisualisation({});
    expect(axiosMock.get).toHaveBeenCalledWith('/api/queryAllScanResultVisualise/?format=json');
  });
});

describe('fetchDirectoryFileAuthLogs', () => {
  beforeEach(() => axiosMock.get.mockReset());

  it('returns the log lines for the workflow', async () => {
    axiosMock.get.mockResolvedValue({ data: { logs: ['[START]', '[COMPLETE]'] } });
    await expect(fetchDirectoryFileAuthLogs('wf-1')).resolves.toEqual(['[START]', '[COMPLETE]']);
    expect(axiosMock.get).toHaveBeenCalledWith(
      '/api/action/directory-file/auth-logs/?workflow_id=wf-1',
    );
  });

  it('returns an empty list when the body has no logs', async () => {
    axiosMock.get.mockResolvedValue({ data: {} });
    await expect(fetchDirectoryFileAuthLogs('wf-2')).resolves.toEqual([]);
  });
});

describe('fetchScanScreenshotSubdomains', () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it('requests every subdomain of the scan with credentials', async () => {
    fetchMock.mockResolvedValue(jsonResponse([{ id: 1 }]));
    await expect(fetchScanScreenshotSubdomains(42)).resolves.toEqual([{ id: 1 }]);
    const [url, init] = fetchMock.mock.calls[0];
    const parsed = new URL(url);
    expect(parsed.origin).toBe(window.location.origin);
    expect(parsed.pathname).toBe('/api/listSubdomains/');
    expect(parsed.searchParams.get('scan_id')).toBe('42');
    expect(parsed.searchParams.get('no_page')).toBe('1');
    expect(parsed.searchParams.get('format')).toBe('json');
    expect(init).toEqual({ credentials: 'include' });
  });

  it('unwraps a paginated body', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ results: [{ id: 2 }] }));
    await expect(fetchScanScreenshotSubdomains(1)).resolves.toEqual([{ id: 2 }]);
  });

  it('returns an empty list for an unexpected body', async () => {
    fetchMock.mockResolvedValue(jsonResponse(null));
    await expect(fetchScanScreenshotSubdomains(1)).resolves.toEqual([]);
  });

  it('throws on an HTTP error', async () => {
    fetchMock.mockResolvedValue(jsonResponse({}, false));
    await expect(fetchScanScreenshotSubdomains(1)).rejects.toThrow('Failed to fetch screenshots');
  });
});

describe('scan report requests', () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it('starts a report with the given options', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ status: true, report_id: 9 }));
    const params = new URLSearchParams({ report_type: 'full', download: 'False' });
    await expect(createScanReport(5, params)).resolves.toEqual({ status: true, report_id: 9 });
    expect(fetchMock).toHaveBeenCalledWith(
      '/scan/create_report/5?report_type=full&download=False',
      { credentials: 'include' },
    );
  });

  it('rejects when the report cannot be started', async () => {
    fetchMock.mockResolvedValue(jsonResponse({}, false));
    await expect(createScanReport(5, new URLSearchParams())).rejects.toThrow(
      'Failed to initiate report',
    );
  });

  it('polls the report status', async () => {
    const body = { status: 2, report_url: '/media/report.pdf', error_message: null };
    fetchMock.mockResolvedValue(jsonResponse(body));
    await expect(fetchScanReportStatus(9)).resolves.toEqual(body);
    expect(fetchMock).toHaveBeenCalledWith('/scan/report/status/9', { credentials: 'include' });
  });

  it('rejects when the status check fails', async () => {
    fetchMock.mockResolvedValue(jsonResponse({}, false));
    await expect(fetchScanReportStatus(9)).rejects.toThrow('Failed to check status');
  });
});
