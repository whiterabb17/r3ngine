import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setScanHardwareProfile } from '../index';

const jsonResponse = (body: unknown, ok = true) =>
  ({ ok, json: () => Promise.resolve(body) }) as Response;

describe('setScanHardwareProfile', () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it('posts the profile id to the scan endpoint', async () => {
    const body = { status: true, message: 'ok', hardware_profile: { id: 3, name: 'dedicated' } };
    fetchMock.mockResolvedValue(jsonResponse(body));

    await expect(setScanHardwareProfile(42, 3)).resolves.toEqual(body);

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/action/scan/42/hardware-profile/');
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('include');
    expect(JSON.parse(init.body)).toEqual({ hardware_profile_id: 3 });
  });

  it('surfaces the server message on a rejected profile', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ status: false, message: 'Hardware profile not found or inactive.' }, false),
    );
    await expect(setScanHardwareProfile(42, 9)).rejects.toThrow('Hardware profile not found or inactive.');
  });

  it('falls back to a generic message when the body is not JSON', async () => {
    fetchMock.mockResolvedValue({ ok: false, json: () => Promise.reject(new Error('html')) } as unknown as Response);
    await expect(setScanHardwareProfile(42, 9)).rejects.toThrow('Failed to change the hardware profile');
  });
});
