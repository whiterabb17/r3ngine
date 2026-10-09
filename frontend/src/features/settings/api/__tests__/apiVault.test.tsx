import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const axiosMock = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  defaults: {},
  interceptors: { request: { use: vi.fn() } },
}));
vi.mock('axios', () => ({ default: axiosMock }));

import { useUpdateApiVault, type ApiVaultSettings } from '..';

const vault: ApiVaultSettings = {
  netlas_key: '',
  chaos_key: '',
  shodan_key: '',
  censys_key: '',
  leaklookup_key: '',
  hackerone_username: '',
  hackerone_key: '',
  acunetix_url: '',
  acunetix_key: '',
  securitytrails_key: 'st-test-key',
};

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
);

beforeEach(() => {
  axiosMock.post.mockReset();
});

describe('useUpdateApiVault', () => {
  it('sends the SecurityTrails key under the name the vault view reads', async () => {
    axiosMock.post.mockResolvedValue({ data: { status: 'success' } });
    const { result } = renderHook(() => useUpdateApiVault('default'), { wrapper });

    await act(() => result.current.mutateAsync(vault));

    const [url, body] = axiosMock.post.mock.calls[0];
    expect(url).toBe('/scanEngine/default/api_vault');
    expect((body as FormData).get('key_securitytrails')).toBe('st-test-key');
  });

  it('sends an empty value so the key can be cleared', async () => {
    axiosMock.post.mockResolvedValue({ data: { status: 'success' } });
    const { result } = renderHook(() => useUpdateApiVault('default'), { wrapper });

    await act(() => result.current.mutateAsync({ ...vault, securitytrails_key: undefined }));

    expect((axiosMock.post.mock.calls[0][1] as FormData).get('key_securitytrails')).toBe('');
  });
});
