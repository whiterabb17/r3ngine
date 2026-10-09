import { beforeEach, describe, expect, it, vi } from 'vitest';

const axiosMock = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  defaults: {},
  interceptors: { request: { use: vi.fn() } },
}));
vi.mock('axios', () => ({ default: axiosMock }));

import { canFetchLlmModels, fetchLlmModels, saveLlmSettings, testLlmConnection } from '..';

const sent = (call: unknown[]): Record<string, string> =>
  Object.fromEntries((call[1] as FormData).entries()) as Record<string, string>;

beforeEach(() => {
  axiosMock.get.mockReset();
  axiosMock.post.mockReset();
});

describe('OpenAI-compatible provider requests', () => {
  it('asks for the gateway model list with its base URL', async () => {
    axiosMock.get.mockResolvedValue({ data: { models: [{ name: 'claude-opus-4-8' }] } });
    await expect(fetchLlmModels('default', 'openai_compatible', 'k', 'https://gw.example.test/v1'))
      .resolves.toEqual([{ name: 'claude-opus-4-8' }]);
    expect(axiosMock.get).toHaveBeenCalledWith('/scanEngine/default/fetch_llm_models', {
      params: { provider: 'openai_compatible', api_key: 'k', base_url: 'https://gw.example.test/v1' },
    });
  });

  it('does not send a base URL for providers with a fixed endpoint', async () => {
    axiosMock.get.mockResolvedValue({ data: { models: [] } });
    await fetchLlmModels('default', 'openai', 'k', 'https://ignored.example.test');
    expect(axiosMock.get.mock.calls[0][1]).toEqual({ params: { provider: 'openai', api_key: 'k' } });
  });

  it('waits for both key and base URL before listing a gateway', () => {
    expect(canFetchLlmModels('openai_compatible', 'k', '')).toBe(false);
    expect(canFetchLlmModels('openai_compatible', '', 'https://gw.example.test/v1')).toBe(false);
    expect(canFetchLlmModels('openai_compatible', 'k', 'https://gw.example.test/v1')).toBe(true);
    expect(canFetchLlmModels('openai', 'k')).toBe(true);
    expect(canFetchLlmModels('ollama', '')).toBe(true);
  });

  it('saves and tests with the base URL', async () => {
    axiosMock.post.mockResolvedValue({ data: { status: 'success', message: '', response: 'CONNECTED' } });
    await saveLlmSettings('default', {
      provider: 'openai_compatible', api_key: 'k', base_url: 'https://gw.example.test/v1',
      selected_model: 'gpt-oss-120b', is_active: true, action: 'save',
    });
    await testLlmConnection('default', {
      provider: 'openai_compatible', api_key: 'k', model: 'gpt-oss-120b', base_url: 'https://gw.example.test/v1',
    });
    expect(axiosMock.post.mock.calls[0][0]).toBe('/scanEngine/default/update_llm_settings');
    expect(sent(axiosMock.post.mock.calls[0])).toMatchObject({
      provider: 'openai_compatible', base_url: 'https://gw.example.test/v1', selected_model: 'gpt-oss-120b', is_active: 'true',
    });
    expect(axiosMock.post.mock.calls[1][0]).toBe('/scanEngine/default/test_llm_connection');
    expect(sent(axiosMock.post.mock.calls[1])).toMatchObject({ base_url: 'https://gw.example.test/v1', model: 'gpt-oss-120b' });
  });
});
