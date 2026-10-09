import { describe, expect, it, vi } from 'vitest';

const axiosMock = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock('axios', () => ({ default: axiosMock }));

import { fetchPluginRegistry } from '../pluginsApi';

describe('fetchPluginRegistry', () => {
  it('returns the UI registry of enabled plugins', async () => {
    const registry = [
      { slug: 'demo', name: 'Demo', components: { menu_item: 'Demo', menu_path: '/p/demo' } },
    ];
    axiosMock.get.mockResolvedValue({ data: registry });
    await expect(fetchPluginRegistry()).resolves.toEqual(registry);
    expect(axiosMock.get).toHaveBeenCalledWith('/api/plugins/registry/');
  });
});
