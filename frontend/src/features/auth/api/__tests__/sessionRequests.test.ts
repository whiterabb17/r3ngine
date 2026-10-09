import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const axiosMock = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  defaults: {},
  interceptors: { request: { use: vi.fn() } },
}));
vi.mock('axios', () => ({ default: axiosMock }));

import { changePassword, fetchCurrentUser, logoutSession } from '..';

const clearCsrfCookie = () => {
  document.cookie = 'csrftoken=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
};

beforeEach(() => {
  axiosMock.get.mockReset();
  axiosMock.post.mockReset();
  clearCsrfCookie();
});
afterEach(() => {
  clearCsrfCookie();
  vi.unstubAllGlobals();
});

describe('fetchCurrentUser', () => {
  it('asks for JSON and returns the body', async () => {
    const user = { id: 1, username: 'analyst', email: 'analyst@example.test', role: 'auditor' };
    axiosMock.get.mockResolvedValue({ data: user });
    await expect(fetchCurrentUser()).resolves.toEqual(user);
    expect(axiosMock.get).toHaveBeenCalledWith('/api/users/me/', {
      headers: { Accept: 'application/json' },
    });
  });
});

describe('logoutSession', () => {
  it('posts to the logout view with the CSRF cookie', async () => {
    document.cookie = 'csrftoken=tok123; path=/';
    axiosMock.post.mockResolvedValue({ data: {} });
    await logoutSession();
    expect(axiosMock.post).toHaveBeenCalledWith('/logout/', {}, {
      headers: { 'X-CSRFToken': 'tok123' },
    });
  });
});

describe('changePassword', () => {
  const fetchMock = vi.fn();
  const data = { old_password: 'old', new_password1: 'new', new_password2: 'new' };

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
  });

  it('posts the form to the project profile view', async () => {
    document.cookie = 'csrftoken=tok456; path=/';
    fetchMock.mockResolvedValue({ ok: true } as Response);
    await expect(changePassword('default', data)).resolves.toBe(true);

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/default/profile/');
    expect(init.method).toBe('POST');
    expect(init.headers).toEqual({ 'X-CSRFToken': 'tok456' });
    const body = init.body as FormData;
    expect(body.get('old_password')).toBe('old');
    expect(body.get('new_password1')).toBe('new');
    expect(body.get('new_password2')).toBe('new');
  });

  it('reports a rejected change and sends an empty token without a cookie', async () => {
    fetchMock.mockResolvedValue({ ok: false } as Response);
    await expect(changePassword('default', data)).resolves.toBe(false);
    expect(fetchMock.mock.calls[0][1].headers).toEqual({ 'X-CSRFToken': '' });
  });
});
