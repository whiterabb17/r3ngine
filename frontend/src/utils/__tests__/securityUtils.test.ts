import { describe, expect, it, vi } from 'vitest';

import { getSafeUrl, isSafeUrl, openSafeUrl } from '../securityUtils';

describe('getSafeUrl', () => {
  it.each([
    'http://example.test/advisory',
    'https://example.test/path?q=1#frag',
    'HTTPS://EXAMPLE.TEST/',
    'HtTp://example.test',
    '/media/screenshots/shot.png',
    '/scan/report/1',
  ])('accepts %s', (url) => {
    expect(getSafeUrl(url)).toBe(url);
  });

  it.each([
    'javascript:alert(1)',
    'JavaScript:alert(1)',
    'JAVASCRIPT:alert(1)',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'DATA:image/svg+xml,<svg onload=alert(1)>',
    'vbscript:msgbox(1)',
    'VBScript:msgbox(1)',
    'file:///etc/passwd',
    'ftp://example.test/file',
    'mailto:user@example.test',
    '//evil.test/path',
    '/\\evil.test/path',
    'example.test/path',
    'relative/path',
    '#anchor',
    '',
  ])('rejects %s', (url) => {
    expect(getSafeUrl(url)).toBeUndefined();
  });

  it('trims surrounding whitespace from accepted URLs', () => {
    expect(getSafeUrl('  https://example.test/a \n')).toBe('https://example.test/a');
    expect(getSafeUrl('\t/media/a.png ')).toBe('/media/a.png');
  });

  it('rejects dangerous schemes hidden behind whitespace', () => {
    expect(getSafeUrl('  javascript:alert(1)')).toBeUndefined();
    expect(getSafeUrl('\njavascript:alert(1)')).toBeUndefined();
  });

  it('rejects embedded control characters the URL parser would strip', () => {
    expect(getSafeUrl('java\tscript:alert(1)')).toBeUndefined();
    expect(getSafeUrl('java\nscript:alert(1)')).toBeUndefined();
    expect(getSafeUrl('/\t/evil.test')).toBeUndefined();
    expect(getSafeUrl('https://exa\u0000mple.test')).toBeUndefined();
  });

  it('returns undefined for missing values', () => {
    expect(getSafeUrl(null)).toBeUndefined();
    expect(getSafeUrl(undefined)).toBeUndefined();
  });
});

describe('isSafeUrl', () => {
  it('agrees with getSafeUrl on untrimmed input', () => {
    expect(isSafeUrl('https://example.test')).toBe(true);
    expect(isSafeUrl('/path')).toBe(true);
    expect(isSafeUrl('javascript:alert(1)')).toBe(false);
    expect(isSafeUrl(' javascript:alert(1)')).toBe(false);
  });
});

describe('openSafeUrl', () => {
  it('opens safe URLs with the given target and features', () => {
    const win = {} as Window;
    const open = vi.spyOn(window, 'open').mockReturnValue(win);
    expect(openSafeUrl(' /media/report.pdf ', '_blank', 'noopener')).toBe(win);
    expect(open).toHaveBeenCalledWith('/media/report.pdf', '_blank', 'noopener');
    open.mockRestore();
  });

  it('does not open unsafe or missing URLs', () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    expect(openSafeUrl('javascript:alert(1)')).toBeNull();
    expect(openSafeUrl(undefined)).toBeNull();
    expect(open).not.toHaveBeenCalled();
    open.mockRestore();
  });
});
