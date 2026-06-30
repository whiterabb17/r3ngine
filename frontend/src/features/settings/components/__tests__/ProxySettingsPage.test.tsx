/**
 * Tests for proxy-line parsing helper.
 *
 * NOTE: Frontend test runner (vitest) not yet installed. To run:
 *   npm install --save-dev vitest @testing-library/react @testing-library/jest-dom jsdom
 * Then add to vite.config.ts: test: { environment: 'jsdom', globals: true }
 */
import { describe, it, expect } from 'vitest';
import { parseProxyLine } from '../ProxySettingsPage';

describe('parseProxyLine', () => {
  it('accepts bare host:port', () => {
    expect(parseProxyLine('192.168.1.1:1080')).toBe('192.168.1.1:1080');
  });
  it('accepts hostname:port', () => {
    expect(parseProxyLine('proxy.example.com:8080')).toBe('proxy.example.com:8080');
  });
  it('strips socks5:// prefix and returns bare host:port', () => {
    expect(parseProxyLine('socks5://10.0.0.1:1080')).toBe('10.0.0.1:1080');
  });
  it('strips socks4:// prefix', () => {
    expect(parseProxyLine('socks4://10.0.0.2:1080')).toBe('10.0.0.2:1080');
  });
  it('strips https:// prefix', () => {
    expect(parseProxyLine('https://10.0.0.3:443')).toBe('10.0.0.3:443');
  });
  it('strips http:// prefix', () => {
    expect(parseProxyLine('http://10.0.0.4:8080')).toBe('10.0.0.4:8080');
  });
  it('rejects lines without a port', () => {
    expect(parseProxyLine('192.168.1.1')).toBeNull();
  });
  it('rejects URL with path after port', () => {
    expect(parseProxyLine('http://evil.com:80/path')).toBeNull();
  });
  it('rejects javascript: scheme', () => {
    expect(parseProxyLine('javascript:void(0)')).toBeNull();
  });
  it('rejects data: URI', () => {
    expect(parseProxyLine('data:text/html,<script>alert(1)</script>')).toBeNull();
  });
  it('rejects empty string', () => {
    expect(parseProxyLine('')).toBeNull();
  });
  it('rejects whitespace-only string', () => {
    expect(parseProxyLine('   ')).toBeNull();
  });
  it('rejects # comment', () => {
    expect(parseProxyLine('# comment')).toBeNull();
  });
  it('rejects // comment', () => {
    expect(parseProxyLine('// comment')).toBeNull();
  });
  it('rejects port 0', () => {
    expect(parseProxyLine('1.2.3.4:0')).toBeNull();
  });
  it('rejects port 65536', () => {
    expect(parseProxyLine('1.2.3.4:65536')).toBeNull();
  });
  it('rejects line with embedded credentials', () => {
    expect(parseProxyLine('user:pass@1.2.3.4:1080')).toBeNull();
  });
});

describe('deduplication count', () => {
  it('counts only new unique entries, not total fetched', () => {
    const existingSet = new Set([
      'socks5://1.2.3.4:1080',
      'socks5://2.3.4.5:1080',
    ]);
    const incoming = [
      'socks5://1.2.3.4:1080',
      'socks5://2.3.4.5:1080',
      'socks5://9.9.9.9:1080',
    ];
    const newEntries = incoming.filter(p => !existingSet.has(p));
    expect(newEntries).toHaveLength(1);
    expect(newEntries[0]).toBe('socks5://9.9.9.9:1080');
  });
});
