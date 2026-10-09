import DOMPurify from 'dompurify';

/**
 * Sanitizes HTML content to prevent XSS attacks.
 * Use this when you must render HTML content from an untrusted source.
 */
export const sanitizeHtml = (html: string): string => {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li', 'code', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
    ALLOWED_ATTR: ['href', 'target', 'rel', 'class'],
  });
};

/**
 * Escapes characters that have special meaning in regular expressions.
 */
export const escapeRegExp = (string: string): string => {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
};

/**
 * Basic SQL Injection detection for input fields.
 * Note: This is a client-side helper, the backend MUST handle SQLi prevention.
 */
export const containsSqlInjection = (input: string): boolean => {
  const sqlKeywords = [
    '-- ',
    ';--',
    ' union ',
    ' select ',
    ' insert ',
    ' update ',
    ' delete ',
    ' drop ',
    ' truncate ',
    ' alter ',
    ' exec ',
    ' xp_',
  ];
  const lowercaseInput = input.toLowerCase();
  return sqlKeywords.some(keyword => lowercaseInput.includes(keyword));
};

// C0 controls and DEL: the URL parser drops tabs/newlines, so "java\tscript:" or "/\t/host" would
// reach the browser as something other than what was checked.
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;

/**
 * Validates if a URL is safe for redirection or linking: an absolute http(s) URL, or a
 * same-origin path. Protocol-relative (`//host`, `/\host`) and every other scheme
 * (`javascript:`, `data:`, `vbscript:`, `file:`...) are rejected.
 */
export const isSafeUrl = (url: string): boolean => {
  if (!url || CONTROL_CHARS.test(url)) return false;

  // Allow same-origin paths; browsers treat "/\" like "//" (protocol-relative).
  if (/^\/(?![/\\])/.test(url)) return true;

  // Allow only http and https protocols
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
};

/**
 * Returns the trimmed URL when {@link isSafeUrl} accepts it, otherwise `undefined`.
 * Use it for every `href`, `src` or `window.open` target built from API or user data
 * (security rule 4.2), e.g. `href={getSafeUrl(ref) ?? '#'}`.
 */
export const getSafeUrl = (url: string | null | undefined): string | undefined => {
  if (typeof url !== 'string') return undefined;
  const trimmed = url.trim();
  return isSafeUrl(trimmed) ? trimmed : undefined;
};

/**
 * `window.open` for a URL from API or user data: opens nothing and returns `null` when
 * {@link getSafeUrl} rejects it.
 */
export const openSafeUrl = (
  url: string | null | undefined,
  target = '_blank',
  features?: string,
): Window | null => {
  const safe = getSafeUrl(url);
  return safe ? window.open(safe, target, features) : null;
};
