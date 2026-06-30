---
description: Security guidelines for r3ngine — path traversal, log injection, URLs, XSS in React, dynamic objects, file permissions, exceptions, network binding, and external scripts.
---

# r3ngine – Security rules

## 1. Paths and file system (Path traversal / Uncontrolled path)

- **Rule 1.1**: No data coming from the user, the request or the database (domain names, model fields, URL parameters) must be concatenated directly with `Path()`, `os.path.join()` or passed to `open()` without validation.
- **Rule 1.2**: Before using any path constructed from uncontrolled data:
  - Resolve the full path with `os.path.realpath()` or `pathlib.Path.resolve()`.
  - Assert the resolved path starts with the expected base directory (`str(resolved).startswith(str(base))`).
  - Reject any path containing `..` segments, leading `/`, or null bytes before resolution.
- **Rule 1.3**: Do not duplicate safe-path logic. If a helper already validates paths in `common_func.py` or a utility module, reuse it — do not re-implement inline.
- **Rule 1.4**: Sanitise path-segment input (domain names, scan names used in file paths) by allowing only safe characters (alphanumeric, hyphens, dots) and rejecting everything else.

## 2. Logs (Log injection)

- **Rule 2.1**: For any logger call whose message can contain user, request or database data (names, URLs, IDs, external error messages), use **only** `%`-style formatting with arguments:
  ```python
  logger.info("Scanning target %s with config %s", target_name, config_id)
  ```
  Do not use f-strings or string concatenation in log messages for externally-controlled data.
- **Rule 2.2**: During code review, reject any pattern like `logger.info(f"... {variable}")` when `variable` is or may be externally controlled.

## 3. URLs (Incomplete URL substring sanitization)

- **Rule 3.1**: To compare the host or scheme of a URL, use `urllib.parse.urlparse(url)` and compare `.netloc` / `.hostname` and `.scheme`. Do not use substring checks like `"example.com" in url`.
- **Rule 3.2**: URLs constructed from user data (display, redirects, outgoing requests) must validate the scheme (allow only `http`/`https`; reject `javascript:`, `data:`, `file:`, etc.) before use.

## 4. XSS and dynamic content (React frontend)

- **Rule 4.1**: React's JSX renderer escapes values by default. Never bypass this with `dangerouslySetInnerHTML` unless the content is sanitised first (e.g. via DOMPurify). Document every use of `dangerouslySetInnerHTML` with a comment explaining why it is safe.
- **Rule 4.2**: For `href` or `src` attributes set from API data or user input, validate the scheme before assignment:
  ```typescript
  // ❌ Bad
  <a href={userProvidedUrl}>Link</a>

  // ✅ Good
  const safeSrc = /^https?:\/\//i.test(userProvidedUrl) ? userProvidedUrl : '#';
  <a href={safeSrc}>Link</a>
  ```
- **Rule 4.3**: Do not assign raw HTML strings via `element.innerHTML` in any vanilla JS code that exists alongside React. Use DOM APIs or React state instead.
- **Rule 4.4**: In any remaining Django templates (e.g. admin customisations), render variables with `{{ value|escape }}` by default. Use `{{ value|safe }}` only with documented justification.

## 5. Dynamic objects and properties (Remote property injection)

- **Rule 5.1**: When an object key comes from the network, an API response, or user input, do not use it directly on a plain object literal (`obj[key]`). Either use a `Map` (keys do not affect prototype) or validate the key against an allowlist.
- **Rule 5.2**: Treat any usage of `response[key]`, `item[field]` or `options[userInput]` as suspicious during code review if the key is not a constant or a documented server-side enum.

## 6. File permissions (Overly permissive file permissions)

- **Rule 6.1**: Files created by the application (reports, scan output, uploads) must not use `0o777`. Prefer `0o640` for group-readable files or `0o600` for sensitive data.
- **Rule 6.2**: In tests, use the most restrictive mode that fits the scenario (e.g. `0o400` for read-only) and document the reason.

## 7. Cross-cutting rules

- **Rule 7.1**: Do not duplicate security logic. Have a single place for path validation, a single one for URL scheme checking. Other modules call these helpers.
- **Rule 7.2**: Prefer native Django mechanisms (CSRF, template escaping, ORM parameterisation, file storage) and only bypass them with documented justification.
- **Rule 7.3**: Security findings from CodeQL, bandit, or manual review at High/Medium severity must be addressed or explicitly accepted with justification — do not ignore without trace.

## 8. Information exposure through exceptions

- **Rule 8.1**: Never return raw exception text (`str(e)`, tracebacks) to the client via HTTP response, WebSocket, or JSON. Always:
  - Log the full exception server-side: `logger.exception("Context message")` or `logger.error("...", exc_info=True)`.
  - Return a generic error message to the client.
- **Rule 8.2**: For known validation errors (`ValidationError`, explicit user-facing messages), return only the sanitised message. For unknown/500-level errors, return a fixed generic string.

## 9. Network binding (Binding socket to all interfaces)

- **Rule 9.1**: Development or debug servers (e.g. debugpy) must not bind to `0.0.0.0` by default. Use `127.0.0.1` to restrict to localhost.
- **Rule 9.2**: If binding on all interfaces is required (e.g. remote debugging in Docker), gate it behind an explicit environment variable and document the risks.

## 10. External scripts (Inclusion from untrusted source)

- **Rule 10.1**: The r3ngine frontend is built with Vite and bundles all dependencies — do not add CDN script tags to React components or HTML templates.
- **Rule 10.2**: If a CDN script is ever added to a Django template or static HTML file, it must include an SRI `integrity` attribute and `crossorigin="anonymous"`. Update the SRI hash on every version upgrade.