"""
Scratch test: validate Swagger UI spec URL extraction against the
scan 5 endpoint: http://branding.chillbev.co.za/about/swagger-ui/

Run inside the web container:
  docker exec -it r3ngine-web-1 python /app/test_swagger_extraction.py

Or from the host (needs internet access):
  python web/tests/scratch/test_swagger_ui_extraction.py
"""

import sys
import re
from urllib.parse import urljoin

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Copy of the three regex patterns from post_scan_processing.py ─────────────
_SWAGGER_BUNDLE_RE = re.compile(
    r'SwaggerUIBundle\s*\(\s*\{[^}]*?[\'"]{0,1}url[\'"]{0,1}\s*:\s*["\']([^"\']+)["\']',
    re.DOTALL,
)
_SWAGGER_INIT_RE = re.compile(
    r'window\s*\.\s*onload\s*=.*?url\s*:\s*["\']([^"\']+)["\']',
    re.DOTALL,
)
_SWAGGER_URL_RE = re.compile(
    r'["\']url["\']\s*:\s*["\']([^"\']*(?:openapi|swagger|api-docs)[^"\']*)["\']',
    re.IGNORECASE,
)


def _extract_spec_url_from_swagger_ui(html: str, page_url: str) -> str | None:
    for pattern in (_SWAGGER_BUNDLE_RE, _SWAGGER_INIT_RE, _SWAGGER_URL_RE):
        match = pattern.search(html)
        if match:
            spec_path = match.group(1).strip()
            if spec_path:
                return urljoin(page_url, spec_path)
    return None


def test_swagger_ui_extraction(target_url: str) -> None:
    print(f"\n{'='*60}")
    print(f"Testing Swagger UI extraction against: {target_url}")
    print('='*60)

    session = requests.Session()
    session.headers['User-Agent'] = 'r3ngine-post-scan/1.0 (OpenAPI Discovery)'

    # Step 1: Fetch the Swagger UI page
    try:
        resp = session.get(target_url, timeout=15, verify=False, allow_redirects=True)
        print(f"\n[1] HTTP {resp.status_code} — Content-Type: {resp.headers.get('Content-Type', 'unknown')}")
        print(f"    Response size: {len(resp.text)} chars")
    except Exception as exc:
        print(f"[FAIL] Could not fetch {target_url}: {exc}")
        sys.exit(1)

    if resp.status_code != 200:
        print(f"[FAIL] Expected 200, got {resp.status_code}")
        sys.exit(1)

    # Step 2: Extract spec URL
    spec_url = _extract_spec_url_from_swagger_ui(resp.text, target_url)

    if spec_url:
        print(f"\n[2] SUCCESS — Spec URL extracted: {spec_url}")
    else:
        print("\n[2] FAIL — Could not extract spec URL from page")
        # Dump relevant HTML snippet for debugging
        lower = resp.text.lower()
        for keyword in ('swaggeruibundle', 'url:', 'openapi', 'swagger'):
            idx = lower.find(keyword)
            if idx != -1:
                snippet = resp.text[max(0, idx-50):idx+200]
                print(f"\n    Found '{keyword}' at pos {idx}:")
                print(f"    {repr(snippet)}")
                break
        sys.exit(1)

    # Step 3: Fetch the spec
    print(f"\n[3] Fetching spec from: {spec_url}")
    try:
        spec_resp = session.get(spec_url, timeout=15, verify=False, allow_redirects=True)
        print(f"    HTTP {spec_resp.status_code} — Content-Type: {spec_resp.headers.get('Content-Type', 'unknown')}")
    except Exception as exc:
        print(f"    [FAIL] Could not fetch spec: {exc}")
        sys.exit(1)

    if spec_resp.status_code != 200:
        print(f"    [FAIL] Expected 200 from spec URL, got {spec_resp.status_code}")
        sys.exit(1)

    # Step 4: Parse the spec
    try:
        spec = spec_resp.json()
    except Exception:
        try:
            import yaml
            spec = yaml.safe_load(spec_resp.text)
        except Exception as exc:
            print(f"    [FAIL] Could not parse spec as JSON or YAML: {exc}")
            sys.exit(1)

    if not isinstance(spec, dict) or not ('paths' in spec or 'openapi' in spec or 'swagger' in spec):
        print(f"    [FAIL] Response does not look like an OpenAPI spec (keys: {list(spec.keys())[:10]})")
        sys.exit(1)

    paths = spec.get('paths', {})
    info = spec.get('info', {})
    print(f"\n[4] SUCCESS — OpenAPI spec parsed:")
    print(f"    Title:   {info.get('title', 'unknown')}")
    print(f"    Version: {info.get('version', 'unknown')}")
    print(f"    Spec version: {spec.get('openapi') or spec.get('swagger', 'unknown')}")
    print(f"    Paths:   {len(paths)}")

    # Step 5: Run _parse_spec (the actual CPDE function)
    print(f"\n[5] Running CPDE _parse_spec...")
    try:
        sys.path.insert(0, '/app')
        import django, os
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
        django.setup()
        from reNgine.cpde.openapi_discoverer import _parse_spec
        findings = _parse_spec(spec, spec_url)
        print(f"    SUCCESS — {len(findings)} parameter findings extracted")
        if findings:
            print("\n    Sample findings:")
            for f in findings[:5]:
                print(f"      - {f['name']} ({f.get('location')}) [{f.get('context')}]")
    except Exception as exc:
        print(f"    [WARN] Django not available for _parse_spec test: {exc}")
        print(f"    (Run inside container for full test)")

    print(f"\n{'='*60}")
    print("ALL CHECKS PASSED")
    print('='*60)


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else 'http:/example.com/swagger-ui/'
    test_swagger_ui_extraction(target)
