"""
js_collector.py — JavaScript File Collection

Reads all urls_*.txt files produced by fetch_url and downloads any discovered
.js files for downstream AST analysis. Deduplicates by SHA-256 so each unique
bundle is only analysed once per scan.

This module does NOT re-run Katana or any other crawler. It is a pure
post-processing step on files already produced by fetch_url.
"""

import glob
import hashlib
import logging
import os
import re

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Request timeout for downloading individual JS files
_JS_DOWNLOAD_TIMEOUT = 20  # seconds

# Maximum JS file size to download and analyse (10 MB)
_MAX_JS_SIZE_BYTES = 10 * 1024 * 1024

# Regex to match JS file URLs (including .mjs, .ts bundles)
_JS_URL_RE = re.compile(r'https?://[^\s]+\.(?:js|mjs|jsx|ts|tsx)(?:\?[^\s]*)?$', re.IGNORECASE)


def get_js_urls_from_results_dir(results_dir: str) -> list[str]:
    """Read all urls_*.txt files in results_dir and return discovered JS file URLs.

    Covers output from every fetch_url tool (katana, gau, gospider, waybackurls,
    hakrawler). Deduplicates by URL string; download_js_files deduplicates further
    by SHA-256 content hash.

    Args:
        results_dir (str): Path to the scan results directory.

    Returns:
        list[str]: Deduplicated list of JS file URLs found across all tool outputs.
    """
    file_paths = glob.glob(os.path.join(results_dir, 'urls_*.txt'))

    js_urls: list[str] = []
    seen: set[str] = set()
    for filepath in file_paths:
        try:
            with open(filepath, encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    url = line.strip()
                    if url and url not in seen and _JS_URL_RE.match(url):
                        seen.add(url)
                        js_urls.append(url)
        except OSError as exc:
            logger.error('[CPDE:js_collector] Failed to read %s: %s', filepath, exc)

    logger.warning(
        '[CPDE:js_collector] Found %d unique JS URLs across %d url file(s)',
        len(js_urls), len(file_paths),
    )
    return js_urls


def download_js_files(
    js_urls: list[str],
    session: requests.Session | None = None,
    proxy: str | None = None,
) -> list[dict]:
    """Download JS files and return their content with metadata.

    Skips files that exceed _MAX_JS_SIZE_BYTES or fail to download.
    Deduplicates identical files by SHA-256 hash so minified bundles
    served from multiple CDN paths are only analysed once.

    Args:
        js_urls (list[str]): JS file URLs to download.
        session (requests.Session | None): Optional shared session for connection reuse.
        proxy (str | None): Optional HTTP proxy URL.

    Returns:
        list[dict]: Each dict has keys:
            url (str), content (str), size (int), hash (str), content_type (str)
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from scanEngine.models import Proxy
    import random

    if session is None:
        session = requests.Session()

    available_proxies = []
    use_proxy = False
    if proxy:
        available_proxies = [proxy]
        use_proxy = True
    else:
        try:
            if Proxy.objects.all().exists():
                proxy_config = Proxy.objects.first()
                if proxy_config.use_proxy:
                    use_proxy = True
                    available_proxies = [p.strip() for p in proxy_config.proxies.splitlines() if p.strip()]
                    random.shuffle(available_proxies)
        except Exception as e:
            logger.error("[CPDE:js_collector] Failed to load proxies: %s", e)

    seen_hashes: set[str] = set()
    results: list[dict] = []
    
    def download_worker(url):
        logger.warning("[CPDE:js_collector] Downloading file: %s", url)
        max_retries = min(5, len(available_proxies)) if use_proxy and available_proxies else 1
        if max_retries < 1:
            max_retries = 1
            
        attempt = 0
        current_proxy_index = random.randint(0, len(available_proxies) - 1) if available_proxies else 0

        while attempt < max_retries:
            proxies = None
            if use_proxy and available_proxies:
                current_proxy_name = available_proxies[current_proxy_index % len(available_proxies)]
                proxies = {'http': current_proxy_name, 'https': current_proxy_name}
                
            try:
                try:
                    head = session.head(url, timeout=_JS_DOWNLOAD_TIMEOUT, proxies=proxies, allow_redirects=True, verify=False)
                    content_length = int(head.headers.get('Content-Length', 0))
                    if content_length > _MAX_JS_SIZE_BYTES:
                        logger.warning('[CPDE:js_collector] Skipping %s — too large (%d bytes)', url, content_length)
                        return None
                except Exception:
                    pass

                resp = session.get(url, timeout=_JS_DOWNLOAD_TIMEOUT, proxies=proxies, stream=True, verify=False)
                if resp.status_code == 200:
                    raw_content = b""
                    for chunk in resp.iter_content(chunk_size=8192):
                        if len(raw_content) + len(chunk) > _MAX_JS_SIZE_BYTES:
                            raw_content += chunk[:_MAX_JS_SIZE_BYTES - len(raw_content)]
                            break
                        raw_content += chunk
                    
                    content = raw_content.decode('utf-8', errors='replace')
                    file_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                    
                    logger.warning("[CPDE:js_collector] Download complete: %s", url)
                    return {
                        'url': url,
                        'content': content,
                        'size': len(raw_content),
                        'hash': file_hash,
                        'content_type': resp.headers.get('Content-Type', '')
                    }
                elif resp.status_code in [407, 502, 503, 504]:
                    raise requests.exceptions.ProxyError(f"Proxy returned status code {resp.status_code}")
                else:
                    break
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                attempt += 1
                current_proxy_index += 1
            except Exception as e:
                logger.debug(f"[CPDE:js_collector] JS downloader got non-network error for {url}: {e}")
                break
        return None

    MAX_FILES = 500
    if len(js_urls) > MAX_FILES:
        logger.warning("[CPDE:js_collector] Capping URLs from %d to %d to prevent stalling", len(js_urls), MAX_FILES)
        js_urls = list(js_urls)[:MAX_FILES]

    logger.warning("[CPDE:js_collector] Downloading %d JS files in parallel (max_workers=10)...", len(js_urls))
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(download_worker, url): url for url in js_urls}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    if res['hash'] not in seen_hashes:
                        seen_hashes.add(res['hash'])
                        results.append(res)
                    else:
                        logger.debug('[CPDE:js_collector] Skipping duplicate JS at %s', res['url'])
            except Exception as exc:
                logger.error('[CPDE:js_collector] Error in download thread: %s', exc)

    logger.warning(
        '[CPDE:js_collector] Download phase complete: %d / %d files downloaded successfully',
        len(results), len(js_urls),
    )
    return results
