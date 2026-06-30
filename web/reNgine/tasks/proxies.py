import logging
import re
import json
import threading
import concurrent.futures
import requests

from django.utils import timezone as _dj_tz

from reNgine.common_func import *
from reNgine.definitions import *

logger = logging.getLogger(__name__)


def fetch_proxies_task(limit=1000, job_id=None):
    """Scrape proxies concurrently from a large list of public sources,
    verify their validity against robust target APIs, and return the live ones.

    Args:
        limit (int, optional): Maximum number of raw proxies to scrape and check. Defaults to 1000.

    Returns:
        str: Newline-separated list of validated live proxies.
    """
    from reNgine.common_func import check_proxy_robust, is_proxy_recently_used
    from reNgine.job_tracker import update_job as _update_job
    from scanEngine.models import Proxy

    logger.info(f"Starting automated proxy fetch and verification task (limit={limit}).")
    if job_id:
        _update_job(job_id, 'RUNNING', 10, 'Downloading new proxies')

    proxy_urls = [
        'https://api.proxyscrape.com/v2/?request=displayproxies',
        'https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt',
        'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
        'https://raw.githubusercontent.com/yuceltoluyag/GoodProxy/main/raw.txt',
        'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
        'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt',
        'https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt',
        'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
        'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt',
        'https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt',
        'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt',
        'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt',
        'https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt',
        'https://proxyspace.pro/http.txt',
        'https://api.proxyscrape.com/?request=displayproxies&proxytype=http',
        'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
        'http://worm.rip/http.txt',
        'http://alexa.lr2b.com/proxylist.txt',
        'https://api.openproxylist.xyz/http.txt',
        'http://rootjazz.com/proxies/proxies.txt',
        'https://multiproxy.org/txt_all/proxy.txt',
        'https://proxy-spider.com/api/proxies.example.txt',
        'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
        'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=anonymous',
        'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt',
        'https://raw.githubusercontent.com/Firdoxx/proxy-list/main/https',
        'https://raw.githubusercontent.com/Firdoxx/proxy-list/main/http',
        'https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt',
        'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt',
        'https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt',
        'https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt',
        'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt',
        'https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt',
        'https://raw.githubusercontent.com/casals-ar/proxy-list/main/http',
        'https://raw.githubusercontent.com/casals-ar/proxy-list/main/https',
        'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt',
        'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt',
        'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt',
        'https://raw.githubusercontent.com/Jakee8718/Free-Proxies/main/proxy/-http%20and%20https.txt',
        'https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/http.txt',
        'https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/https.txt',
        'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt',
        'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt',
        'https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all',
        'https://www.proxy-list.download/api/v1/get?type=socks5',
        'https://raw.githubusercontent.com/manuGMG/proxy-365/main/SOCKS5.txt',
        'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt',
        'https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt',
        'https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt',
        'https://raw.githubusercontent.com/a2u/free-proxy-list/master/free-proxy-list.txt',
        'https://raw.githubusercontent.com/mishakorzik/Free-Proxy/main/proxy.txt',
        'https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list/data.txt',
        'https://raw.githubusercontent.com/UptimerBot/proxy-list/master/proxies/http.txt',
        'https://github.com/hookzof/socks5_list/blob/master/proxy.txt',
        'https://github.com/jetkai/proxy-list/blob/main/online-proxies/txt/proxies-http.txt',
        'https://github.com/jetkai/proxy-list/blob/main/online-proxies/txt/proxies-https.txt',
        'https://github.com/jetkai/proxy-list/blob/main/online-proxies/txt/proxies-socks4.txt',
        'https://github.com/jetkai/proxy-list/blob/main/online-proxies/txt/proxies-socks5.txt',
        'https://github.com/jetkai/proxy-list/blob/main/online-proxies/txt/proxies.txt',
        'https://github.com/clarketm/proxy-list/blob/master/proxy-list-raw.txt'
    ]

    all_proxies = set()
    for url in proxy_urls:
        if len(all_proxies) >= limit:
            break

        if 'github.com' in url and '/blob/' in url:
            url = url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')

        logger.info(f"Downloading proxy list from: {url}")
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                lines = response.text.splitlines()
                added_this_url = 0
                for line in lines:
                    if len(all_proxies) >= limit:
                        break

                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('//') or line.startswith('<'):
                        continue

                    parts = re.split(r'[\s,;]+', line)
                    token = parts[0].strip()
                    if ':' in token:
                        if token not in all_proxies:
                            all_proxies.add(token)
                            added_this_url += 1

                logger.info(f"Successfully added {added_this_url} raw proxies from {url}")
            else:
                logger.warning(f"Failed to download proxy list from {url}. Status code: {response.status_code}")
        except Exception as e:
            logger.error(f"Error fetching proxies from {url}: {str(e)}")

    unique_proxies = list(all_proxies)[:limit]
    total = len(unique_proxies)
    logger.info(f"Total unique raw proxies fetched: {total} (capped at {limit})")

    if job_id:
        _update_job(job_id, 'RUNNING', 30, f'Verifying {total} proxies')

    live_proxies = []
    lock = threading.Lock()
    completed_count = [0]
    _job_id = job_id

    MAX_WORKERS = min(32, max(1, total))

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_map = {pool.submit(check_proxy_robust, p, 10): p for p in unique_proxies}
        for future in concurrent.futures.as_completed(future_map):
            proxy_str = future_map[future]
            try:
                alive = future.result()
            except Exception:
                alive = False
            if alive:
                logger.info("Proxy LIVE: %s", proxy_str)
                with lock:
                    live_proxies.append(proxy_str)
            with lock:
                completed_count[0] += 1
                done = completed_count[0]
            if done % 50 == 0 or done == total:
                logger.info(f"Verification progress: {done}/{total} - Found {len(live_proxies)} live proxies so far.")
                progress = 30 + int((done / total) * 65)
                if _job_id:
                    _update_job(
                        _job_id, 'RUNNING', progress,
                        f'Checking proxies: {done}/{total} ({len(live_proxies)} live)',
                    )

    logger.info(f"Proxy verification complete. Found {len(live_proxies)} live proxies out of {total} tested.")
    if job_id:
        _update_job(job_id, 'RUNNING', 95, 'Formatting live proxies')

    final_list = [f"http://{p}" if not p.startswith('http') and not p.startswith('socks') else p for p in live_proxies]

    proxy_str = "\n".join(final_list)
    try:
        proxy_obj = Proxy.objects.first()
        if not proxy_obj:
            proxy_obj = Proxy.objects.create()

        # Preserve proxies that were successfully used within the last 24 hours
        existing_proxies = [p.strip() for p in (proxy_obj.proxies or '').splitlines() if p.strip()]
        final_set = set(final_list)
        preserved = [p for p in existing_proxies if is_proxy_recently_used(p) and p not in final_set]
        if preserved:
            logger.info('Preserving %d recently-used proxies during pool refresh.', len(preserved))
            final_list = final_list + preserved
            proxy_str = "\n".join(final_list)

        proxy_obj.proxies = proxy_str
        proxy_obj.use_proxy = True
        proxy_obj.proxies_verified_at = _dj_tz.now()
        proxy_obj.save()
        logger.info("Automatically saved live proxies to database (verified_at=%s).", proxy_obj.proxies_verified_at)
    except Exception as e:
        logger.error(f"Failed to auto-save proxies: {e}")

    if job_id:
        _update_job(job_id, 'SUCCESS', 100, 'Proxy list updated and saved automatically', result={"count": len(final_list), "proxies": proxy_str})
    logger.info("Automated proxy fetch task finished successfully.")
    return proxy_str
