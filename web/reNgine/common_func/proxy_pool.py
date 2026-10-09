"""Proxy pool validation, selection and in-process caches, plus user-agent rotation.

Split out of the former reNgine/common_func.py; re-exported by
reNgine.common_func for backward compatibility.
"""
import ipaddress
import random
import re
import threading
import time
import logging

import requests

from reNgine.settings import (
	PROXY_SAMPLE_ATTEMPTS,
	PROXY_TRUST_WINDOW_SECONDS,
	PROXY_VALIDATION_MAX_WORKERS,
	PROXY_VALIDATION_TIMEOUT,
)
from scanEngine.models import Proxy

logger = logging.getLogger(__name__)


# Curated pool of modern desktop browser user agents for realistic request spoofing.
_USER_AGENT_POOL = [
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
	'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0',
	'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Vivaldi/6.7.3329.21',
]


_DEFAULT_USER_AGENT = _USER_AGENT_POOL[0]


# 5 popular, fast public checkers in preference order
ALL_PROXY_CHECKERS = [
	("https://whatismyip.akamai.com/", "plain"),
	("https://cloudflare.com/cdn-cgi/trace", "cloudflare"),
	("https://api.ip.sb/ip", "plain"),
	("https://ifconfig.co/ip", "plain"),
	("https://icanhazip.com", "plain"),
]


# Cache of proxies known to be dead within this process lifetime, mapping proxy_url -> epoch timestamp.
_failed_proxy_cache: dict = {}


_FAILED_PROXY_TTL = 1800  # 30 minutes


# Cache of proxies successfully validated and used, mapping proxy_url -> epoch timestamp.
# Protects proxies from DB removal for 24 hours after last successful use.
_used_proxy_cache: dict = {}


_USED_PROXY_TTL = 86400  # 24 hours


# Serialises read-modify-write operations on Proxy.proxies within this process.
# select_for_update() handles cross-process serialisation at the DB level.
_proxy_pool_lock = threading.Lock()


# Standard exceptions suggesting proxy itself is down/unreachable (connection phase)
_PROXY_DEAD_EXCEPTIONS = (
	requests.exceptions.ProxyError,
	requests.exceptions.ConnectTimeout,
	requests.exceptions.ConnectionError,
)


_PROXY_DEAD_KEYWORDS = ('proxyerror', 'connecttimeout', 'refused', 'unreachable', 'connection reset', 'connection aborted')


def _detect_server_ip(timeout: int = 5) -> str:
	"""Return the server's own outbound IP by hitting an IP-reflection API
	without a proxy. Returns '' on any failure.

	Used only when OpSec transparent-proxy detection is enabled.
	"""
	try:
		resp = requests.get(
			'https://api.ipify.org?format=json',
			timeout=timeout,
			headers={'User-Agent': 'Mozilla/5.0'},
		)
		if resp.status_code == 200:
			return resp.json().get('ip', '')
	except (requests.RequestException, ValueError, AttributeError):
		# Detection was explicitly enabled, so running without it must be visible.
		logger.warning("Server IP lookup failed; transparent proxy detection is skipped", exc_info=True)
	return ''


def mark_proxy_used(proxy_url: str) -> None:
	"""Record that a proxy was successfully validated and used.

	Proxies in this cache are shielded from remove_proxy_from_pool for
	_USED_PROXY_TTL seconds (24 h) after last successful use, preventing
	transient failures from evicting known-good proxies.
	"""
	normalized = _normalize_proxy_pool_line(proxy_url)
	if normalized:
		_used_proxy_cache[normalized] = time.time()


def is_proxy_recently_used(proxy_url: str) -> bool:
	"""Return True if the proxy was successfully used within the last 24 hours."""
	normalized = _normalize_proxy_pool_line(proxy_url)
	if not normalized:
		return False
	last_used = _used_proxy_cache.get(normalized)
	return last_used is not None and (time.time() - last_used) < _USED_PROXY_TTL


def check_proxy_robust(proxy_url, timeout=PROXY_VALIDATION_TIMEOUT, server_ip=''):
	"""Test if a proxy is truly working and not transparent.
	Avoids false positives from captive portals, ISP redirects, or proxy auth/block pages
	by making a request to a public API returning a JSON payload or plain text with client IP.
	"""
	proxy_url = proxy_url.strip()
	if not proxy_url:
		return False
	test_proxy = proxy_url
	if not any(test_proxy.startswith(s) for s in ['http://', 'https://', 'socks4://', 'socks5://', 'socks5h://']):
		test_proxy = 'http://' + test_proxy

	# Select two checkers deterministically within this process lifetime.
	# hash() is randomized per-process (PYTHONHASHSEED) so selection varies
	# across worker restarts — this is intentional: it spreads load across
	# checkers without requiring a PRNG or state.
	hash_val = abs(hash(proxy_url))
	idx1 = hash_val % len(ALL_PROXY_CHECKERS)
	idx2 = (hash_val + 1) % len(ALL_PROXY_CHECKERS)
	check_targets = [ALL_PROXY_CHECKERS[idx1], ALL_PROXY_CHECKERS[idx2]]

	def _try_proxy(scheme_proxy):
		"""Return (reported_ip, errors) for the given proxy URL."""
		proxies = {'http': scheme_proxy, 'https': scheme_proxy}
		headers = {"User-Agent": _DEFAULT_USER_AGENT}
		errors = []
		with requests.Session() as session:
			session.proxies = proxies
			session.headers.update(headers)
			for url, expected_type in check_targets:
				try:
					response = session.get(
						url,
						timeout=timeout,
						allow_redirects=True
					)
					if response.status_code == 200:
						text = response.text.strip()
						if expected_type == "cloudflare":
							# Parse cloudflare trace line-by-line to extract IP
							for line in text.splitlines():
								if line.startswith("ip="):
									val = line.split("=", 1)[1].strip()
									try:
										ipaddress.ip_address(val)
										return val, []
									except ValueError:
										pass
							errors.append("Could not parse IP from cloudflare trace")
						elif expected_type == "plain":
							try:
								ipaddress.ip_address(text)
								return text, []
							except ValueError:
								errors.append(f"Invalid IP address format: {text[:50]}")
					else:
						errors.append(f"HTTP {response.status_code}")
				except Exception as exc:
					errors.append(exc)
					# If the proxy itself is unreachable or times out, stop checking further targets
					if isinstance(exc, _PROXY_DEAD_EXCEPTIONS) or any(k in str(exc).lower() for k in _PROXY_DEAD_KEYWORDS):
						break
		return None, errors

	# 1) Try with the original scheme
	reported_ip, errors = _try_proxy(test_proxy)

	# 2) For socks5:// only, retry with socks5h:// (remote DNS via proxy).
	if not reported_ip and test_proxy.startswith('socks5://'):
		is_proxy_unreachable = False
		for err in errors:
			if isinstance(err, _PROXY_DEAD_EXCEPTIONS) or any(k in str(err).lower() for k in _PROXY_DEAD_KEYWORDS):
				is_proxy_unreachable = True
				break
		if not is_proxy_unreachable:
			socks5h_proxy = test_proxy.replace('socks5://', 'socks5h://', 1)
			logger.debug("check_proxy_robust: retrying with remote DNS via %s", socks5h_proxy)
			reported_ip, _ = _try_proxy(socks5h_proxy)

	if not reported_ip:
		return False

	# Optional transparent-proxy detection
	if server_ip and reported_ip == server_ip:
		logger.warning(
			'Proxy %s is transparent – reported IP %s matches server IP. Rejecting.',
			proxy_url, reported_ip,
		)
		return False

	return True


def validate_single_proxy(proxy_name):
	"""Helper to validate a single proxy string.
	Returns (proxy_name, True) if valid, otherwise (proxy_name, False).
	"""
	is_valid = check_proxy_robust(proxy_name)
	return proxy_name, is_valid


def validate_proxies(proxy_text):
	"""Concurrently validate newline-separated proxy strings using the same robust logic as the fetch task.
	Returns a newline-separated string of validated live proxies.
	"""
	from concurrent.futures import ThreadPoolExecutor, as_completed
	if not proxy_text:
		return ''
	raw_proxies = [line.strip() for line in proxy_text.splitlines() if line.strip()]
	if not raw_proxies:
		return ''
	valid_proxies = []
	max_workers = min(PROXY_VALIDATION_MAX_WORKERS, max(1, len(raw_proxies)))
	with ThreadPoolExecutor(max_workers=max_workers) as executor:
		future_to_proxy = {executor.submit(check_proxy_robust, p, PROXY_VALIDATION_TIMEOUT): p for p in raw_proxies}
		for future in as_completed(future_to_proxy):
			proxy_name = future_to_proxy[future]
			try:
				is_valid = future.result()
			except Exception:
				is_valid = False
			if is_valid:
				valid_proxies.append(proxy_name)
	return '\n'.join(valid_proxies)


def _normalize_proxy_pool_line(proxy_line):
	"""Normalize a proxy line for consistent persistence comparisons."""
	proxy_line = (proxy_line or '').strip()
	if not proxy_line:
		return ''
	if not proxy_line.startswith('http') and not proxy_line.startswith('socks'):
		return f"http://{proxy_line}"
	return proxy_line


def get_valid_proxy_count(proxy_obj=None):
	"""Return the count of persisted non-empty proxy lines."""
	proxy_obj = proxy_obj or Proxy.objects.first()
	if not proxy_obj or not proxy_obj.proxies:
		return 0
	return len([line for line in proxy_obj.proxies.splitlines() if line.strip()])


# Matches the userinfo part of any URL, e.g. socks5://user:pass@host:1234.
# Deliberately narrow: the password must not contain '@', '/' or whitespace,
# which is exactly the shape a usable proxy URL has (specials percent-encoded).
_URL_CREDENTIALS_RE = re.compile(
	r'([a-zA-Z][a-zA-Z0-9+.\-]*://)([^:/@\s]+):([^@/\s]+)@'
)


def redact_proxy_credentials(text):
	"""Mask the password in any credentialed URL inside `text`.

	An authenticated proxy (socks5://user:pass@host:port) reaches the scan tools
	as a plain command-line argument, so without this the password lands in the
	Command table, the scan log shown in the UI, the Redis log stream and
	`docker logs`. The username is kept so a run stays identifiable.
	"""
	if not text:
		return text
	if not isinstance(text, str):
		text = str(text)
	return _URL_CREDENTIALS_RE.sub(r'\1\2:***@', text)


def get_priority_proxies(proxy_obj=None):
	"""Return the operator's hand-entered proxies, in the order they were typed.

	These live in their own field, which is what keeps fetch_proxies_task from
	overwriting them and remove_proxy_from_pool from evicting them: both operate
	on the scraped `proxies` field only.
	"""
	proxy_obj = proxy_obj or Proxy.objects.first()
	if not proxy_obj or not getattr(proxy_obj, 'use_priority_proxies', True):
		return []
	return [
		line.strip()
		for line in (getattr(proxy_obj, 'priority_proxies', '') or '').splitlines()
		if line.strip()
	]


def proxy_has_credentials(proxy_line):
	"""True when a proxy line carries userinfo, e.g. socks5://user:pass@host:1234.

	Credentialed entries are hand-entered paid endpoints, never scraped ones, so
	this doubles as the test for "the operator typed this in and wants it kept".
	"""
	proxy_line = (proxy_line or '').strip()
	if not proxy_line:
		return False
	authority = proxy_line.split('://', 1)[-1]
	# Trim anything after the host:port part before looking for userinfo.
	authority = authority.split('/', 1)[0]
	return '@' in authority


def remove_proxy_from_pool(proxy_value, proxy_obj=None):
	"""Remove a proxy from the persisted pool safely and idempotently.

	Proxies that were successfully used within the last 24 hours are protected
	from removal even if they temporarily fail a liveness check.

	Credentialed proxies are never removed at all. Both callers are automatic
	health checks, and a single timed-out check used to delete a paid endpoint
	from the database permanently — the check is far less reliable than the
	proxy it judges.
	"""
	if is_proxy_recently_used(proxy_value):
		logger.info(
			'Proxy %s was recently used — skipping removal to honour 24-hour retention.',
			redact_proxy_credentials(proxy_value),
		)
		return False

	proxy_obj = proxy_obj or Proxy.objects.first()
	if not proxy_obj or not proxy_obj.proxies:
		return False

	if proxy_has_credentials(proxy_value):
		logger.warning(
			'Proxy %s failed its check but carries credentials — keeping it in the pool.',
			redact_proxy_credentials(proxy_value),
		)
		return False

	target = _normalize_proxy_pool_line(proxy_value)
	if not target:
		return False

	from django.db import transaction

	with _proxy_pool_lock:
		with transaction.atomic():
			# Re-fetch inside lock+transaction; select_for_update prevents
			# concurrent DB transactions from reading a stale pool simultaneously.
			if proxy_obj is None:
				locked_obj = Proxy.objects.select_for_update().first()
			else:
				locked_obj = Proxy.objects.select_for_update().filter(pk=proxy_obj.pk).first()

			if not locked_obj or not locked_obj.proxies:
				return False

			remaining_lines = []
			removed = False
			for line in locked_obj.proxies.splitlines():
				stripped = line.strip()
				if not stripped:
					continue
				if not removed and _normalize_proxy_pool_line(stripped) == target:
					removed = True
					continue
				remaining_lines.append(stripped)

			if removed:
				locked_obj.proxies = '\n'.join(remaining_lines)
				locked_obj.save(update_fields=['proxies'])

	return removed


def remove_proxies_from_pool(proxy_values, proxy_obj=None):
	"""Remove multiple proxies from the persisted pool safely and idempotently.
	"""
	targets = []
	for pv in proxy_values:
		if is_proxy_recently_used(pv):
			continue
		if proxy_has_credentials(pv):
			# Same rule as the single-proxy path: a hand-entered paid endpoint is
			# never dropped on the word of an automatic health check.
			logger.warning(
				'Proxy %s failed its check but carries credentials — keeping it in the pool.',
				redact_proxy_credentials(pv),
			)
			continue
		target = _normalize_proxy_pool_line(pv)
		if target:
			targets.append(target)
			
	if not targets:
		return False

	from django.db import transaction

	with _proxy_pool_lock:
		with transaction.atomic():
			if proxy_obj is None:
				locked_obj = Proxy.objects.select_for_update().first()
			else:
				locked_obj = Proxy.objects.select_for_update().filter(pk=proxy_obj.pk).first()

			if not locked_obj or not locked_obj.proxies:
				return False

			remaining_lines = []
			removed_count = 0
			for line in locked_obj.proxies.splitlines():
				stripped = line.strip()
				if not stripped:
					continue
				if _normalize_proxy_pool_line(stripped) in targets:
					removed_count += 1
					continue
				remaining_lines.append(stripped)

			if removed_count > 0:
				locked_obj.proxies = '\n'.join(remaining_lines)
				locked_obj.save(update_fields=['proxies'])
				logger.warning('Removed %d invalid proxies from pool', removed_count)
				return True
				
	return False


def get_random_user_agent():
	"""Return a user agent string respecting the OpSec random UA setting.

	If OpSec is enabled and enable_random_ua is True, returns a randomly chosen
	modern browser user agent from the curated pool. Otherwise returns the default
	Chrome UA to avoid fingerprinting as a scanner.

	Returns:
		str: A User-Agent header value string.
	"""
	try:
		from scanEngine.models import OpSec
		opsec = OpSec.objects.first()
		if opsec and opsec.enable_random_ua:
			return random.choice(_USER_AGENT_POOL)
	except Exception as e:
		logger.warning('get_random_user_agent: could not read OpSec settings: %s', e)
	return _DEFAULT_USER_AGENT


def get_random_proxy(http_only=False, socks5_only=False):
	"""Get a random proxy from the list stored in the database.

	Args:
		http_only: If True, skip TOR and return only http(s) entries.
		socks5_only: If True, return only socks5:// or socks5h:// entries
			(Reacher SMTP verify cannot use HTTP or SOCKS4).

	Enhancements over the old implementation:
	  - **Freshness short-circuit**: if the proxy list was batch-verified by
	    ``fetch_proxies_task`` within the configured TTL (default 120 min) it is
	    trusted directly and a random entry is returned without re-validation.
	    This prevents hundreds of milliseconds of blocking overhead on every tool
	    call during a scan.
	  - **Parallel re-validation**: when the list is stale, all candidate proxies
	    are checked concurrently (up to 50 workers) instead of sequentially.
	    The first live one wins; the rest are cancelled.
	  - **In-process failure cache**: proxies that fail during the current scan
	    session are recorded in ``_failed_proxy_cache`` and skipped on subsequent
	    calls, avoiding repeated timeouts against already-dead entries.
	  - **Transparent-proxy detection**: when the OpSec setting
	    ``enable_transparent_proxy_detection`` is True the server's own outbound IP
	    is detected once per call and passed to ``check_proxy_robust`` so that
	    transparent proxies are rejected.

	Returns:
		str: Proxy URL string, 'socks5://tor:9050' when TOR is enabled, or '' if
			 no valid proxy is available.
	"""
	from concurrent.futures import ThreadPoolExecutor, as_completed
	from datetime import timezone as _tz
	import datetime as _dt

	# ------------------------------------------------------------------
	# TOR mode: bypass all proxy logic and return the TOR SOCKS5 address
	# ------------------------------------------------------------------
	_proxy_obj = Proxy.objects.first()
	if _proxy_obj and _proxy_obj.use_tor and not http_only:
		return 'socks5://tor:9050'

	if not _proxy_obj or not _proxy_obj.use_proxy:
		return ''

	# Hand-entered proxies come first and are tried on their own before the
	# scraped pool is considered at all. The operator vouches for these, so a
	# working one should always win over a free entry of unknown quality.
	priority_raw = get_priority_proxies(_proxy_obj)
	raw_proxies = [p.strip() for p in (_proxy_obj.proxies or '').splitlines() if p.strip()]
	if not raw_proxies and not priority_raw:
		return ''

	def _normalise(lines):
		out = []
		for p in lines:
			if not p.startswith('http') and not p.startswith('socks'):
				p = f'http://{p}'
			out.append(p)
		return out

	priority_proxies = _normalise(priority_raw)
	proxies = _normalise(raw_proxies)

	if socks5_only:
		def _is_socks5(url):
			lower = url.lower()
			return lower.startswith('socks5://') or lower.startswith('socks5h://')
		priority_proxies = [p for p in priority_proxies if _is_socks5(p)]
		proxies = [p for p in proxies if _is_socks5(p)]
		if not priority_proxies and not proxies:
			return ''

	if priority_proxies:
		server_ip_pre = ''
		for candidate in priority_proxies:
			if check_proxy_robust(candidate, timeout=PROXY_VALIDATION_TIMEOUT, server_ip=server_ip_pre):
				logger.info(
					'Using priority proxy %s', redact_proxy_credentials(candidate)
				)
				return candidate
			logger.warning(
				'Priority proxy %s did not answer; it stays configured, trying the next.',
				redact_proxy_credentials(candidate),
			)
		if not proxies:
			logger.error('All priority proxies failed and no scraped pool is configured.')
			return ''
		logger.warning(
			'All %d priority proxies failed — falling back to the scraped pool.',
			len(priority_proxies),
		)

	if http_only:
		proxies = [p for p in proxies if p.lower().startswith('http')]

	# Remove entries that have already failed this session (within TTL)
	now_epoch = time.time()
	candidates = [
		p for p in proxies
		if p not in _failed_proxy_cache or (now_epoch - _failed_proxy_cache[p]) > _FAILED_PROXY_TTL
	]
	if not candidates:
		# All known proxies have failed – clear the cache and try again fresh
		logger.warning('All cached proxies failed this session. Clearing failure cache.')
		_failed_proxy_cache.clear()
		candidates = proxies

	# ------------------------------------------------------------------
	# Freshness handling — three tiers rather than one blind window.
	#
	# 1. Inside PROXY_TRUST_WINDOW_SECONDS the batch verification is recent
	#    enough to take on trust; this is the "fetch_proxies_task just
	#    finished" case and costs nothing.
	# 2. Past that but inside proxy_ttl_minutes, the pool is still not
	#    re-validated wholesale, but the proxy about to be handed out is
	#    checked. Previously an unchecked entry was returned for the entire
	#    TTL, two hours by default, so a free proxy that died five minutes
	#    after the batch run kept being fed into scans as if it were good.
	# 3. Past the TTL, the existing full parallel re-validation runs.
	# ------------------------------------------------------------------
	ttl_minutes = getattr(_proxy_obj, 'proxy_ttl_minutes', 120) or 120
	verified_at = getattr(_proxy_obj, 'proxies_verified_at', None)
	within_ttl = False
	age_minutes = 0.0
	if verified_at is not None:
		now_utc = _dt.datetime.now(_tz.utc)
		age_seconds = (now_utc - verified_at).total_seconds()
		age_minutes = age_seconds / 60
		within_ttl = age_minutes <= ttl_minutes
		if age_seconds <= PROXY_TRUST_WINDOW_SECONDS:
			chosen = random.choice(candidates)
			mark_proxy_used(chosen)
			logger.info(
				'Proxy list was verified %.0fs ago (trust window %ds). '
				'Returning %s unchecked.',
				age_seconds, PROXY_TRUST_WINDOW_SECONDS,
				redact_proxy_credentials(chosen),
			)
			return chosen
		if not within_ttl:
			logger.info(
				'Proxy list is stale (%.1f min old, TTL %d min). '
				'Falling back to parallel re-validation.',
				age_minutes, ttl_minutes,
			)
	else:
		logger.info('No proxies_verified_at timestamp found. Performing parallel re-validation.')

	# ------------------------------------------------------------------
	# Optional transparent-proxy detection (opt-in via OpSec setting).
	# Needed by both the sampled check below and the full re-validation.
	# ------------------------------------------------------------------
	server_ip = ''
	try:
		from scanEngine.models import OpSec as _OpSec
		_opsec = _OpSec.objects.first()
		if _opsec and getattr(_opsec, 'enable_transparent_proxy_detection', False):
			server_ip = _detect_server_ip(timeout=5)
			if server_ip:
				logger.info('Transparent proxy detection enabled. Server IP: %s', server_ip)
	except Exception as _e:
		logger.warning('Could not read OpSec settings for transparent proxy detection: %s', _e)

	# ------------------------------------------------------------------
	# Sampled verification — the cheap middle tier inside the TTL.
	# At most PROXY_SAMPLE_ATTEMPTS checks instead of re-validating the pool.
	# ------------------------------------------------------------------
	if within_ttl:
		sample = random.sample(
			candidates, min(PROXY_SAMPLE_ATTEMPTS, len(candidates))
		)
		for candidate in sample:
			if check_proxy_robust(
				candidate, timeout=PROXY_VALIDATION_TIMEOUT, server_ip=server_ip
			):
				# Same bookkeeping as the other two tiers, so a proxy verified
				# here also earns the 24-hour removal protection.
				mark_proxy_used(candidate)
				logger.info(
					'Proxy list is %.1f min old; verified %s before handing it out.',
					age_minutes, redact_proxy_credentials(candidate),
				)
				return candidate
			_failed_proxy_cache[candidate] = time.time()
			if remove_proxy_from_pool(candidate, _proxy_obj):
				logger.warning(
					'Removed invalid proxy from pool: %s',
					redact_proxy_credentials(candidate),
				)
		logger.warning(
			'None of the %d sampled proxies answered; re-validating the whole pool.',
			len(sample),
		)

	# ------------------------------------------------------------------
	# Parallel re-validation – first live proxy wins
	# ------------------------------------------------------------------
	random.shuffle(candidates)
	# Cap workers to avoid spawning thousands of threads for a huge list
	max_workers = min(50, len(candidates))

	result_holder = [None]  # thread-safe single-slot via GIL

	def _check(proxy_url):
		"""Check a single proxy; mark it failed on the cache."""
		if check_proxy_robust(proxy_url, timeout=PROXY_VALIDATION_TIMEOUT, server_ip=server_ip):
			return proxy_url
		_failed_proxy_cache[proxy_url] = time.time()
		# Pool removal is batched below via remove_proxies_from_pool().
		return None

	with ThreadPoolExecutor(max_workers=max_workers) as pool:
		future_map = {pool.submit(_check, p): p for p in candidates}
		dead_proxies = []
		for fut in as_completed(future_map):
			try:
				live = fut.result()
			except Exception:
				live = None
			if live:
				result_holder[0] = live
				# Cancel remaining futures to stop wasting resources
				for other in future_map:
					if other is not fut:
						other.cancel()
				break
			else:
				dead_proxies.append(future_map[fut])
				
	if dead_proxies:
		remove_proxies_from_pool(dead_proxies, _proxy_obj)

	if result_holder[0]:
		mark_proxy_used(result_holder[0])
		logger.info(
			'Using valid proxy (parallel validation): %s',
			redact_proxy_credentials(result_holder[0]),
		)
		return result_holder[0]

	logger.error('No valid proxies found after parallel re-validation!')
	return ''


def get_proxy_list():
	"""Get a list of all proxies input by the user in the UI.
	Does not validate if they are alive.
	
	Returns:
		list: List of proxy names or [] if no proxy defined or use_proxy is False,
			  or if use_tor is True (since Tor uses proxychains).
	"""
	proxy = Proxy.objects.first()
	if not proxy or not proxy.use_proxy or proxy.use_tor:
		return []

	# Hand-entered proxies lead the file. Tools that read it top-down therefore
	# reach for the vouched-for entries before anything scraped.
	priority = get_priority_proxies(proxy)
	proxies = priority + [
		p.strip() for p in (proxy.proxies or '').splitlines() if p.strip()
	]
	cleaned_proxies = []
	seen = set()
	for p in proxies:
		if not p.startswith('http') and not p.startswith('socks'):
			p = f"http://{p}"
		if p in seen:
			continue
		seen.add(p)
		cleaned_proxies.append(p)

	return cleaned_proxies
