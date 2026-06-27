import hashlib
import logging
import os
import base64
import json
import threading
from urllib.parse import urlparse
from django.utils import timezone
from redis import Redis
from django.conf import settings

from reNgine.definitions import (
	DIR_FILE_FUZZ,
	ENABLE_HTTP_CRAWL,
	RATE_LIMIT,
	EXTENSIONS,
	DEFAULT_DIR_FILE_FUZZ_EXTENSIONS,
	FOLLOW_REDIRECT,
	MAX_TIME,
	MATCH_HTTP_STATUS,
	FFUF_DEFAULT_MATCH_HTTP_STATUS,
	RECURSIVE_LEVEL,
	FFUF_DEFAULT_RECURSIVE_LEVEL,
	STOP_ON_ERROR,
	TIMEOUT,
	THREADS,
	WORDLIST,
	AUTO_CALIBRATION,
	DELAY,
	CUSTOM_HEADERS,
	CUSTOM_HEADER,
	FFUF_DEFAULT_WORDLIST_PATH,
	RUN_DIRSEARCH,
	RUN_FEROXBUSTER,
)
from reNgine.settings import (
	DEFAULT_ENABLE_HTTP_CRAWL,
	DEFAULT_RATE_LIMIT,
	DEFAULT_HTTP_TIMEOUT,
	DEFAULT_THREADS
)
from reNgine.utils.opsec import OpSecManager, get_opsec_manager
from reNgine.common_func import get_http_urls, get_subdomain_from_url, extract_path_from_url, get_random_proxy, sanitize_url
from reNgine.utils.task import (
	run_command,
	stream_command,
	ensure_endpoints_crawled_and_execute,
	parse_custom_header_to_list,
	bulk_persist_fetch_urls,
	bulk_get_or_create_directory_files,
	activity_heartbeat_safe,
)
from startScan.models import DirectoryScan, Subdomain, EndPoint, ScanHistory

logger = logging.getLogger(__name__)

_FUZZ_BATCH_SIZE = 100


def _fuzz_target_marker(results_dir, target_url):
	digest = hashlib.md5(target_url.encode('utf-8')).hexdigest()
	return os.path.join(results_dir, f'fuzz_done_{digest}.marker')


def filter_fuzz_batch_with_redis(batch, scan_history_id, subdomain_id, max_repeat, tool_name):
	"""Filters out duplicate fuzzing responses based on response signatures using Redis."""
	if not batch or max_repeat <= 0:
		return batch

	redis_url = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
	try:
		redis_client = Redis.from_url(redis_url)
		pipeline = redis_client.pipeline()
		
		# Build the signature keys and queue INCR and EXPIRE operations
		keys = []
		for item in batch:
			status = item.get('status') or item.get('http_status') or 0
			length = item.get('length') or item.get('content_length') or item.get('content-length') or 0
			words = item.get('words') or item.get('word_count') or 0
			lines = item.get('lines') or item.get('line_count') or 0
			
			sig_key = f"fuzz:sig:{scan_history_id}:{subdomain_id}:{status}:{length}:{words}:{lines}"
			keys.append(sig_key)
			pipeline.incr(sig_key)
			pipeline.expire(sig_key, 86400)  # 24 hour TTL

		results = pipeline.execute()
		filtered_batch = []
		
		# Pipeline returns [INCR_result1, EXPIRE_result1, INCR_result2, EXPIRE_result2, ...]
		for i, item in enumerate(batch):
			incr_val = results[i * 2]
			if incr_val <= max_repeat:
				filtered_batch.append(item)
				
		return filtered_batch
	except Exception as e:
		logger.warning('Redis signature filtering failed for %s batch (fail-open): %s', tool_name, e)
		return batch




def _flush_ffuf_batch(batch, dirscan, ctx, scan, subdomain_id=0, max_repeat=10):
	"""Persist a batch of ffuf JSON result dicts with batched DB writes."""
	if not batch or not scan:
		return

	batch = filter_fuzz_batch_with_redis(
		batch,
		scan.id,
		subdomain_id,
		max_repeat,
		tool_name='ffuf'
	)

	if not batch:
		return

	rows = []
	urls = []
	for line in batch:
		res_url = line.get('url')
		if not res_url:
			continue
		name = base64.b64encode(extract_path_from_url(res_url).encode()).decode()
		if not name:
			continue
		http_url = sanitize_url(res_url)
		urls.append(http_url)
		rows.append({
			'line': line,
			'name': name,
			'url': res_url,
			'http_url': http_url,
		})

	if not urls:
		return

	bulk_persist_fetch_urls(urls, ctx, batch_size=len(urls))
	endpoints = {
		ep.http_url: ep
		for ep in EndPoint.objects.filter(scan_history=scan, http_url__in=urls)
	}

	ep_updates = []
	dfile_candidates = []
	for row in rows:
		line = row['line']
		ep = endpoints.get(row['http_url'])
		if not ep:
			continue
		status = line.get('status', 0)
		length = line.get('length', 0)
		words = line.get('words', 0)
		lines_count = line.get('lines', 0)
		content_type = line.get('content-type', '')
		duration = line.get('duration', 0)
		ep.http_status = status
		ep.content_length = length
		ep.response_time = duration / 1000000000 if duration else ep.response_time
		ep.content_type = content_type
		ep_updates.append(ep)
		dfile_candidates.append({
			'name': row['name'],
			'url': row['url'],
			'http_status': status,
			'length': length,
			'words': words,
			'lines': lines_count,
			'content_type': content_type,
		})

	if ep_updates:
		EndPoint.objects.bulk_update(
			ep_updates,
			['http_status', 'content_length', 'response_time', 'content_type'],
			batch_size=_FUZZ_BATCH_SIZE,
		)

	dfiles = bulk_get_or_create_directory_files(dfile_candidates)
	if dfiles:
		dirscan.directory_files.add(*dfiles)


def _flush_ds_batch(batch, dirscan_ds, ctx, scan, subdomain_id=0, max_repeat=10):
	"""Persist a batch of dirsearch result dicts with batched DB writes."""
	if not batch or not scan:
		return

	batch = filter_fuzz_batch_with_redis(
		batch,
		scan.id,
		subdomain_id,
		max_repeat,
		tool_name='dirsearch'
	)

	if not batch:
		return

	rows = []
	urls = []
	for ds_res in batch:
		res_url = ds_res.get('url')
		if not res_url:
			continue
		name = base64.b64encode(extract_path_from_url(res_url).encode()).decode()
		if not name:
			continue
		http_url = sanitize_url(res_url)
		urls.append(http_url)
		rows.append({
			'ds_res': ds_res,
			'name': name,
			'url': res_url,
			'http_url': http_url,
		})

	if not urls:
		return

	bulk_persist_fetch_urls(urls, ctx, batch_size=len(urls))
	endpoints = {
		ep.http_url: ep
		for ep in EndPoint.objects.filter(scan_history=scan, http_url__in=urls)
	}

	ep_updates = []
	dfile_candidates = []
	for row in rows:
		ds_res = row['ds_res']
		ep = endpoints.get(row['http_url'])
		if not ep:
			continue
		status = ds_res.get('status', 0)
		length = ds_res.get('content-length', 0)
		content_type = ds_res.get('content-type', '')
		ep.http_status = status
		ep.content_length = length
		ep.content_type = content_type
		ep_updates.append(ep)
		dfile_candidates.append({
			'name': row['name'],
			'url': row['url'],
			'http_status': status,
			'length': length,
			'content_type': content_type,
		})

	if ep_updates:
		EndPoint.objects.bulk_update(
			ep_updates,
			['http_status', 'content_length', 'content_type'],
			batch_size=_FUZZ_BATCH_SIZE,
		)

	dfiles = bulk_get_or_create_directory_files(dfile_candidates)
	if dfiles:
		dirscan_ds.directory_files.add(*dfiles)


def _flush_ferox_batch(batch, dirscan, ctx, scan, subdomain_id=0, max_repeat=10):
	"""Persist a batch of feroxbuster NDJSON result dicts with batched DB writes."""
	if not batch or not scan:
		return

	batch = filter_fuzz_batch_with_redis(
		batch,
		scan.id,
		subdomain_id,
		max_repeat,
		tool_name='feroxbuster'
	)

	if not batch:
		return

	rows = []
	urls = []
	for entry in batch:
		if entry.get('type') != 'response':
			continue
		res_url = entry.get('url')
		if not res_url:
			continue
		name = base64.b64encode(extract_path_from_url(res_url).encode()).decode()
		if not name:
			continue
		http_url = sanitize_url(res_url)
		urls.append(http_url)
		rows.append({
			'entry': entry,
			'name': name,
			'url': res_url,
			'http_url': http_url,
		})

	if not urls:
		return

	bulk_persist_fetch_urls(urls, ctx, batch_size=len(urls))
	endpoints = {
		ep.http_url: ep
		for ep in EndPoint.objects.filter(scan_history=scan, http_url__in=urls)
	}

	ep_updates = []
	dfile_candidates = []
	for row in rows:
		entry = row['entry']
		ep = endpoints.get(row['http_url'])
		if not ep:
			continue
		status = entry.get('status', 0)
		length = entry.get('content_length', 0)
		words = entry.get('word_count', 0)
		lines_count = entry.get('line_count', 0)
		content_type = entry.get('content_type', '')
		ep.http_status = status
		ep.content_length = length
		ep.content_type = content_type
		ep_updates.append(ep)
		dfile_candidates.append({
			'name': row['name'],
			'url': row['url'],
			'http_status': status,
			'length': length,
			'words': words,
			'lines': lines_count,
			'content_type': content_type,
		})

	if ep_updates:
		EndPoint.objects.bulk_update(
			ep_updates,
			['http_status', 'content_length', 'content_type'],
			batch_size=_FUZZ_BATCH_SIZE,
		)

	dfiles = bulk_get_or_create_directory_files(dfile_candidates)
	if dfiles:
		dirscan.directory_files.add(*dfiles)


def dir_file_fuzz(self, ctx=None, description=None, prepare_only=False, parse_only=None):
	"""Perform directory and file fuzzing using FFUF and Dirsearch.

	This wrapper ensures that any endpoints are crawled first by delegating to
	ensure_endpoints_crawled_and_execute.

	Args:
		ctx (dict, optional): Task context containing scan information.
		description (str, optional): Task description shown in UI.

	Returns:
		list: List of URLs/lines discovered during fuzzing.
	"""
	if ctx is None:
		ctx = {}

	def _execute_dir_file_fuzz(ctx, description, prepare_only=False, parse_only=None):
		"""Inner execution logic for FFUF and Dirsearch fuzzing."""
		from scanEngine.models import Wordlist
		from reNgine.tasks import http_crawl

		config = self.yaml_configuration.get(DIR_FILE_FUZZ) or {}
		max_repeat = config.get('max_repeat_by_signature', 10)
		enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
		rate_limit = config.get(RATE_LIMIT) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT)
		extensions = config.get(EXTENSIONS, DEFAULT_DIR_FILE_FUZZ_EXTENSIONS)

		extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
		extensions_str = ','.join(map(str, extensions))
		follow_redirect = config.get(FOLLOW_REDIRECT, False)
		max_time = config.get(MAX_TIME, 0)
		match_http_status = config.get(MATCH_HTTP_STATUS, FFUF_DEFAULT_MATCH_HTTP_STATUS)
		mc = ','.join(str(status) for status in match_http_status) if match_http_status else ''
		recursive_level = config.get(RECURSIVE_LEVEL, FFUF_DEFAULT_RECURSIVE_LEVEL)
		stop_on_error = config.get(STOP_ON_ERROR, False)
		timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
		threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
		wordlist_name = config.get(WORDLIST, 'dicc')
		auto_calibration = config.get(AUTO_CALIBRATION, True)
		delay = rate_limit / (threads * 100) if threads else 0
		custom_headers = config.get(CUSTOM_HEADERS) or config.get(CUSTOM_HEADER) or []
		run_dirsearch = config.get(RUN_DIRSEARCH, True)
		run_feroxbuster = config.get(RUN_FEROXBUSTER, False)

		custom_headers_list = parse_custom_header_to_list(custom_headers)

		wordlist_path = f'/usr/src/wordlist/{wordlist_name}.txt'
		if not os.path.exists(wordlist_path):
			db_wl = Wordlist.objects.filter(short_name=wordlist_name).first()
			if db_wl:
				wordlist_path = f'/usr/src/wordlist/{db_wl.short_name}.txt'
			else:
				wordlist_path = FFUF_DEFAULT_WORDLIST_PATH

		from reNgine.tasks.api import resolve_wordlist_path
		wordlist_path = resolve_wordlist_path(config, wordlist_path)

		input_path = f'{self.results_dir}/input_endpoints_dir_file_fuzz.txt'

		ffuf_base_cmd = 'ffuf'
		ffuf_base_cmd += f' -w {wordlist_path}'
		ffuf_base_cmd += f' -e {extensions_str}' if extensions else ''
		ffuf_base_cmd += f' -maxtime {max_time}' if max_time > 0 else ''
		ffuf_base_cmd += f' -rate {rate_limit}' if rate_limit > 0 else ''
		if recursive_level > 0:
			ffuf_base_cmd += f' -recursion -recursion-depth {recursive_level}'
			if max_time > 0:
				job_time = max(30, max_time // (recursive_level + 1))
				ffuf_base_cmd += f' -maxtime-job {job_time}'
		ffuf_base_cmd += f' -t {threads}' if threads and threads > 0 else ''
		ffuf_base_cmd += f' -timeout {timeout}' if timeout and timeout > 0 else ''
		ffuf_base_cmd += ' -se' if stop_on_error else ''
		ffuf_base_cmd += ' -r' if follow_redirect else ''
		ffuf_base_cmd += ' -ac' if auto_calibration else ''
		if not auto_calibration and mc:
			ffuf_base_cmd += f' -mc {mc}'

		has_ua = any('user-agent' in h.lower() for h in custom_headers_list)
		if not has_ua:
			ffuf_base_cmd += " -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'"

		for header in custom_headers_list:
			ffuf_base_cmd += f" -H '{header}'"
			if 'cookie' in header.lower() or 'authorization' in header.lower():
				logger.warning('Authenticated FFUF fuzzing enabled via header: %s', header)

		dirsearch_base_cmd = None
		if run_dirsearch:
			dirsearch_base_cmd = 'dirsearch'
			dirsearch_base_cmd += f' -w {wordlist_path}'
			dirsearch_base_cmd += f' -e {extensions_str.replace(".", "")}' if extensions else ''
			dirsearch_base_cmd += f' -t {threads}' if threads and threads > 0 else ''
			dirsearch_base_cmd += f' --timeout {timeout}' if timeout and timeout > 0 else ''
			dirsearch_base_cmd += f' -r' if recursive_level > 0 else ''
			dirsearch_base_cmd += f' --max-recursion-depth {recursive_level}' if recursive_level > 0 else ''
			dirsearch_base_cmd += f' -i {mc}' if mc else ''
			dirsearch_base_cmd += ' --follow-redirects' if follow_redirect else ''
			dirsearch_base_cmd += f' --max-time {max_time}' if max_time > 0 else ''
			dirsearch_base_cmd += f' --delay {delay}' if delay > 0 else ''
			dirsearch_base_cmd += ' --exit-on-error' if stop_on_error else ''

			if not has_ua:
				dirsearch_base_cmd += ' --random-agent'

			for header in custom_headers_list:
				dirsearch_base_cmd += f' -H "{header}"'
				if 'cookie' in header.lower() or 'authorization' in header.lower():
					logger.warning('Authenticated Dirsearch fuzzing enabled via header: %s', header)
		else:
			logger.info('Dirsearch disabled via run_dirsearch config key. Only ffuf will run.')

		ferox_base_cmd = None
		if run_feroxbuster:
			ferox_base_cmd = 'feroxbuster --no-state --silent --json'
			ferox_base_cmd += f' --wordlist {wordlist_path}'
			if extensions:
				ferox_base_cmd += f' --extensions {extensions_str}'
			if threads and threads > 0:
				ferox_base_cmd += f' --threads {threads}'
			if rate_limit and rate_limit > 0:
				ferox_base_cmd += f' --rate-limit {rate_limit}'
			if timeout and timeout > 0:
				ferox_base_cmd += f' --timeout {timeout}'
			if recursive_level > 0:
				ferox_base_cmd += f' --depth {recursive_level}'
			else:
				ferox_base_cmd += ' --no-recursion'
			if follow_redirect:
				ferox_base_cmd += ' --follow-redirects'
			if auto_calibration:
				ferox_base_cmd += ' --auto-calibration'
			for header in custom_headers_list:
				ferox_base_cmd += f" -H '{header}'"

		if ctx.get("urls_override"):
			urls = ctx["urls_override"]
		else:
			raw_urls = get_http_urls(
				is_alive=True,
				ignore_files=False,
				write_filepath=input_path,
				get_only_default_urls=False,
				ctx=ctx
			)
			if not raw_urls:
				logger.error('No alive URLs found for directory fuzzing. Skipping.')
				return []

			base_url_map = {}
			for u in raw_urls:
				parsed = urlparse(u)
				base = f"{parsed.scheme}://{parsed.netloc}"
				if base not in base_url_map:
					base_url_map[base] = set()

				path = parsed.path
				if path and '.' in path.split('/')[-1]:
					path = '/'.join(path.split('/')[:-1])
				if not path.endswith('/'):
					path += '/'

				segments = [s for s in path.strip('/').split('/') if s]
				if len(segments) <= 2:
					base_url_map[base].add(path)

			urls = []
			for base, paths in base_url_map.items():
				for path in list(paths)[:10]:
					urls.append(f"{base}{path}")

		logger.warning('Fuzzing URLs: %s', urls)

		if prepare_only:
			return {
				"urls": urls,
				"ffuf_base_cmd": ffuf_base_cmd,
				"dirsearch_base_cmd": dirsearch_base_cmd,
				"ferox_base_cmd": ferox_base_cmd,
				"enable_http_crawl": enable_http_crawl,
			}

		results = []
		redis_client = Redis.from_url(os.environ.get('REDIS_URL', 'redis://redis:6379/0'))
		opsec = get_opsec_manager()
		scan = ScanHistory.objects.filter(pk=ctx.get('scan_history_id')).first()

		for target_url in urls:
			done_marker = _fuzz_target_marker(self.results_dir, target_url)
			if parse_only is None and os.path.exists(done_marker):
				logger.info('Skipping already-fuzzed target (marker present): %s', target_url)
				continue

			logger.warning('Fuzzing URL: %s', target_url)
			url_parse = urlparse(target_url)
			base_url = url_parse.scheme + '://' + url_parse.netloc
			subdomain_name = get_subdomain_from_url(base_url)
			subdomain = Subdomain.objects.filter(name=subdomain_name, scan_history=self.scan).first()
			if not subdomain and ctx.get('subdomain_id', 0) > 0:
				subdomain = Subdomain.objects.filter(id=ctx['subdomain_id']).first()

			proxy = get_random_proxy()
			if proxy:
				if not any(proxy.startswith(s) for s in ['http://', 'https://', 'socks4://', 'socks5://']):
					proxy = 'http://' + proxy

			lock_key = f"fuzz_execution_lock_{self.scan_id}_{hashlib.md5(target_url.encode()).hexdigest()}"
			with redis_client.lock(lock_key, timeout=1800):
				ffuf_results_local = []
				ffuf_exc = [None]
				ds_exc = [None]

				def _run_ffuf():
					try:
						_fuzz_url = target_url if target_url.endswith('/') else target_url + '/'
						fcmd = ffuf_base_cmd + f' -u {_fuzz_url}FUZZ -json'
						
						ffuf_proxy = proxy
						if ffuf_proxy and ffuf_proxy.startswith('socks4'):
							for _ in range(25):
								new_proxy = get_random_proxy()
								if not new_proxy:
									ffuf_proxy = None
									break
								if not new_proxy.startswith('http') and not new_proxy.startswith('socks'):
									new_proxy = 'http://' + new_proxy
								if new_proxy.startswith('http') or new_proxy.startswith('socks5'):
									ffuf_proxy = new_proxy
									break
							else:
								ffuf_proxy = None
								logger.warning('ffuf proxy requirement: failed to find an http/s or socks5 proxy after 25 retries (socks4 not supported), bypassing proxy for ffuf')
							
						fcmd += f' -x {ffuf_proxy}' if ffuf_proxy else ''
						fcmd = opsec.apply_stealth('ffuf', fcmd, proxy=ffuf_proxy)

						dirscan = DirectoryScan.objects.create(
							scanned_date=timezone.now(),
							command_line=fcmd
						)
						if subdomain:
							subdomain.directories.add(dirscan)

						logger.info('Running ffuf for %s', base_url)
						logger.warning('ffuf command: %s', fcmd)

						batch = []
						if parse_only is not None and target_url in parse_only.get('ffuf', {}):
							ffuf_stdout = parse_only['ffuf'][target_url]
							for raw_line in ffuf_stdout.splitlines():
								raw_line = raw_line.strip()
								if not raw_line:
									continue
								try:
									parsed = json.loads(raw_line)
									batch.append(parsed)
									ffuf_results_local.append(parsed)
								except Exception:
									pass
								if len(batch) >= _FUZZ_BATCH_SIZE:
									subdomain_id = subdomain.id if subdomain else 0
									_flush_ffuf_batch(batch, dirscan, ctx, scan, subdomain_id=subdomain_id, max_repeat=max_repeat)
									batch = []
						else:
							for line in stream_command(
									fcmd,
									shell=True,
									history_file=self.history_file,
									scan_id=self.scan_id,
									activity_id=self.activity_id,
									route_to_executor=True):
								if not isinstance(line, dict):
									continue
								batch.append(line)
								ffuf_results_local.append(line)
								if len(batch) >= _FUZZ_BATCH_SIZE:
									subdomain_id = subdomain.id if subdomain else 0
									_flush_ffuf_batch(batch, dirscan, ctx, scan, subdomain_id=subdomain_id, max_repeat=max_repeat)
									batch = []
									activity_heartbeat_safe(f'ffuf {target_url} {len(ffuf_results_local)} hits')

						subdomain_id = subdomain.id if subdomain else 0
						_flush_ffuf_batch(batch, dirscan, ctx, scan, subdomain_id=subdomain_id, max_repeat=max_repeat)

						if self.subscan:
							from startScan.models import SubScan
							if SubScan.objects.filter(pk=self.subscan.pk).exists():
								dirscan.dir_subscan_ids.add(self.subscan)
						dirscan.save()
					except Exception as e:
						ffuf_exc[0] = e

				def _run_dirsearch():
					try:
						if not run_dirsearch or not dirsearch_base_cmd:
							return
						dirsearch_output = f'{self.results_dir}/dirsearch_{subdomain_name}.json'
						target_url_stripped = target_url.rstrip('/')

						def _build_dcmd(p):
							cmd = f'{dirsearch_base_cmd} -u {target_url_stripped} --format=json -o {dirsearch_output} --no-color'
							if p:
								cmd += f' --proxy {p}'
							return opsec.apply_stealth('dirsearch', cmd, proxy=p)

						current_proxy = proxy
						dcmd = _build_dcmd(current_proxy)

						dirscan_ds = DirectoryScan.objects.create(
							scanned_date=timezone.now(),
							command_line=dcmd
						)
						if subdomain:
							subdomain.directories.add(dirscan_ds)

						logger.info('Running dirsearch for %s', target_url)
						logger.warning('dirsearch command: %s', dcmd)

						if parse_only is None:
							_PROXY_ERROR = 'Error with the proxy:'
							_max_proxy_retries = 2
							_attempt = 0
							while True:
								_, ds_output = run_command(
									dcmd,
									shell=True,
									history_file=self.history_file,
									scan_id=self.scan_id,
									activity_id=self.activity_id
								)
								if _PROXY_ERROR not in ds_output:
									break
								if _attempt < _max_proxy_retries:
									_attempt += 1
									current_proxy = get_random_proxy()
									if current_proxy and not any(
										current_proxy.startswith(s)
										for s in ['http://', 'https://', 'socks4://', 'socks5://']
									):
										current_proxy = 'http://' + current_proxy
									logger.warning(
										'dirsearch proxy error (attempt %d/%d), retrying with new proxy',
										_attempt, _max_proxy_retries
									)
									dcmd = _build_dcmd(current_proxy)
									dirscan_ds.command_line = dcmd
									dirscan_ds.save()
								else:
									logger.warning(
										'dirsearch proxy error after %d retries, retrying without proxy',
										_max_proxy_retries
									)
									dcmd = _build_dcmd(None)
									dirscan_ds.command_line = dcmd
									dirscan_ds.save()
									run_command(
										dcmd,
										shell=True,
										history_file=self.history_file,
										scan_id=self.scan_id,
										activity_id=self.activity_id
									)
									break

						if os.path.exists(dirsearch_output):
							try:
								with open(dirsearch_output, 'r') as f:
									results_list = json.load(f).get('results', [])
								logger.info('dirsearch collected %d results for %s', len(results_list), target_url)
								for i in range(0, len(results_list), _FUZZ_BATCH_SIZE):
									subdomain_id = subdomain.id if subdomain else 0
									_flush_ds_batch(
										results_list[i:i + _FUZZ_BATCH_SIZE],
										dirscan_ds,
										ctx,
										scan,
										subdomain_id=subdomain_id,
										max_repeat=max_repeat,
									)
							except Exception as e:
								logger.error('Error parsing dirsearch output for %s: %s', base_url, e)

						if self.subscan:
							from startScan.models import SubScan
							if SubScan.objects.filter(pk=self.subscan.pk).exists():
								dirscan_ds.dir_subscan_ids.add(self.subscan)
						dirscan_ds.save()
					except Exception as e:
						ds_exc[0] = e

				def _run_feroxbuster():
					if not run_feroxbuster or not ferox_base_cmd:
						return
					ferox_output = f'{self.results_dir}/feroxbuster_{hashlib.md5(target_url.encode()).hexdigest()[:8]}.json'
					fcmd = f'{ferox_base_cmd} --url {target_url} --output {ferox_output}'
					ferox_proxy = proxy
					if ferox_proxy:
						if ferox_proxy.startswith('socks'):
							ferox_proxy = None
						else:
							fcmd += f' --proxy {ferox_proxy}'

					dirscan_ferox = DirectoryScan.objects.create(
						scanned_date=timezone.now(),
						command_line=fcmd,
					)
					if subdomain:
						subdomain.directories.add(dirscan_ferox)

					logger.info('Running feroxbuster for %s', target_url)
					logger.warning('feroxbuster command: %s', fcmd)

					ferox_batch = []
					if parse_only is not None and target_url in parse_only.get('ferox', {}):
						for raw_line in parse_only['ferox'][target_url].splitlines():
							raw_line = raw_line.strip()
							if not raw_line:
								continue
							try:
								entry = json.loads(raw_line)
								if entry.get('type') == 'response':
									ferox_batch.append(entry)
							except Exception:
								pass
						subdomain_id = subdomain.id if subdomain else 0
						_flush_ferox_batch(ferox_batch, dirscan_ferox, ctx, scan, subdomain_id=subdomain_id, max_repeat=max_repeat)
					else:
						run_command(
							fcmd,
							shell=True,
							history_file=self.history_file,
							scan_id=self.scan_id,
							activity_id=self.activity_id,
						)
						if os.path.exists(ferox_output):
							try:
								ferox_total = 0
								with open(ferox_output, 'r') as f:
									for raw_line in f:
										raw_line = raw_line.strip()
										if not raw_line:
											continue
										try:
											entry = json.loads(raw_line)
											if entry.get('type') == 'response':
												ferox_batch.append(entry)
												ferox_total += 1
												if len(ferox_batch) >= _FUZZ_BATCH_SIZE:
													subdomain_id = subdomain.id if subdomain else 0
													_flush_ferox_batch(ferox_batch, dirscan_ferox, ctx, scan, subdomain_id=subdomain_id, max_repeat=max_repeat)
													activity_heartbeat_safe(f'feroxbuster {target_url} {ferox_total} hits')
													ferox_batch = []
										except Exception:
											pass
								if ferox_batch:
									subdomain_id = subdomain.id if subdomain else 0
									_flush_ferox_batch(ferox_batch, dirscan_ferox, ctx, scan, subdomain_id=subdomain_id, max_repeat=max_repeat)
								logger.info('feroxbuster collected %d results for %s', ferox_total, target_url)
							except Exception as e:
								logger.error('Error parsing feroxbuster output for %s: %s', target_url, e)
							finally:
								try:
									os.remove(ferox_output)
								except FileNotFoundError:
									pass
						else:
							logger.warning('feroxbuster output file not found for %s', target_url)

					if self.subscan:
						from startScan.models import SubScan
						if SubScan.objects.filter(pk=self.subscan.pk).exists():
							dirscan_ferox.dir_subscan_ids.add(self.subscan)
					dirscan_ferox.save()

				# Run ffuf first
				logger.info('Starting sequential execution: ffuf first, then dirsearch for %s', target_url)
				_run_ffuf()

				if ffuf_exc[0]:
					raise ffuf_exc[0]

				# Run dirsearch after ffuf completes
				if run_dirsearch and dirsearch_base_cmd:
					_run_dirsearch()

				if ds_exc[0]:
					logger.error('dirsearch failed for %s: %s', target_url, ds_exc[0])

				if run_feroxbuster and ferox_base_cmd:
					_run_feroxbuster()

				results.extend(ffuf_results_local)

			if parse_only is None:
				with open(done_marker, 'w', encoding='utf-8') as marker:
					marker.write('ok')

		if enable_http_crawl:
			ctx['track'] = True
			http_crawl(self, urls, ctx=ctx)

		return results

	return ensure_endpoints_crawled_and_execute(
		self,
		lambda ctx, description: _execute_dir_file_fuzz(ctx, description, prepare_only=prepare_only, parse_only=parse_only),
		ctx,
		description
	)