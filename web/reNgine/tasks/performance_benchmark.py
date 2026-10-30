"""Lighthouse performance benchmarking for alive HTTP assets."""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from reNgine.definitions import (
	PERFORMANCE_BENCHMARK,
	PERFORMANCE_BENCHMARK_DEFAULT_MAX_URLS,
	PERFORMANCE_BENCHMARK_DEFAULT_TIMEOUT,
	PERFORMANCE_BENCHMARK_HARD_MAX_TIMEOUT,
	PERFORMANCE_BENCHMARK_HARD_MAX_URLS,
	PERFORMANCE_BENCHMARK_MAX_URLS,
	TIMEOUT,
)
from startScan.models import EndPoint, PerformanceBenchmark

logger = logging.getLogger(__name__)

CHROMIUM_PATH = os.environ.get('LIGHTHOUSE_CHROME_PATH', '/usr/bin/chromium')
LIGHTHOUSE_BIN = os.environ.get('LIGHTHOUSE_BIN', 'lighthouse')

_AUDIT_METRIC_MAP = {
	'first-contentful-paint': 'fcp_ms',
	'largest-contentful-paint': 'lcp_ms',
	'total-blocking-time': 'tbt_ms',
	'cumulative-layout-shift': 'cls',
	'speed-index': 'speed_index_ms',
	'interactive': 'tti_ms',
	'server-response-time': 'ttfb_ms',
}

_CATEGORY_SCORE_MAP = {
	'performance': 'performance_score',
	'accessibility': 'accessibility_score',
	'best-practices': 'best_practices_score',
	'seo': 'seo_score',
}


def _score_to_100(value):
	"""Convert Lighthouse 0-1 category score to 0-100, or None."""
	if value is None:
		return None
	try:
		return round(float(value) * 100, 1)
	except (TypeError, ValueError):
		return None


def _audit_numeric(audits, audit_id):
	audit = audits.get(audit_id) or {}
	value = audit.get('numericValue')
	if value is None:
		return None
	try:
		return float(value)
	except (TypeError, ValueError):
		return None


def parse_lighthouse_json(payload):
	"""Extract denormalized metrics and a trimmed summary from Lighthouse JSON.

	Args:
		payload (dict): Parsed Lighthouse report JSON.

	Returns:
		dict: Fields suitable for PerformanceBenchmark kwargs (without FKs).
	"""
	if not isinstance(payload, dict):
		return {'raw_json': {}, 'error': 'Invalid Lighthouse payload'}

	categories = payload.get('categories') or {}
	audits = payload.get('audits') or {}

	fields = {
		'raw_json': {
			'categories': {
				key: {
					'score': (categories.get(key) or {}).get('score'),
					'title': (categories.get(key) or {}).get('title'),
				}
				for key in _CATEGORY_SCORE_MAP
				if key in categories
			},
			'audits': {
				audit_id: {
					'numericValue': (audits.get(audit_id) or {}).get('numericValue'),
					'displayValue': (audits.get(audit_id) or {}).get('displayValue'),
					'score': (audits.get(audit_id) or {}).get('score'),
				}
				for audit_id in _AUDIT_METRIC_MAP
				if audit_id in audits
			},
			'fetchTime': payload.get('fetchTime'),
			'finalUrl': payload.get('finalUrl') or payload.get('requestedUrl'),
		},
		'error': None,
	}

	for cat_id, field_name in _CATEGORY_SCORE_MAP.items():
		fields[field_name] = _score_to_100((categories.get(cat_id) or {}).get('score'))

	for audit_id, field_name in _AUDIT_METRIC_MAP.items():
		fields[field_name] = _audit_numeric(audits, audit_id)

	return fields


def run_lighthouse(url, timeout=PERFORMANCE_BENCHMARK_DEFAULT_TIMEOUT, chrome_path=None):
	"""Run Lighthouse CLI against a URL and return parsed metrics.

	Args:
		url (str): Target URL.
		timeout (int): Soft timeout seconds for the Lighthouse process.
		chrome_path (str, optional): Chromium binary path.

	Returns:
		dict: Parsed fields from parse_lighthouse_json, or error-only dict.
	"""
	chrome = chrome_path or CHROMIUM_PATH
	lighthouse = shutil.which(LIGHTHOUSE_BIN) or LIGHTHOUSE_BIN
	if not shutil.which(LIGHTHOUSE_BIN) and not Path(LIGHTHOUSE_BIN).exists():
		return {
			'raw_json': {},
			'error': f'Lighthouse binary not found ({LIGHTHOUSE_BIN}). Rebuild the web image.',
		}

	chrome_flags = '--headless --no-sandbox --disable-dev-shm-usage --disable-gpu'
	with tempfile.TemporaryDirectory(prefix='lighthouse_') as tmpdir:
		out_path = Path(tmpdir) / 'report.json'
		cmd = [
			lighthouse,
			url,
			f'--chrome-path={chrome}',
			f'--chrome-flags={chrome_flags}',
			'--output=json',
			f'--output-path={out_path}',
			'--quiet',
			'--only-categories=performance,accessibility,best-practices,seo',
			'--no-enable-error-reporting',
		]
		try:
			# Lighthouse itself can hang; give a hard process ceiling above soft timeout.
			proc = subprocess.run(
				cmd,
				capture_output=True,
				text=True,
				timeout=max(int(timeout) + 30, 90),
				check=False,
			)
		except subprocess.TimeoutExpired:
			return {'raw_json': {}, 'error': f'Lighthouse timed out after {timeout}s'}
		except FileNotFoundError:
			return {'raw_json': {}, 'error': f'Lighthouse binary not found ({lighthouse})'}
		except OSError as exc:
			return {'raw_json': {}, 'error': f'Failed to start Lighthouse: {exc}'}

		if not out_path.exists():
			stderr = (proc.stderr or proc.stdout or '').strip()[:500]
			return {
				'raw_json': {},
				'error': f'Lighthouse produced no report (exit={proc.returncode}): {stderr or "no output"}',
			}

		try:
			payload = json.loads(out_path.read_text(encoding='utf-8'))
		except (OSError, json.JSONDecodeError) as exc:
			return {'raw_json': {}, 'error': f'Failed to parse Lighthouse JSON: {exc}'}

		parsed = parse_lighthouse_json(payload)
		if proc.returncode not in (0, None) and parsed.get('performance_score') is None:
			stderr = (proc.stderr or '').strip()[:300]
			parsed['error'] = parsed.get('error') or f'Lighthouse exit={proc.returncode}: {stderr}'
		return parsed


def performance_benchmark(self, ctx={}, description=None):
	"""Run Lighthouse against default alive endpoints (same target universe as screenshots).

	Args:
		ctx (dict): Scan context.
		description (str, optional): Activity description for UI.
	"""
	config = self.yaml_configuration.get(PERFORMANCE_BENCHMARK) or {}
	try:
		max_urls = int(config.get(PERFORMANCE_BENCHMARK_MAX_URLS) or PERFORMANCE_BENCHMARK_DEFAULT_MAX_URLS)
	except (TypeError, ValueError):
		max_urls = PERFORMANCE_BENCHMARK_DEFAULT_MAX_URLS
	try:
		timeout = int(
			config.get(TIMEOUT)
			or self.yaml_configuration.get(TIMEOUT)
			or PERFORMANCE_BENCHMARK_DEFAULT_TIMEOUT
		)
	except (TypeError, ValueError):
		timeout = PERFORMANCE_BENCHMARK_DEFAULT_TIMEOUT
	# Keep wall-clock work inside the activity start_to_close budget (8h).
	max_urls = max(1, min(max_urls, PERFORMANCE_BENCHMARK_HARD_MAX_URLS))
	timeout = max(15, min(timeout, PERFORMANCE_BENCHMARK_HARD_MAX_TIMEOUT))

	endpoints = (
		EndPoint.objects
		.filter(scan_history=self.scan, is_default=True)
		.filter(subdomain__isnull=False)
		.exclude(http_url__isnull=True)
		.exclude(http_url='')
		.select_related('subdomain')
		.order_by('id')
	)
	subdomain_id = ctx.get('subdomain_id')
	if subdomain_id:
		endpoints = endpoints.filter(subdomain_id=subdomain_id)
	elif ctx.get('singular_tool_run') and ctx.get('urls'):
		endpoints = endpoints.filter(http_url__in=list(ctx.get('urls') or []))

	# Idempotent: retries must not accumulate duplicate Lighthouse rows.
	prior = PerformanceBenchmark.objects.filter(scan_history=self.scan)
	if subdomain_id:
		prior = prior.filter(subdomain_id=subdomain_id)
	deleted, _ = prior.delete()
	if deleted:
		logger.info('Cleared %d prior performance benchmark row(s) before re-run', deleted)

	endpoint_list = list(endpoints[:max_urls])
	logger.info(
		'Starting Lighthouse performance benchmark for %d endpoints (max_urls=%s timeout=%ss)...',
		len(endpoint_list), max_urls, timeout,
	)

	success_count = 0
	error_count = 0
	for endpoint in endpoint_list:
		url = endpoint.http_url
		logger.info('Lighthouse probing %s', url)
		parsed = run_lighthouse(url, timeout=timeout)
		PerformanceBenchmark.objects.create(
			scan_history=self.scan,
			subdomain=endpoint.subdomain,
			endpoint=endpoint,
			http_url=url,
			performance_score=parsed.get('performance_score'),
			accessibility_score=parsed.get('accessibility_score'),
			best_practices_score=parsed.get('best_practices_score'),
			seo_score=parsed.get('seo_score'),
			fcp_ms=parsed.get('fcp_ms'),
			lcp_ms=parsed.get('lcp_ms'),
			tbt_ms=parsed.get('tbt_ms'),
			cls=parsed.get('cls'),
			speed_index_ms=parsed.get('speed_index_ms'),
			tti_ms=parsed.get('tti_ms'),
			ttfb_ms=parsed.get('ttfb_ms'),
			raw_json=parsed.get('raw_json') or {},
			error=parsed.get('error'),
		)
		if parsed.get('error') and parsed.get('performance_score') is None:
			error_count += 1
		else:
			success_count += 1

	self.notify(fields={
		'Performance benchmarks': (
			f'Lighthouse completed for {success_count} URL(s)'
			+ (f' ({error_count} failed)' if error_count else '')
		),
	})
	return True
