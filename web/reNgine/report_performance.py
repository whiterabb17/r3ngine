"""Build performance-benchmarking context for scan PDF reports."""

from __future__ import annotations

from statistics import mean, median
from typing import Any

from django.db.models import Avg

from startScan.models import EndPoint, PerformanceBenchmark, Subdomain


def _percentile(sorted_values: list[float], pct: float) -> float | None:
	if not sorted_values:
		return None
	if len(sorted_values) == 1:
		return sorted_values[0]
	k = (len(sorted_values) - 1) * (pct / 100.0)
	f = int(k)
	c = min(f + 1, len(sorted_values) - 1)
	if f == c:
		return sorted_values[f]
	return sorted_values[f] + (sorted_values[c] - sorted_values[f]) * (k - f)


def _avg(values: list[float]) -> float | None:
	return mean(values) if values else None


def build_performance_context(scan, table_limit: int = 40) -> dict[str, Any]:
	"""Aggregate Lighthouse rows and httpx probe latency for a scan report.

	Args:
		scan: ScanHistory instance.
		table_limit: Max URL rows for the PDF table.

	Returns:
		dict: Template context under ``performance_context``.
	"""
	benchmarks = list(
		PerformanceBenchmark.objects
		.filter(scan_history=scan)
		.order_by('-performance_score', 'http_url')
	)
	ok_rows = [b for b in benchmarks if b.performance_score is not None]

	perf_scores = [b.performance_score for b in ok_rows if b.performance_score is not None]
	lcp_vals = [b.lcp_ms for b in ok_rows if b.lcp_ms is not None]
	fcp_vals = [b.fcp_ms for b in ok_rows if b.fcp_ms is not None]
	cls_vals = [b.cls for b in ok_rows if b.cls is not None]
	ttfb_vals = [b.ttfb_ms for b in ok_rows if b.ttfb_ms is not None]

	# Probe latency from httpx (seconds on EndPoint / Subdomain).
	endpoint_times = list(
		EndPoint.objects
		.filter(scan_history=scan, response_time__isnull=False, response_time__gte=0)
		.exclude(http_status=0)
		.values_list('response_time', flat=True)
	)
	endpoint_times = sorted(float(t) for t in endpoint_times if t is not None and float(t) >= 0)

	slowest_endpoints = list(
		EndPoint.objects
		.filter(scan_history=scan, response_time__isnull=False, response_time__gte=0)
		.exclude(http_status=0)
		.order_by('-response_time')[:10]
		.values('http_url', 'response_time', 'http_status')
	)

	subdomain_avg = (
		Subdomain.objects
		.filter(scan_history=scan, response_time__isnull=False, response_time__gte=0)
		.aggregate(avg=Avg('response_time'))
		.get('avg')
	)

	table_rows = []
	for b in benchmarks[:table_limit]:
		table_rows.append({
			'http_url': b.http_url,
			'performance_score': b.performance_score,
			'accessibility_score': b.accessibility_score,
			'best_practices_score': b.best_practices_score,
			'seo_score': b.seo_score,
			'lcp_ms': b.lcp_ms,
			'fcp_ms': b.fcp_ms,
			'cls': b.cls,
			'ttfb_ms': b.ttfb_ms,
			'error': b.error,
		})

	return {
		'has_benchmarks': bool(benchmarks),
		'benchmark_count': len(benchmarks),
		'success_count': len(ok_rows),
		'error_count': len(benchmarks) - len(ok_rows),
		'avg_performance_score': _avg(perf_scores),
		'avg_lcp_ms': _avg(lcp_vals),
		'avg_fcp_ms': _avg(fcp_vals),
		'avg_cls': _avg(cls_vals),
		'avg_ttfb_ms': _avg(ttfb_vals),
		'probe_latency': {
			'count': len(endpoint_times),
			'avg_ms': (mean(endpoint_times) * 1000) if endpoint_times else None,
			'median_ms': (median(endpoint_times) * 1000) if endpoint_times else None,
			'p95_ms': (
				(_percentile(endpoint_times, 95) * 1000)
				if endpoint_times else None
			),
			'subdomain_avg_ms': (float(subdomain_avg) * 1000) if subdomain_avg is not None else None,
			'slowest': [
				{
					'http_url': row['http_url'],
					'response_time_ms': float(row['response_time']) * 1000,
					'http_status': row['http_status'],
				}
				for row in slowest_endpoints
			],
		},
		'rows': table_rows,
		'rows_truncated': len(benchmarks) > table_limit,
		'total_rows': len(benchmarks),
	}
