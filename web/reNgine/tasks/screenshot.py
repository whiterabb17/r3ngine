import logging

from reNgine.common_func import *
from reNgine.definitions import *
from startScan.models import EndPoint

logger = logging.getLogger(__name__)


def screenshot(self, ctx={}, description=None):
	"""Embedded Playwright Screenshot task.

	Queries is_default=True endpoints directly — one per subdomain root — and
	passes the full http_url (including path) to the capture engine.
	Mirrors the rengine-ng approach; fixes the single-screenshot bug caused by
	the Subdomain http_url/http_status strict filter.

	Args:
		description (str, optional): Task description shown in UI.
	"""
	from reNgine.screenshot.tasks import take_screenshot_and_save

	config = self.yaml_configuration.get(SCREENSHOT) or {}
	intensity = config.get(INTENSITY) or self.yaml_configuration.get(INTENSITY, DEFAULT_SCAN_INTENSITY)
	strict = intensity == 'normal'

	# is_default=True excludes both False and NULL; null=True on the field is intentional
	# (NULL means "not yet determined", not "yes"). subdomain__isnull=False guards against
	# orphaned endpoints that would cause take_screenshot_and_save to raise DoesNotExist.
	endpoints = (
		EndPoint.objects
		.filter(scan_history=self.scan, is_default=True)
		.filter(subdomain__isnull=False)
		.exclude(http_url__isnull=True)
		.exclude(http_url='')
		.select_related('subdomain')
	)

	# No http_status filter: is_default endpoints are created before http_crawl probes them,
	# so they always have http_status=0. Playwright handles unreachable URLs gracefully.
	# intensity=normal still limits scope via is_default=True (one endpoint per subdomain root).
	_ = strict  # reserved for future per-intensity tuning

	endpoint_list = list(endpoints)
	logger.info("Starting Playwright screenshot capture for %d default endpoints...", len(endpoint_list))

	success_count = 0
	for endpoint in endpoint_list:
		if take_screenshot_and_save(
			subdomain_id=endpoint.subdomain_id,
			scan_id=self.scan_id,
			results_dir=self.results_dir,
			activity_id=self.activity_id,
			url_override=endpoint.http_url,
		):
			success_count += 1

	self.notify(fields={'Screenshots': f'Successfully captured {success_count} screenshots using Embedded Playwright.'})
	return True
