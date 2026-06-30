import os
import django
from django.apps import apps
if not apps.ready and not apps.loading:
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
    django.setup()

import csv
import threading
import requests
import json
import pprint
import subprocess
import time
import validators
import xmltodict
import yaml
import tldextract
import concurrent.futures
import base64
import io
import shutil
from redis import Redis


from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from api.serializers import SubdomainSerializer
import logging
from django.db import transaction
from django.db.models import Count
from dotted_dict import DottedDict
from django.utils import timezone
from django.shortcuts import get_object_or_404
from pycvesearch import CVESearch
from metafinder.extractor import extract_metadata_from_google_search

from django.core.cache import cache
from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.settings import *
from reNgine.llm import *
from reNgine.utilities import *
from reNgine.utils.opsec import ProxychainsWrapper, get_opsec_manager
from reNgine.utils.waf import OriginDiscoveryManager, WafBypassOrchestrator
from scanEngine.models import (EngineType, InstalledExternalTool, Notification, Proxy, OpSec)
from startScan.models import *
from startScan.models import EndPoint, Subdomain, Vulnerability, Parameter
from targetApp.models import Domain, normalize_manual_subdomains
from dashboard.models import AcunetixAPIKey, HunterIOAPIKey
from reNgine.tasks.monitor import *
from reNgine.utils.graph import Neo4jManager
from reNgine.tasks.vulnerability import *
from reNgine.tasks.fuzzing import *
from reNgine.stress.testing_tasks import run_stress_testing
from reNgine.utils.task import (
    run_command, run_command_with_retry, stream_command, save_email, save_employee, save_subdomain, save_endpoint, save_parameter,
    sanitize_command_for_db, get_tool_color, ensure_endpoints_crawled_and_execute, save_fuzzing_file,
    parse_custom_header_to_list, save_subdomain_metadata,
    bulk_persist_fetch_urls, bulk_apply_gf_pattern_from_file, activity_heartbeat_safe,
)
from reNgine.tasks.report import *
from reNgine.tasks.wpscan import wpscan_scan
from reNgine.parsers import SpiderFootBatchParser
from reNgine.tech_mapping import get_nuclei_tags_from_techs
try:
	from acunetix import Acunetix
except ImportError:
	Acunetix = None

from plugins.orchestrator import PluginOrchestrator
from reNgine.tasks.parsers import (
    parse_nuclei_result,
    parse_dalfox_result,
    parse_crlfuzz_result,
    parse_s3scanner_result,
)
from reNgine.tasks.acunetix import (
    map_acunetix_severity,
    _validate_subdomain_name,
    _build_vuln_detail_url,
    _normalize_acunetix_target_url,
    _find_acunetix_target,
    _get_acunetix_profile_id,
    _create_or_reuse_acunetix_target,
    _start_acunetix_scan_direct,
    _fetch_acunetix_vulnerabilities,
    acunetix_scan,
)
from reNgine.tasks.geo import (
    geo_localize,
    query_whois,
    query_reverse_whois,
    query_ip_history,
    fetch_related_tlds_and_domains,
    fetch_whois_data_using_netlas,
)
from reNgine.tasks.llm import (
    llm_vulnerability_description, pull_ollama_model,
    get_vulnerability_gpt_report, add_gpt_description_db,
)
from reNgine.tasks.proxies import fetch_proxies_task
from reNgine.tasks.waf import waf_detection, waf_bypass
from reNgine.tasks.screenshot import screenshot
from reNgine.tasks.notifications import (
    send_notif,
    send_scan_notif,
    generate_inapp_notification,
    send_task_notif,
    send_file_to_discord,
    send_hackerone_report,
)
from reNgine.tasks.persistence import (
    remove_duplicate_endpoints,
    process_httpx_response,
    extract_httpx_url,
    save_metadata_info,
    create_scan_activity,
    save_ip_address,
    save_secret_leak,
)
from reNgine.tasks.port_scan import (
    port_scan, nmap, firewall_vpn_scan,
    parse_nmap_results, parse_nmap_https_redirect_output,
    parse_nmap_http_server_header_output, parse_nmap_fingerprint_strings_output,
    parse_nmap_http_title_output, parse_nmap_generic_vuln_output,
    parse_nmap_http_csrf_output, parse_nmap_vulscan_output,
    parse_nmap_vulners_output, get_severity_from_cvss,
    cve_to_vuln, parse_sslscan_results,
)
from reNgine.tasks.crawl import (
    http_crawl, fetch_url, web_api_discovery, parse_curl_output,
)
from reNgine.tasks.vuln import (
    vulnerability_scan, nuclei_scan, dalfox_xss_scan, crlfuzz_scan, s3scanner,
    sync_cisa_kev_catalog, sync_semgrep_rules, clean_and_validate_url,
    semgrep_scan, save_semgrep_vulnerability_finding, save_semgrep_secret_finding,
    smugglex_scan, second_order_scan, nuclei_dast_scan
)
from reNgine.tasks.osint import (
    osint, osint_discovery, dorking, theHarvester, h8mail,
    leaklookup, secret_scanning, spiderfoot_scan,
    persist_osint_item, _process_spiderfoot_batch,
    get_and_save_dork_results,
    run_holehe, run_maigret, run_linkedint,
    enrich_identities_task, db_conn_safe_wrapper, osint_orchestrator,
)
from reNgine.tasks.subdomain import (
    subdomain_discovery, amass_intel_discovery, save_imported_subdomains,
)
from reNgine.tasks.scan_init import (
    SCAN_PIPELINE_DEFINITION,
    sync_all_scans_to_graph,
    finish_osint,
    finish_osint_discovery,
    initiate_scan_temporal,
    initiate_subscan_temporal,
    report,
    resume_scan_temporal,
)

"""
Celery tasks.
"""

logger = get_task_logger(__name__)




def correlate_exposures(self, scan_history_id, ctx={}, description=None):
	"""Correlate exposures and attack surface assets.
	"""
	logger.warning("[TIER7][CORRELATE_EXPOSURES] Starting exposure correlation | scan_id=%s", scan_history_id)
	
	from startScan.models import ScanHistory
	from reNgine.exposure_correlation import ExposureCorrelationEngine
	try:
		history = ScanHistory.objects.get(id=scan_history_id)
		engine = ExposureCorrelationEngine(scan_history=history)
		engine.correlate_exposures()
		logger.info("[TIER7][CORRELATE_EXPOSURES] Completed exposure correlation for scan_id=%s", scan_history_id)
	except ScanHistory.DoesNotExist:
		logger.error("ScanHistory not found: %s", scan_history_id)
	except Exception as e:
		logger.error("Error correlating exposures: %s", e)


def correlate_vulnerabilities(self, scan_history_id, ctx={}, description=None):
	"""Correlate discovered technologies with known CVEs and update the graph database.

	Args:
		scan_history_id (int): Scan history ID.
		ctx (dict): Scan context.
	"""
	logger.warning("[TIER7][CORRELATE] Starting vulnerability correlation | scan_id=%s", scan_history_id)

	# Check if there are other scanning tasks still running
	from startScan.models import ScanActivity
	from reNgine.definitions import RUNNING_TASK, INITIATED_TASK
	post_processing_names = ['correlate_vulnerabilities', 'calculate_risk_scores', 'generate_impact_assessment', 'run_apme', 'report']

	if self.subscan:
		running_scans = ScanActivity.objects.filter(
			execution_id__in=self.subscan.workflow_ids,
			status__in=[RUNNING_TASK, INITIATED_TASK]
		).exclude(name__in=post_processing_names)
	else:
		running_scans = ScanActivity.objects.filter(
			scan_of_id=scan_history_id,
			status__in=[RUNNING_TASK, INITIATED_TASK]
		).exclude(name__in=post_processing_names)

	if running_scans.exists() and not getattr(self, '_is_temporal_proxy', False):
		running_names = list(running_scans.values_list('name', flat=True))
		logger.warning("[TIER7][CORRELATE] Scan tasks still running (%s) — rescheduling", running_names)
		raise self.retry(countdown=10, max_retries=1000)

	vuln_count = Vulnerability.objects.filter(scan_history_id=scan_history_id).count()
	logger.warning("[TIER7][CORRELATE] Syncing %d vulnerabilities to Neo4j graph | scan_id=%s", vuln_count, scan_history_id)

	nm = Neo4jManager()
	try:
		nm.sync_scan_results(scan_history_id)
		logger.warning("[TIER7][CORRELATE] Neo4j sync complete | scan_id=%s", scan_history_id)
	except Exception as e:
		logger.error("[TIER7][CORRELATE] Neo4j sync failed for scan_id=%s: %s", scan_history_id, e)
	finally:
		nm.close()

	logger.warning("[TIER7][CORRELATE] Vulnerability correlation complete | scan_id=%s", scan_history_id)


def calculate_risk_scores(self, scan_history_id, ctx={}, description=None):
	"""Calculate a weighted risk score for discovered vulnerabilities.

	Args:
		scan_history_id (int): Scan history ID.
		ctx (dict): Scan context.
	"""
	logger.warning("[TIER7][RISK] Starting risk score calculation | scan_id=%s", scan_history_id)

	# Check if there are other scanning tasks still running
	from startScan.models import ScanActivity
	from reNgine.definitions import RUNNING_TASK, INITIATED_TASK
	post_processing_names = ['correlate_vulnerabilities', 'calculate_risk_scores', 'generate_impact_assessment', 'run_apme', 'report']

	if self.subscan:
		running_scans = ScanActivity.objects.filter(
			execution_id__in=self.subscan.workflow_ids,
			status__in=[RUNNING_TASK, INITIATED_TASK]
		).exclude(name__in=post_processing_names)
	else:
		running_scans = ScanActivity.objects.filter(
			scan_of_id=scan_history_id,
			status__in=[RUNNING_TASK, INITIATED_TASK]
		).exclude(name__in=post_processing_names)

	if running_scans.exists() and not getattr(self, '_is_temporal_proxy', False):
		running_names = list(running_scans.values_list('name', flat=True))
		logger.warning("[TIER7][RISK] Scan tasks still running (%s) — rescheduling", running_names)
		raise self.retry(countdown=10, max_retries=1000)

	from reNgine.correlation import VulnerabilityCorrelationEngine
	scan_history = ScanHistory.objects.get(id=scan_history_id)

	vuln_count = Vulnerability.objects.filter(scan_history_id=scan_history_id).count()
	logger.warning("[TIER7][RISK] Running correlation engine on %d vulnerabilities | scan_id=%s", vuln_count, scan_history_id)

	correlator = VulnerabilityCorrelationEngine(scan_history=scan_history)
	try:
		correlator.correlate_findings()
		logger.warning("[TIER7][RISK] Risk score calculation complete | scan_id=%s", scan_history_id)
	except Exception as e:
		logger.error("[TIER7][RISK] Correlation engine failed for scan_id=%s: %s", scan_history_id, e, exc_info=True)
		raise


def generate_impact_assessment(self, scan_history_id=None, vulnerability_id=None, ctx={}, description=None):
	"""Generate an AI-powered impact assessment for vulnerabilities.

	Args:
		scan_history_id (int): Scan history ID.
		vulnerability_id (int): Specific vulnerability ID.
		ctx (dict): Scan context.
	"""
	logger.warning("[TIER7][IMPACT] Starting AI impact assessment | scan_id=%s vuln_id=%s", scan_history_id, vulnerability_id)

	from reNgine.llm import LLMImpactGenerator
	from reNgine.privacy import PIIGate

	# Cap the per-run vuln limit so the activity stays well inside start_to_close_timeout.
	# Single-vuln calls from the dashboard UI bypass this via vulnerability_id.
	_VULN_LIMIT = 100

	if vulnerability_id:
		vulns = Vulnerability.objects.filter(id=vulnerability_id).prefetch_related(
			'subdomain__technologies', 'cve_ids'
		)
		if not scan_history_id and vulns.exists():
			scan_history_id = vulns.first().scan_history_id
		logger.warning("[TIER7][IMPACT] Single-vuln mode | vuln_id=%s scan_id=%s", vulnerability_id, scan_history_id)
	elif scan_history_id:
		# Order critical→info so the most important findings are assessed first
		# if the run is interrupted; cap to avoid timeout on large scans.
		vulns = (
			Vulnerability.objects
			.filter(scan_history_id=scan_history_id)
			.prefetch_related('subdomain__technologies', 'cve_ids')
			.order_by('-severity')[:_VULN_LIMIT]
		)
		total_vulns = Vulnerability.objects.filter(scan_history_id=scan_history_id).count()
		logger.warning(
			"[TIER7][IMPACT] Bulk mode | %d total vulns | processing up to %d (capped) | scan_id=%s",
			total_vulns, _VULN_LIMIT, scan_history_id,
		)
	else:
		logger.error("[TIER7][IMPACT] Neither scan_history_id nor vulnerability_id provided — aborting.")
		return False

	# Check if there are other scanning tasks still running
	if scan_history_id:
		from startScan.models import ScanActivity
		from reNgine.definitions import RUNNING_TASK, INITIATED_TASK
		post_processing_names = ['correlate_vulnerabilities', 'calculate_risk_scores', 'generate_impact_assessment', 'run_apme', 'report']

		if self.subscan:
			running_scans = ScanActivity.objects.filter(
				execution_id__in=self.subscan.workflow_ids,
				status__in=[RUNNING_TASK, INITIATED_TASK]
			).exclude(name__in=post_processing_names)
		else:
			running_scans = ScanActivity.objects.filter(
				scan_of_id=scan_history_id,
				status__in=[RUNNING_TASK, INITIATED_TASK]
			).exclude(name__in=post_processing_names)

		if running_scans.exists() and not getattr(self, '_is_temporal_proxy', False):
			running_names = list(running_scans.values_list('name', flat=True))
			logger.warning("[TIER7][IMPACT] Scan tasks still running (%s) — rescheduling", running_names)
			raise self.retry(countdown=10, max_retries=1000)

	generator = LLMImpactGenerator(logger)
	assessed_count = 0
	suppressed_count = 0
	failed_count = 0
	vuln_list = list(vulns)
	total = len(vuln_list)

	logger.warning("[TIER7][IMPACT] Beginning per-vulnerability LLM loop | total=%d | scan_id=%s", total, scan_history_id)

	for idx, vuln in enumerate(vuln_list, start=1):
		# Skip suppressed vulnerabilities during bulk scan, but process them if specifically requested by user.
		if vuln.is_suppressed and not vulnerability_id:
			suppressed_count += 1
			logger.warning("[TIER7][IMPACT] [%d/%d] Skipping suppressed vuln_id=%s", idx, total, vuln.id)
			continue

		asset = vuln.subdomain.name if vuln.subdomain else (vuln.endpoint.http_url if vuln.endpoint else 'Unknown')

		try:
			# Step 1 — populate structured description/impact/remediation/references if not already done
			if not vuln.is_gpt_used:
				logger.warning(
					"[TIER7][IMPACT] [%d/%d] Generating GPT vulnerability report | vuln_id=%s",
					idx, total, vuln.id,
				)
				gpt_report = get_vulnerability_gpt_report(
					(vuln.name, vuln.get_path()),
					vulnerability_id=vuln.id,
				)
				if gpt_report.get('status'):
					vuln.refresh_from_db()
					logger.warning(
						"[TIER7][IMPACT] [%d/%d] GPT report saved | vuln_id=%s",
						idx, total, vuln.id,
					)
				else:
					logger.warning(
						"[TIER7][IMPACT] [%d/%d] GPT report failed | vuln_id=%s error=%s",
						idx, total, vuln.id, gpt_report.get('error'),
					)

			# Step 2 — generate AI business-impact assessment (for ImpactAssessment record)
			logger.warning(
				"[TIER7][IMPACT] [%d/%d] Calling LLM impact generator | vuln_id=%s severity=%s asset=%s",
				idx, total, vuln.id, vuln.severity, asset,
			)

			existing_assessment = ImpactAssessment.objects.filter(
				vulnerability__name=vuln.name,
				is_ai_generated=True
			).first()

			if existing_assessment and existing_assessment.potential_impact:
				logger.warning(
					"[TIER7][IMPACT] [%d/%d] Reusing existing target-agnostic impact assessment for %s | vuln_id=%s",
					idx, total, vuln.name, vuln.id,
				)
				final_impact = existing_assessment.potential_impact
				elapsed = 0.0
			else:
				# Omit Asset to make context target-agnostic (PII masking is handled by generator)
				context = "Vulnerability: %s\n" % vuln.name
				context += "Description: %s\n" % (vuln.description or '')
				if vuln.subdomain:
					context += "Technologies: %s\n" % ', '.join([t.name for t in vuln.subdomain.technologies.all()])

				t_start = time.time()
				final_impact = generator.generate_impact_assessment(context)
				elapsed = time.time() - t_start

			logger.warning(
				"[TIER7][IMPACT] [%d/%d] LLM returned in %.1fs | vuln_id=%s impact_len=%d",
				idx, total, elapsed, vuln.id, len(final_impact) if final_impact else 0,
			)

			# Persist business-impact text to ImpactAssessment model
			ImpactAssessment.objects.update_or_create(
				vulnerability=vuln,
				defaults={
					'scan_history_id': scan_history_id,
					'subdomain': vuln.subdomain,
					'potential_impact': final_impact,
					'is_ai_generated': True
				}
			)

			# Only write back to Vulnerability.impact when the structured GPT report
			# has not already set it (avoid overwriting the richer structured content).
			if not vuln.is_gpt_used:
				vuln.impact = final_impact
				vuln.save()

			assessed_count += 1
			logger.warning("[TIER7][IMPACT] [%d/%d] Saved | vuln_id=%s", idx, total, vuln.id)

		except Exception as e:
			failed_count += 1
			logger.error(
				"[TIER7][IMPACT] [%d/%d] Failed for vuln_id=%s: %s",
				idx, total, vuln.id, e, exc_info=True,
			)

	logger.warning(
		"[TIER7][IMPACT] AI impact assessment complete | assessed=%d suppressed=%d failed=%d | scan_id=%s",
		assessed_count, suppressed_count, failed_count, scan_history_id,
	)




def run_apme(self, scan_history_id, ctx={}, description=None):
	"""Run the Attack Path Modeling Engine (APME).

	Args:
		scan_history_id (int): Scan history ID.
		ctx (dict): Scan context.
	"""
	logger.warning("[TIER7][APME] Starting Attack Path Modeling Engine | scan_id=%s", scan_history_id)

	if not RENGINE_APME_ENABLED:
		logger.warning("[TIER7][APME] Disabled via RENGINE_APME_ENABLED=False — skipping | scan_id=%s", scan_history_id)
		return

	# Check if there are other scanning tasks still running
	from startScan.models import ScanActivity
	from reNgine.definitions import RUNNING_TASK, INITIATED_TASK
	post_processing_names = ['correlate_vulnerabilities', 'calculate_risk_scores', 'generate_impact_assessment', 'run_apme', 'report']

	if self.subscan:
		running_scans = ScanActivity.objects.filter(
			execution_id__in=self.subscan.workflow_ids,
			status__in=[RUNNING_TASK, INITIATED_TASK]
		).exclude(name__in=post_processing_names)
	else:
		running_scans = ScanActivity.objects.filter(
			scan_of_id=scan_history_id,
			status__in=[RUNNING_TASK, INITIATED_TASK]
		).exclude(name__in=post_processing_names)

	if running_scans.exists() and not getattr(self, '_is_temporal_proxy', False):
		running_names = list(running_scans.values_list('name', flat=True))
		logger.warning("[TIER7][APME] Scan tasks still running (%s) — rescheduling", running_names)
		raise self.retry(countdown=10, max_retries=1000)

	try:
		from apme.orchestrator import APMEOrchestrator
		from startScan.models import ScanHistory

		# Fetch configuration from engine
		scan = ScanHistory.objects.get(id=scan_history_id)
		config = yaml.safe_load(scan.scan_type.yaml_configuration) or {}
		apme_config = config.get(ATTACK_PATH_MODELING, {})
		top_n = apme_config.get('top_n', 5)

		logger.warning("[TIER7][APME] Running orchestrator | top_n=%d | scan_id=%s", top_n, scan_history_id)
		orchestrator = APMEOrchestrator(top_n=top_n)
		result = orchestrator.run(scan_history_id)

		logger.warning(
			"[TIER7][APME] Complete | total_paths=%d returned_paths=%d | scan_id=%s",
			result.get('total_paths', 0), result.get('returned_paths', 0), scan_history_id,
		)
		return result
	except Exception as exc:
		logger.error("[TIER7][APME] Failed for scan_id=%s: %s", scan_history_id, exc, exc_info=True)
		return {"error": str(exc), "total_paths": 0, "returned_paths": 0, "paths": []}