"""Compatibility surface of the former single-file reNgine/tasks/osint.py.

The implementation now lives in cohesive submodules (see the imports at the
bottom). This module is re-exported by the ``reNgine.tasks`` shim and looked up
by attribute from Temporal activities and tests, so the original import block
is kept verbatim and every definition is re-exported explicitly. Do not add
``__all__``: it would shrink that surface.

New code should import from the submodule that owns the function.
"""
import csv  # noqa: F401,F403
import logging  # noqa: F401,F403
import shlex  # noqa: F401,F403
import math  # noqa: F401,F403
import re  # noqa: F401,F403
import shutil  # noqa: F401,F403
import subprocess  # noqa: F401,F403
import threading  # noqa: F401,F403
import json  # noqa: F401,F403
import requests  # noqa: F401,F403
import base64  # noqa: F401,F403
import os  # noqa: F401,F403
import yaml  # noqa: F401,F403
from concurrent.futures import ThreadPoolExecutor, as_completed  # noqa: F401,F403
from pathlib import Path  # noqa: F401,F403
from django.db import transaction  # noqa: F401,F403

from reNgine.common_func import *  # noqa: F401,F403
from reNgine.definitions import *  # noqa: F401,F403
from reNgine.parsers import SpiderFootBatchParser  # noqa: F401,F403
from reNgine.utils.task import (  # noqa: F401,F403
    run_command,
    stream_command,
    save_email,
    save_employee,
    save_subdomain,
    save_endpoint,
)
from reNgine.utils.opsec import get_opsec_manager, OpSecManager, ProxychainsWrapper  # noqa: F401,F403
from reNgine.tasks.persistence import (  # noqa: F401,F403
    save_metadata_info,
    save_ip_address,
    save_secret_leak,
)
from reNgine.tasks.geo import query_whois  # noqa: F401,F403
from reNgine.tasks.scan_init import finish_osint, finish_osint_discovery  # noqa: F401,F403
from reNgine.tasks.certificate import run_certificate_intel  # noqa: F401,F403
from reNgine.tasks.vuln import semgrep_scan  # noqa: F401,F403
from reNgine.osint.hibp_scraper import check_hibp_for_email_task  # noqa: F401,F403
from reNgine.osint.linkedin_intelligence import LinkedInScraper  # noqa: F401,F403
from reNgine.osint.hunter_lookup import run_hunter_lookup  # noqa: F401,F403
from reNgine.osint.email_leaks import run_emailfinder, run_leaksearch  # noqa: F401,F403
from reNgine.osint.cloud_recon import run_msftrecon  # noqa: F401,F403
from reNgine.osint.api_leaks import run_porch_pirate, run_postleaks, run_swaggerspy_internet, run_swaggerspy_path_mode  # noqa: F401,F403
from reNgine.osint.post_crawl_metadata import run_post_crawl_exifray  # noqa: F401,F403
from reNgine.osint.github_analysis import run_github_analysis  # noqa: F401,F403
from reNgine.osint.misconfig import run_misconfig_mapper  # noqa: F401,F403
from reNgine.osint.domain_security import run_spoofcheck  # noqa: F401,F403
from reNgine.utils.graph import Neo4jManager  # noqa: F401,F403
from redis import Redis  # noqa: F401,F403
from scanEngine.models import Proxy  # noqa: F401,F403
from startScan.models import *  # noqa: F401,F403
from startScan.models import Email, Employee  # noqa: F401,F403
from targetApp.models import Domain  # noqa: F401,F403
from dashboard.models import LinkedInCredentials, HunterIOAPIKey  # noqa: F401,F403

logger = logging.getLogger(__name__)

from reNgine.tasks.osint.pipeline import (  # noqa: E402,F401
    osint,
    osint_discovery,
    post_crawl_osint,
)
from reNgine.tasks.osint.dorks import (  # noqa: E402,F401
    dorking,
    get_and_save_dork_results,
)
from reNgine.tasks.osint.people import (  # noqa: E402,F401
    theHarvester,
    run_holehe,
    run_maigret,
    run_linkedint,
    enrich_identities_task,
    db_conn_safe_wrapper,
    osint_orchestrator,
)
from reNgine.tasks.osint.breach_intel import (  # noqa: E402,F401
    h8mail,
    leaklookup,
)
from reNgine.tasks.osint.secret_leaks import (  # noqa: E402,F401
    secret_scanning,
)
from reNgine.tasks.osint.spiderfoot import (  # noqa: E402,F401
    spiderfoot_scan,
    _handle_subdomain,
    _handle_email,
    _handle_employee,
    _handle_url,
    _handle_ip,
    _handle_port,
    _handle_tech,
    _handle_leak,
    _handle_ssl,
    _handle_dns,
    _handle_phone,
    _handle_social,
    _handle_os,
    _handle_crypto,
    _handle_hosting,
    TYPE_ROUTER,
    persist_osint_item,
    _DNS_SF_TYPE_TO_RECORD,
    _enrich_metadata,
    _process_spiderfoot_batch,
)

# The single-file module annotated TYPE_ROUTER at module level, which gave it an
# __annotations__ attribute; a bare annotation keeps that surface without rebinding.
TYPE_ROUTER: dict
