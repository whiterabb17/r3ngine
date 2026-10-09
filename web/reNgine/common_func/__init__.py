"""Compatibility surface of the former single-file reNgine/common_func.py.

The implementation now lives in cohesive submodules (see the imports at the
bottom). 30+ modules do ``from reNgine.common_func import *`` and rely on every
name the old module had in its namespace -- including the names it imported
itself -- so the original import block is kept verbatim and every definition is
re-exported explicitly. Do not add ``__all__``: it would shrink that surface.

New code should import from the submodule that owns the helper.
"""
import whatportis  # noqa: F401,F403
import socket  # noqa: F401,F403
import json  # noqa: F401,F403
import glob  # noqa: F401,F403
import os  # noqa: F401,F403
import pickle  # noqa: F401,F403
import subprocess  # noqa: F401,F403
import threading  # noqa: F401,F403
from reNgine.validators import validate_external_url  # noqa: F401,F403
import random  # noqa: F401,F403
import shutil  # noqa: F401,F403
import traceback  # noqa: F401,F403
import ipaddress  # noqa: F401,F403
import humanize  # noqa: F401,F403
import redis  # noqa: F401,F403
import requests  # noqa: F401,F403
import tldextract  # noqa: F401,F403
import shlex  # noqa: F401,F403
import re  # noqa: F401,F403
import xmltodict  # noqa: F401,F403

import time  # noqa: F401,F403
from time import sleep  # noqa: F401,F403
from bs4 import BeautifulSoup  # noqa: F401,F403
from urllib.parse import urlparse, parse_qs  # noqa: F401,F403
import logging as _logging  # noqa: F401,F403
get_task_logger = _logging.getLogger
from discord_webhook import DiscordEmbed, DiscordWebhook  # noqa: F401,F403
from django.db.models import Q  # noqa: F401,F403
from dotted_dict import DottedDict  # noqa: F401,F403

from django.utils import timezone  # noqa: F401,F403
from reNgine.common_serializers import *  # noqa: F401,F403
from reNgine.definitions import *  # noqa: F401,F403
from reNgine.settings import *  # noqa: F401,F403
from scanEngine.models import *  # noqa: F401,F403
from dashboard.models import *  # noqa: F401,F403
from startScan.models import *  # noqa: F401,F403
from targetApp.models import *  # noqa: F401,F403
from reNgine.utilities import is_valid_url, replace_nulls  # noqa: F401,F403


logger = get_task_logger(__name__)

from reNgine.common_func.scan_config import (  # noqa: E402,F401
	dump_custom_scan_engines,
	load_custom_scan_engines,
	create_scan_object,
	get_task_cache_key,
	get_output_file_name,
	get_traceback_path,
	fmt_traceback,
	resolve_api_discovery_tools,
)
from reNgine.common_func.db_queries import (  # noqa: E402,F401
	get_lookup_keywords,
	get_subdomains,
	get_new_added_subdomain,
	get_removed_subdomain,
	get_interesting_subdomains,
	get_http_urls,
	collect_all_scan_urls,
	get_interesting_endpoints,
	record_exists,
	merge_imported_subdomains,
	get_port_service_description,
	update_or_create_port,
)
from reNgine.common_func.vuln_helpers import (  # noqa: E402,F401
	save_vulnerability,
	parse_llm_vulnerability_report,
	_SEMGREP_LABEL_MAP,
	_SEMGREP_STRIP_PREFIXES,
	_SEMGREP_BOILERPLATE,
	clean_semgrep_check_id,
	categorize_secret_type,
	parse_semgrep_result,
	parse_retire_result,
	parse_inql_results,
)
from reNgine.common_func.api_keys import (  # noqa: E402,F401
	get_spiderfoot_keys,
	get_leaklookup_key,
	get_chaos_api_key,
	get_open_ai_key,
	get_netlas_key,
	get_chaos_key,
	get_hackerone_key_username,
	get_securitytrails_key,
)
from reNgine.common_func.url_utils import (  # noqa: E402,F401
	get_subdomain_from_url,
	get_domain_from_subdomain,
	sanitize_url,
	parse_fetched_url_line,
	url_param_signature,
	extract_path_from_url,
	exclude_urls_by_patterns,
	extract_params_from_url,
	get_ip_info,
	get_ips_from_cidr_range,
)
from reNgine.common_func.proxy_pool import (  # noqa: E402,F401
	_USER_AGENT_POOL,
	_DEFAULT_USER_AGENT,
	ALL_PROXY_CHECKERS,
	_failed_proxy_cache,
	_FAILED_PROXY_TTL,
	_used_proxy_cache,
	_USED_PROXY_TTL,
	_proxy_pool_lock,
	_PROXY_DEAD_EXCEPTIONS,
	_PROXY_DEAD_KEYWORDS,
	_detect_server_ip,
	mark_proxy_used,
	is_proxy_recently_used,
	check_proxy_robust,
	validate_single_proxy,
	validate_proxies,
	_normalize_proxy_pool_line,
	get_valid_proxy_count,
	_URL_CREDENTIALS_RE,
	redact_proxy_credentials,
	get_priority_proxies,
	proxy_has_credentials,
	remove_proxy_from_pool,
	remove_proxies_from_pool,
	get_random_user_agent,
	get_random_proxy,
	get_proxy_list,
)
from reNgine.common_func.cli_commands import (  # noqa: E402,F401
	remove_ansi_escape_sequences,
	get_cms_details,
	_build_cmd,
	get_nmap_cmd,
	xml2json,
	is_valid_nmap_command,
)
from reNgine.common_func.notify import (  # noqa: E402,F401
	DISCORD_WEBHOOKS_CACHE,
	send_telegram_message,
	send_slack_message,
	send_lark_message,
	send_discord_message,
	enrich_notification,
	get_scan_title,
	get_scan_url,
	get_scan_fields,
	get_task_title,
	get_task_header_message,
	create_inappnotification,
	send_mobile_push_notification,
)
from reNgine.common_func.whois_info import (  # noqa: E402,F401
	reverse_whois,
	get_domain_historical_ip_address,
	get_domain_info_from_db,
	extract_domain_info,
	format_whois_response,
	parse_whois_data,
	parse_registrar_info,
	parse_registration_info,
	parse_dns_records,
	save_domain_info_to_db,
)
from reNgine.common_func.probe_gates import (  # noqa: E402,F401
	_JWT_PARAM_RE,
	_JWT_SECRET_TYPE_RE,
	_GRAPHQL_PROBE_PATHS,
	_OPENAPI_PROBE_PATHS,
	_PROBE_HEADERS,
	_PROBE_TIMEOUT,
	GRAPHQL_ENDPOINT_URL_REGEX,
	is_graphql_endpoint_url,
	has_graphql_endpoint,
	has_openapi_spec,
	has_jwt_tokens,
)
