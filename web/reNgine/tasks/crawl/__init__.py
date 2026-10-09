"""Compatibility surface of the former single-file reNgine/tasks/crawl.py.

The implementation now lives in cohesive submodules (see the imports at the
bottom). This module is re-exported by the ``reNgine.tasks`` shim and looked up
by attribute from Temporal activities and tests, so the original import block
is kept verbatim and every definition is re-exported explicitly. Do not add
``__all__``: it would shrink that surface.

New code should import from the submodule that owns the function.
"""
import logging  # noqa: F401,F403
import os  # noqa: F401,F403
import json  # noqa: F401,F403
import hashlib  # noqa: F401,F403
import re  # noqa: F401,F403
import shlex  # noqa: F401,F403
import subprocess  # noqa: F401,F403
import requests  # noqa: F401,F403
import validators  # noqa: F401,F403
from pathlib import Path  # noqa: F401,F403
from typing import List, Optional  # noqa: F401,F403
from urllib.parse import urlparse  # noqa: F401,F403

from reNgine.common_func import *  # noqa: F401,F403
from reNgine.definitions import *  # noqa: F401,F403
from reNgine.utils.logger import get_module_logger  # noqa: F401,F403
from reNgine.utils.opsec import OpSecManager, ProxychainsWrapper, get_opsec_manager  # noqa: F401,F403
from reNgine.utils.task import (  # noqa: F401,F403
    run_command, run_command_with_retry, stream_command, activity_heartbeat_safe,
    bulk_persist_fetch_urls, bulk_apply_gf_pattern_from_file,
    save_endpoint, save_parameter,
)
from reNgine.tasks.persistence import process_httpx_response, extract_httpx_url, remove_duplicate_endpoints, save_ip_address  # noqa: F401,F403
from reNgine.utils.graph import Neo4jManager  # noqa: F401,F403
from reNgine.tasks.api import run_jwt_scan, run_graphql_cop  # noqa: F401,F403
from reNgine.tasks.auth_discovery import extract_auth_candidates  # noqa: F401,F403
from reNgine.cpde.graphql_enricher import enrich_graphql_params  # noqa: F401,F403
from startScan.models import *  # noqa: F401,F403

logger = get_module_logger(__name__)

from reNgine.tasks.crawl.api_discovery import (  # noqa: E402,F401
    _GRPC_CANDIDATE_PORTS,
    _GRPC_TLS_PORTS,
    _GRPC_SERVICE_HINTS,
    _TLS_SERVICE_HINTS,
    _GRPC_MAX_PORTS_PER_HOST,
    _GRPC_CONNECT_TIMEOUT,
    _GRPC_MAX_TIME,
    _GRPC_COMMAND_TIMEOUT,
    gqlspection_schema_dumped,
    grpc_probe_targets,
    web_api_discovery,
)
from reNgine.tasks.crawl.url_fetch import (  # noqa: E402,F401
    fetch_url,
)
from reNgine.tasks.crawl.httpx_crawl import (  # noqa: E402,F401
    parse_curl_output,
    http_crawl,
)
from reNgine.tasks.crawl.url_collectors import (  # noqa: E402,F401
    xurlfind3r_scan,
    urlfinder_scan,
    cariddi_scan,
)
from reNgine.tasks.crawl.fuzz_bypass import (  # noqa: E402,F401
    bup_scan,
    feroxbuster_scan,
)
from reNgine.tasks.crawl.param_discovery import (  # noqa: E402,F401
    arjun_scan,
    urlparser_scan,
)
from reNgine.tasks.crawl.gf_patterns import (  # noqa: E402,F401
    gf_scan,
)
