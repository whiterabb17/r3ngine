import logging
import os
import requests

from reNgine.utils.task import save_endpoint, save_parameter, activity_heartbeat_safe
from reNgine.common_func import has_openapi_spec
from startScan.models import Domain

from reNgine.cpde import js_collector
from reNgine.cpde import ast_analyzer
from reNgine.cpde import openapi_discoverer
from reNgine.cpde import correlation_engine
from reNgine.cpde import graph_writer
from reNgine.cpde import url_param_collector

logger = logging.getLogger(__name__)

def param_discovery(self, urls=[], ctx={}, description=None):
    """Custom Parameter Discovery Engine — main orchestration task.

    Reads Katana JS output from the current scan, performs AST analysis,
    probes OpenAPI schema endpoints, and correlates all evidence into
    confidence-scored Parameter records.

    Args:
        urls (list): Seed URLs (used to derive base domains for OpenAPI probing).
        ctx (dict): Scan context dict with scan_history_id, yaml_configuration, etc.
        description (str): Task label for UI timeline.
    """
    logger.info('[CPDE] Starting parameter discovery task')
    scan_id = ctx.get('scan_history_id')
    results_dir = ctx.get('results_dir')
    proxy = ctx.get('proxy')
    if not proxy:
        from reNgine.common_func import get_random_proxy
        proxy = get_random_proxy() or None
    
    if not results_dir:
        logger.error('[CPDE] No results_dir found in context. Aborting.')
        return
        
    activity_heartbeat_safe("Starting parameter intelligence engine")

    # We will use a shared requests Session
    session = requests.Session()
    session.headers['User-Agent'] = 'r3ngine-cpde/1.0'

    # 1. Load JS output from all fetch_url tools
    activity_heartbeat_safe("Collecting JavaScript sources")
    js_urls = js_collector.get_js_urls_from_results_dir(results_dir)
    
    # 2. Download JS files
    activity_heartbeat_safe(f"Downloading {len(js_urls)} JS bundles")
    js_files = js_collector.download_js_files(js_urls, session=session, proxy=proxy)
    
    # 3. Analyze JS AST
    activity_heartbeat_safe(f"Analyzing AST for {len(js_files)} JS files")
    ast_findings = ast_analyzer.extract_from_js_files(js_files)
    
    # 4. Discover OpenAPI — gate on spec presence to avoid GET-probing all paths
    # on targets that serve no API documentation.
    activity_heartbeat_safe("Checking for OpenAPI/Swagger schemas")
    seed_url = urls[0] if urls else None
    if seed_url and has_openapi_spec(seed_url, proxy=proxy):
        activity_heartbeat_safe("Discovering OpenAPI schemas")
        openapi_findings = openapi_discoverer.discover(urls, proxy=proxy)
    else:
        logger.info('[CPDE] No OpenAPI spec reachable at probe paths, skipping OpenAPI discovery')
        openapi_findings = []
    
    # 5. Collect from tool output files (Arjun, ParamSpider, Kiterunner, LinkFinder, URL files)
    activity_heartbeat_safe("Collecting parameters from tool output files")
    tool_file_findings = url_param_collector.collect_all(results_dir)
    logger.info('[CPDE] Tool file collector: %d findings', len(tool_file_findings))

    # 6. Correlate Findings
    activity_heartbeat_safe("Correlating parameter evidence")
    all_findings = ast_findings + openapi_findings + tool_file_findings
    
    # Get user confidence threshold
    cpde_cfg = ctx.get('yaml_configuration', {}).get('param_discovery', {})
    min_confidence = cpde_cfg.get('min_confidence', 50)
    
    correlated_params = correlation_engine.correlate(
        all_findings,
        min_confidence=min_confidence
    )

    # 7. Bulk Persist to DB
    activity_heartbeat_safe(f"Persisting {len(correlated_params)} parameters")
    
    # We need a fallback endpoint if we don't have a specific one for the parameter.
    # In reality, parameters from JS usually don't have a specific endpoint yet, or they 
    # might. Right now ast analyzer doesn't extract endpoint associations, it extracts 
    # parameter names from fetch calls. Openapi provides precise endpoints.
    
    # Let's organize findings.
    # If a finding doesn't have a specific endpoint (e.g. general JS parameter), 
    # we'll attach it to the root endpoint of the target.
    
    domain_id = ctx.get('domain_id')
    domain = Domain.objects.filter(id=domain_id).first() if domain_id else None
    
    if not urls:
        logger.error('[CPDE] No seed URLs provided, cannot determine root endpoint.')
        return
        
    root_url = urls[0]
    # Ensure root endpoint exists
    root_endpoint, _ = save_endpoint(
        root_url,
        ctx=ctx,
        source='CPDE (Root)',
        is_default=True
    )
    
    created_count = 0
    updated_count = 0
    
    # Prepare mapping for neo4j graph writing
    parameter_js_map = []
    endpoint_spec_map = []
    graph_parameters = []
    
    for param in correlated_params:
        # Determine the endpoint for this parameter
        # OpenAPI params have context: "openapi:METHOD:/path"
        # Since we don't fully resolve paths to full URLs here yet (could be complex), 
        # for now we attach to the root endpoint. 
        # Future improvement: parse full endpoints from OpenAPI.
        # JS params also attach to root endpoint as they are global intelligence.
        
        endpoint = root_endpoint
        
        # Save parameter
        db_param, created = save_parameter(
            endpoint=endpoint,
            name=param['name'],
            param_type='js_ast' if param['observed_in_js'] else ('openapi' if param['observed_in_openapi'] else 'cpde'),
            confidence=param['confidence'],
            sources=param['sources'],
            param_location=param['param_location'],
            data_type=param['data_type'],
            is_auth_related=param['is_auth_related'],
            observed_in_js=param['observed_in_js'],
            observed_in_openapi=param['observed_in_openapi'],
            observed_in_graphql=param['observed_in_graphql'],
            scan_history_id=scan_id
        )
        
        if created:
            created_count += 1
        else:
            updated_count += 1
            
        graph_parameters.append({
            'name': param['name'],
            'endpoint_url': endpoint.http_url,
            'confidence': param['confidence'],
            'param_location': param['param_location'],
            'is_auth_related': param['is_auth_related']
        })
        
        # Track for graph mapping
        if param['observed_in_js']:
            for src_url in param.get('source_urls', []):
                parameter_js_map.append({
                    'js_url': src_url,
                    'param_name': param['name'],
                    'endpoint_url': endpoint.http_url
                })
        
        if param['observed_in_openapi']:
            for src_url in param.get('source_urls', []):
                if not any(e['spec_url'] == src_url for e in endpoint_spec_map):
                    endpoint_spec_map.append({
                        'spec_url': src_url,
                        'endpoint_url': endpoint.http_url
                    })

    # Note: GraphQL enrichment is done separately in tasks.py after InQL runs.
    
    logger.info('[CPDE] Persisted %d new, updated %d existing parameters', created_count, updated_count)
    
    # 8. Write to Neo4j graph
    activity_heartbeat_safe("Enriching graph with CPDE findings")
    
    # We need Neo4j driver
    from reNgine.utils.graph import get_neo4j_driver
    driver = get_neo4j_driver()
    if driver and scan_id:
        graph_writer.enrich_parameter_nodes(driver, scan_id, graph_parameters)
        graph_writer.write_js_sources(driver, scan_id, parameter_js_map)
        graph_writer.write_openapi_sources(driver, scan_id, endpoint_spec_map)
        
    activity_heartbeat_safe("Parameter intelligence complete")
    return {
        'js_params': sum(1 for p in correlated_params if p['observed_in_js']),
        'openapi_params': sum(1 for p in correlated_params if p['observed_in_openapi']),
        'correlated_total': len(correlated_params),
        'created': created_count,
        'updated': updated_count
    }
