"""
CPDE (Custom Parameter Discovery Engine) — core sub-package.

This package provides pure-Python business logic for intelligence-based
parameter and route discovery. It does not define any Django models or run
any DB migrations; it is a library consumed by cpde_tasks.py.

Modules
-------
js_collector         Download JS files from Katana output and deduplicate by hash.
ast_analyzer         Parse JS AST (esprima-python) to extract fetch/axios/FormData params.
openapi_discoverer   Probe common schema paths and parse OpenAPI 2/3 specs.
graphql_enricher     Parse InQL output dirs to persist GraphQL variables as Parameters.
correlation_engine   Normalize names, merge sources, compute confidence scores.
graph_writer         Write CPDE-specific Neo4j nodes and relationships.
url_param_collector  Read tool output files (Arjun/ParamSpider/Kiterunner/LinkFinder/URLs)
                     and extract parameter findings for the correlation pipeline.
"""
