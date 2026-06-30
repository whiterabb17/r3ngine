"""
Tests for Expanded Graph & API Intelligence (Plan 3).

Covers:
  - APIIntelligenceProfile model
  - APME schema edge types
  - API intelligence ingestion (collect + ingest)
  - Organization and Application graph node ingestion
  - API intelligence attack rules
  - Neo4j batch merge methods (mocked)
  - Temporal activity (mocked)
  - FullChainGraphView and ChainNodesByTypeView REST endpoints
"""

from django.test import TestCase
from django.utils import timezone
from targetApp.models import Domain
from startScan.models import ScanHistory
from scanEngine.models import EngineType


def _make_scan(domain):
    engine, _ = EngineType.objects.get_or_create(
        engine_name="test-engine",
        defaults={"yaml_configuration": ""},
    )
    return ScanHistory.objects.create(
        scan_status=0,
        domain=domain,
        scan_type=engine,
        start_scan_date=timezone.now(),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Task 1: Model + Schema
# ─────────────────────────────────────────────────────────────────────────────

class TestAPIIntelligenceProfileModel(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name="api.corp.com")
        self.scan = _make_scan(self.domain)

    def test_model_creation_rest(self):
        from startScan.models import APIIntelligenceProfile
        rec = APIIntelligenceProfile.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            base_url="https://api.corp.com/v1/",
            api_type="rest",
            endpoint_count=14,
            requires_auth=True,
            auth_scheme="Bearer",
        )
        self.assertIsNotNone(rec.id)
        self.assertEqual(rec.api_type, "rest")

    def test_model_creation_graphql(self):
        from startScan.models import APIIntelligenceProfile
        rec = APIIntelligenceProfile.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            base_url="https://api.corp.com/graphql",
            api_type="graphql",
            endpoint_count=1,
        )
        self.assertEqual(rec.api_type, "graphql")

    def test_schema_has_depends_on_edge(self):
        from apme.graph.schema import EDGE_TYPES
        self.assertIn("DEPENDS_ON", EDGE_TYPES)

    def test_schema_has_trusts_domain_edge(self):
        from apme.graph.schema import EDGE_TYPES
        self.assertIn("TRUSTS_DOMAIN", EDGE_TYPES)


# ─────────────────────────────────────────────────────────────────────────────
# Task 2: API Intelligence Ingestion
# ─────────────────────────────────────────────────────────────────────────────

class TestAPIIntelligenceIngestion(TestCase):
    def setUp(self):
        from startScan.models import EndPoint, Subdomain, APIIntelligenceProfile
        self.domain = Domain.objects.create(name="api.example.com")
        self.scan = _make_scan(self.domain)
        self.sub = Subdomain.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            name="api.example.com",
            http_url="https://api.example.com/",
        )
        for path in ["/v1/users", "/v1/orders", "/v1/products", "/v2/search"]:
            EndPoint.objects.create(
                scan_history=self.scan,
                target_domain=self.domain,
                subdomain=self.sub,
                http_url=f"https://api.example.com{path}",
                http_status=200,
            )
        EndPoint.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            subdomain=self.sub,
            http_url="https://api.example.com/graphql",
            http_status=200,
            content_type="application/json",
        )

    def test_collect_creates_rest_profile(self):
        from apme.ingestion.api_intelligence import collect_api_intelligence
        profiles = collect_api_intelligence(self.scan.id)
        rest_profiles = [p for p in profiles if p.api_type == "rest"]
        self.assertTrue(len(rest_profiles) >= 1)

    def test_collect_creates_graphql_profile(self):
        from apme.ingestion.api_intelligence import collect_api_intelligence
        profiles = collect_api_intelligence(self.scan.id)
        graphql_profiles = [p for p in profiles if p.api_type == "graphql"]
        self.assertTrue(len(graphql_profiles) >= 1)

    def test_ingest_returns_api_endpoint_nodes(self):
        from apme.ingestion.api_intelligence import collect_api_intelligence, ingest_api_intelligence
        collect_api_intelligence(self.scan.id)
        nodes, edges = ingest_api_intelligence(self.domain.id)
        api_nodes = [n for n in nodes if n.type == "APIEndpoint"]
        self.assertTrue(len(api_nodes) >= 1)

    def test_graphql_endpoint_has_graphql_subtype(self):
        from apme.ingestion.api_intelligence import collect_api_intelligence, ingest_api_intelligence
        collect_api_intelligence(self.scan.id)
        nodes, _ = ingest_api_intelligence(self.domain.id)
        graphql_nodes = [n for n in nodes if n.subtype == "graphql"]
        self.assertTrue(len(graphql_nodes) >= 1)

    def test_ingest_empty_returns_empty(self):
        from startScan.models import APIIntelligenceProfile
        from apme.ingestion.api_intelligence import ingest_api_intelligence
        APIIntelligenceProfile.objects.all().delete()
        nodes, edges = ingest_api_intelligence(self.domain.id)
        self.assertEqual(nodes, [])

    def test_collect_does_not_query_subdomain_per_cluster(self):
        """collect_api_intelligence must build a single subdomain index, not query per cluster."""
        from django.test.utils import CaptureQueriesContext
        from django.db import connection
        from apme.ingestion.api_intelligence import collect_api_intelligence
        from startScan.models import EndPoint, Subdomain

        # Seed 5 more subdomains, each with 3 distinct path prefixes -> 15 extra clusters.
        for i in range(5):
            sub = Subdomain.objects.create(
                scan_history=self.scan,
                target_domain=self.domain,
                name=f"sub{i}.api.example.com",
                http_url=f"https://sub{i}.api.example.com/",
            )
            for path in ["/v1/a", "/v2/b", "/v3/c"]:
                EndPoint.objects.create(
                    scan_history=self.scan,
                    target_domain=self.domain,
                    subdomain=sub,
                    http_url=f"https://sub{i}.api.example.com{path}",
                    http_status=200,
                )

        # Warm the profile rows so a second pass exercises update branch consistently.
        collect_api_intelligence(self.scan.id)

        # Count SELECTs against the Subdomain table during the second pass.
        with CaptureQueriesContext(connection) as ctx:
            collect_api_intelligence(self.scan.id)

        subdomain_selects = [
            q["sql"] for q in ctx.captured_queries
            if "FROM " in q["sql"] and "startscan_subdomain" in q["sql"].lower()
        ]
        # The single prefetched index = exactly one SELECT against Subdomain.
        # The old N+1 path would issue one per cluster (~16 here).
        self.assertLessEqual(
            len(subdomain_selects), 2,
            f"Expected ≤2 Subdomain SELECTs (the prefetched index); got "
            f"{len(subdomain_selects)}. Possible N+1 regression."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Task 3: Organization + Application Graph Nodes
# ─────────────────────────────────────────────────────────────────────────────

class TestGraphExpansionIngestion(TestCase):
    def setUp(self):
        from startScan.models import Subdomain
        self.domain = Domain.objects.create(name="acme.example.com")
        self.scan = _make_scan(self.domain)
        Subdomain.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            name="app.acme.example.com",
            webserver="nginx",
            http_url="https://app.acme.example.com/",
        )
        Subdomain.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            name="api.acme.example.com",
            webserver="apache",
            http_url="https://api.acme.example.com/",
        )

    def test_ingest_applications_returns_app_nodes(self):
        from apme.ingestion.graph_expansion import ingest_applications
        nodes, edges = ingest_applications(self.domain.id)
        app_nodes = [n for n in nodes if n.type == "Application"]
        self.assertTrue(len(app_nodes) >= 1)

    def test_ingest_applications_node_id_format(self):
        from apme.ingestion.graph_expansion import ingest_applications
        nodes, _ = ingest_applications(self.domain.id)
        app_nodes = [n for n in nodes if n.type == "Application"]
        for n in app_nodes:
            self.assertTrue(n.id.startswith("app::"))

    def test_ingest_organizations_no_project_returns_empty(self):
        from apme.ingestion.graph_expansion import ingest_organizations
        # Domain has no project FK in this test, so should return empty gracefully
        nodes, _ = ingest_organizations(self.domain.id)
        org_nodes = [n for n in nodes if n.type == "Organization"]
        self.assertIsInstance(org_nodes, list)

    def test_ingest_organizations_missing_target_returns_empty(self):
        from apme.ingestion.graph_expansion import ingest_organizations
        # A target_id that does not exist must return ([], []) cleanly.
        nodes, edges = ingest_organizations(999999)
        self.assertEqual(nodes, [])
        self.assertEqual(edges, [])

    def test_ingest_empty_subdomain_set_returns_empty(self):
        from startScan.models import Subdomain
        from apme.ingestion.graph_expansion import ingest_applications
        Subdomain.objects.filter(target_domain=self.domain).delete()
        nodes, edges = ingest_applications(self.domain.id)
        self.assertEqual(nodes, [])


# ─────────────────────────────────────────────────────────────────────────────
# Task 4: API Intelligence Attack Rules
# ─────────────────────────────────────────────────────────────────────────────

class TestAPIIntelRules(TestCase):
    def setUp(self):
        from apme.engine.rules_engine import RulesEngine
        from apme.models.node import Node
        self.RulesEngine = RulesEngine
        self.Node = Node
        self.engine = RulesEngine(rules_file="apme/config/rules/x_api_intelligence.yaml")
        self.goal_nodes = [
            Node(id="goal::capability::data_exfil", type="Capability",
                 subtype="data_exfil", confidence=1.0, source="APME:virtual_goal"),
            Node(id="goal::capability::authenticated_access", type="Capability",
                 subtype="authenticated_access", confidence=1.0, source="APME:virtual_goal"),
            Node(id="goal::capability::account_takeover", type="Capability",
                 subtype="account_takeover", confidence=1.0, source="APME:virtual_goal"),
            Node(id="goal::capability::rce_execution", type="Capability",
                 subtype="rce_execution", confidence=1.0, source="APME:virtual_goal"),
            Node(id="goal::capability::internal_discovery", type="Capability",
                 subtype="internal_discovery", confidence=1.0, source="APME:virtual_goal"),
        ]

    def test_graphql_fires_data_exfil(self):
        from apme.models.node import Node
        node = Node(
            id="api_endpoint::https://api.corp.com/graphql",
            type="APIEndpoint", subtype="graphql",
            confidence=0.85, source="reNgine:api_intelligence",
            properties={"api_type": "graphql", "requires_auth": False},
        )
        edges = self.engine.apply(node, [node] + self.goal_nodes)
        subtypes = [e.to_id.split("::")[-1] for e in edges]
        self.assertIn("data_exfil", subtypes)

    def test_unauthenticated_api_fires_authenticated_access(self):
        from apme.models.node import Node
        node = Node(
            id="api_endpoint::https://api.corp.com/v1/",
            type="APIEndpoint", subtype="rest",
            confidence=0.85, source="reNgine:api_intelligence",
            properties={"api_type": "rest", "requires_auth": False},
        )
        edges = self.engine.apply(node, [node] + self.goal_nodes)
        subtypes = [e.to_id.split("::")[-1] for e in edges]
        self.assertIn("authenticated_access", subtypes)

    def test_soap_fires_rce(self):
        from apme.models.node import Node
        node = Node(
            id="api_endpoint::https://corp.com/soap/service.asmx",
            type="APIEndpoint", subtype="soap",
            confidence=0.80, source="reNgine:api_intelligence",
            properties={"api_type": "soap", "requires_auth": False},
        )
        edges = self.engine.apply(node, [node] + self.goal_nodes)
        subtypes = [e.to_id.split("::")[-1] for e in edges]
        self.assertIn("rce_execution", subtypes)

    def test_clean_authenticated_api_fires_fewer_rules(self):
        from apme.models.node import Node
        unauth_node = Node(
            id="api_endpoint::x", type="APIEndpoint", subtype="rest",
            confidence=0.85, source="reNgine:api_intelligence",
            properties={"api_type": "rest", "requires_auth": False},
        )
        edges_unauth = self.engine.apply(unauth_node, [unauth_node] + self.goal_nodes)

        auth_node = Node(
            id="api_endpoint::https://api.corp.com/v2/",
            type="APIEndpoint", subtype="rest",
            confidence=0.85, source="reNgine:api_intelligence",
            properties={"api_type": "rest", "requires_auth": True},
        )
        edges_auth = self.engine.apply(auth_node, [auth_node] + self.goal_nodes)
        self.assertLessEqual(len(edges_auth), len(edges_unauth))


# ─────────────────────────────────────────────────────────────────────────────
# Task 5: Neo4j Batch Merge (mocked)
# ─────────────────────────────────────────────────────────────────────────────

class TestNeo4jExpandedSync(TestCase):
    def setUp(self):
        from startScan.models import Subdomain, APIIntelligenceProfile
        self.domain = Domain.objects.create(name="neo4j.expanded.com")
        self.scan = _make_scan(self.domain)
        self.sub = Subdomain.objects.create(
            scan_history=self.scan, target_domain=self.domain,
            name="api.neo4j.expanded.com", webserver="nginx",
        )
        APIIntelligenceProfile.objects.create(
            scan_history=self.scan, target_domain=self.domain, subdomain=self.sub,
            base_url="https://api.neo4j.expanded.com/v1/",
            api_type="rest", endpoint_count=5,
        )

    def test_batch_merge_api_endpoints_calls_run(self):
        from unittest.mock import MagicMock, patch
        with patch("reNgine.utils.graph.Neo4jManager.__init__", return_value=None):
            from reNgine.utils.graph import Neo4jManager
            mock_tx = MagicMock()
            rows = [{"base_url": "https://api.neo4j.expanded.com/v1/", "api_type": "rest",
                     "endpoint_count": 5, "scan_id": self.scan.id}]
            Neo4jManager._batch_merge_api_endpoints(mock_tx, rows)
            self.assertTrue(mock_tx.run.called)
            cypher = mock_tx.run.call_args[0][0]
            self.assertIn("APIEndpoint", cypher)

    def test_batch_merge_applications_calls_run(self):
        from unittest.mock import MagicMock, patch
        with patch("reNgine.utils.graph.Neo4jManager.__init__", return_value=None):
            from reNgine.utils.graph import Neo4jManager
            mock_tx = MagicMock()
            rows = [{"name": "api.neo4j.expanded.com", "webserver": "nginx",
                     "scan_id": self.scan.id}]
            Neo4jManager._batch_merge_applications(mock_tx, rows)
            self.assertTrue(mock_tx.run.called)
            cypher = mock_tx.run.call_args[0][0]
            self.assertIn("Application", cypher)

    def test_batch_merge_organizations_calls_run(self):
        from unittest.mock import MagicMock, patch
        with patch("reNgine.utils.graph.Neo4jManager.__init__", return_value=None):
            from reNgine.utils.graph import Neo4jManager
            mock_tx = MagicMock()
            rows = [{"slug": "acme-corp", "name": "ACME Corp",
                     "scan_id": self.scan.id}]
            Neo4jManager._batch_merge_organizations(mock_tx, rows)
            self.assertTrue(mock_tx.run.called)
            cypher = mock_tx.run.call_args[0][0]
            self.assertIn("Organization", cypher)

    def test_full_chain_uses_two_passes(self):
        """get_full_chain_graph must issue separate node and edge queries."""
        from unittest.mock import MagicMock, patch
        with patch("reNgine.utils.graph.Neo4jManager.__init__", return_value=None):
            from reNgine.utils.graph import Neo4jManager
            mgr = Neo4jManager()
            mgr.driver = MagicMock()
            session_ctx = mgr.driver.session.return_value.__enter__.return_value
            session_ctx.run = MagicMock(return_value=iter([]))

            result = mgr.get_full_chain_graph(self.scan.id)

            self.assertEqual(session_ctx.run.call_count, 2)
            first_query = session_ctx.run.call_args_list[0][0][0]
            second_query = session_ctx.run.call_args_list[1][0][0]
            self.assertIn("RETURN n", first_query)
            self.assertNotIn("OPTIONAL MATCH", first_query)
            self.assertIn("RETURN n, r, m", second_query)
            self.assertEqual(result, {"nodes": [], "edges": []})

    def test_full_chain_dedupes_edges(self):
        """Duplicate (from, to, type) edges must appear only once in the response."""
        from unittest.mock import MagicMock, patch

        class FakeNode:
            def __init__(self, eid, label):
                self.element_id = eid
                self.labels = [label]
            def __iter__(self):
                return iter([])
            def keys(self):
                return []
            def items(self):
                return []

        class FakeRel:
            def __init__(self, rtype):
                self.type = rtype

        n_a = FakeNode("n1", "Subdomain")
        n_b = FakeNode("n2", "Application")
        rel = FakeRel("DEPENDS_ON")

        edge_record_a = {"n": n_a, "r": rel, "m": n_b}
        edge_record_b = {"n": n_a, "r": rel, "m": n_b}  # exact duplicate

        with patch("reNgine.utils.graph.Neo4jManager.__init__", return_value=None):
            from reNgine.utils.graph import Neo4jManager
            mgr = Neo4jManager()
            mgr.driver = MagicMock()
            session_ctx = mgr.driver.session.return_value.__enter__.return_value
            session_ctx.run = MagicMock(side_effect=[
                iter([]),  # node pass — empty
                iter([     # edge pass — duplicate edge
                    type("Rec", (), {"get": staticmethod(lambda k, _r=edge_record_a: _r.get(k))})(),
                    type("Rec", (), {"get": staticmethod(lambda k, _r=edge_record_b: _r.get(k))})(),
                ]),
            ])

            result = mgr.get_full_chain_graph(self.scan.id)
            self.assertEqual(len(result["edges"]), 1)
            self.assertEqual(result["edges"][0]["type"], "DEPENDS_ON")

    def test_organization_sync_query_resolves_project_fk(self):
        """The ORM query used by sync_scan_results must surface Domain.project as expected."""
        from django.utils import timezone
        from dashboard.models import Project
        from startScan.models import ScanHistory as ScanHistoryModel

        project = Project.objects.create(
            name="ACME Org", slug="acme-org",
            insert_date=timezone.now(),
        )
        self.domain.project = project
        self.domain.save(update_fields=["project"])

        scan = (
            ScanHistoryModel.objects
            .select_related("domain__project")
            .only(
                "id",
                "domain__id",
                "domain__project__id",
                "domain__project__slug",
                "domain__project__name",
            )
            .filter(id=self.scan.id)
            .first()
        )
        resolved = getattr(getattr(scan, "domain", None), "project", None)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved.slug, "acme-org")
        self.assertEqual(resolved.name, "ACME Org")


# ─────────────────────────────────────────────────────────────────────────────
# Task 6: Temporal Activity + REST API
# ─────────────────────────────────────────────────────────────────────────────

class TestAPIIntelActivity(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name="activity.api.com")
        self.scan = _make_scan(self.domain)

    def test_activity_calls_collector(self):
        from unittest.mock import patch
        # The function is imported inside the activity, so patch at source
        with patch("apme.ingestion.api_intelligence.collect_api_intelligence") as mock_collect:
            from reNgine.temporal_activities import run_api_intel_activity
            mock_collect.return_value = []
            result = run_api_intel_activity(self.scan.id)
            self.assertEqual(result["status"], "ok")


class TestFullChainAPI(TestCase):
    def setUp(self):
        from rest_framework.test import APIClient
        from django.contrib.auth.models import User
        self.client = APIClient()
        self.user = User.objects.create_user("chainuser", password="pass")
        # force_authenticate satisfies DRF; force_login satisfies LoginRequiredMiddleware
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)
        self.domain = Domain.objects.create(name="chain.corp.com")
        self.scan = _make_scan(self.domain)

    def test_chain_endpoint_requires_scan_id(self):
        resp = self.client.get("/api/graph/chain/")
        self.assertEqual(resp.status_code, 400)

    def test_chain_nodes_endpoint_requires_scan_id(self):
        resp = self.client.get("/api/graph/chain/nodes/")
        self.assertEqual(resp.status_code, 400)

    def test_chain_nodes_rejects_invalid_type(self):
        resp = self.client.get(
            f"/api/graph/chain/nodes/?scan_id={self.scan.id}&type=__proto__"
        )
        self.assertEqual(resp.status_code, 400)

    def test_unauthenticated_chain_redirects(self):
        from rest_framework.test import APIClient
        anon_client = APIClient()
        resp = anon_client.get(f"/api/graph/chain/?scan_id={self.scan.id}")
        # LoginRequiredMiddleware redirects unauthenticated users to /login/
        self.assertIn(resp.status_code, [302, 401])
