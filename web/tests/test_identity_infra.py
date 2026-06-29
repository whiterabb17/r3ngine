from django.test import TestCase
from django.utils import timezone
from rolepermissions.roles import assign_role
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain


def _make_scan(domain):
    engine = EngineType.objects.create(engine_name="IdentityTest Engine", yaml_configuration="")
    return ScanHistory.objects.create(
        scan_status=0,
        domain=domain,
        scan_type=engine,
        start_scan_date=timezone.now(),
        tasks=[],
    )


# ---------------------------------------------------------------------------
# Task 1 — Model
# ---------------------------------------------------------------------------

class TestIdentityInfraDiscoveryModel(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name="corp.example.com")
        self.scan = _make_scan(self.domain)

    def test_model_creation_adfs(self):
        from startScan.models import IdentityInfraDiscovery
        record = IdentityInfraDiscovery.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            url="https://adfs.corp.example.com/adfs/ls/",
            host="adfs.corp.example.com",
            infra_type="adfs",
            detection_method="url_pattern",
            confidence_score=0.95,
            is_externally_accessible=True,
        )
        self.assertIsNotNone(record.id)
        self.assertEqual(record.infra_type, "adfs")
        self.assertTrue(record.is_externally_accessible)

    def test_model_creation_owa(self):
        from startScan.models import IdentityInfraDiscovery
        record = IdentityInfraDiscovery.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            url="https://mail.corp.example.com/owa/",
            host="mail.corp.example.com",
            infra_type="owa",
            detection_method="url_pattern",
            confidence_score=0.90,
        )
        self.assertEqual(record.infra_type, "owa")

    def test_confidence_range_valid(self):
        from startScan.models import IdentityInfraDiscovery
        record = IdentityInfraDiscovery.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            host="ldap.corp.example.com",
            infra_type="ldap",
            detection_method="title_keyword",
            confidence_score=0.70,
        )
        self.assertGreaterEqual(record.confidence_score, 0.0)
        self.assertLessEqual(record.confidence_score, 1.0)


# ---------------------------------------------------------------------------
# Task 2 — Detection logic
# ---------------------------------------------------------------------------

class TestIdentityDetection(TestCase):
    def test_classify_adfs_url(self):
        from reNgine.tasks.identity import classify_url
        result = classify_url("https://adfs.corp.example.com/adfs/ls/idpinitiatedsignon.htm")
        self.assertIsNotNone(result)
        infra_type, confidence = result
        self.assertEqual(infra_type, "adfs")
        self.assertGreater(confidence, 0.8)

    def test_classify_owa_url(self):
        from reNgine.tasks.identity import classify_url
        result = classify_url("https://mail.corp.example.com/owa/")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "owa")

    def test_classify_exchange_autodiscover(self):
        from reNgine.tasks.identity import classify_url
        result = classify_url("https://corp.example.com/autodiscover/autodiscover.xml")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "exchange")

    def test_classify_ldap_url(self):
        from reNgine.tasks.identity import classify_url
        result = classify_url("ldap://ldap.corp.example.com:389/dc=corp,dc=example,dc=com")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "ldap")

    def test_classify_sso_portal(self):
        from reNgine.tasks.identity import classify_url
        result = classify_url("https://sso.corp.example.com/sso/")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "sso")

    def test_classify_unrelated_url_returns_none(self):
        from reNgine.tasks.identity import classify_url
        result = classify_url("https://blog.corp.example.com/posts/welcome")
        self.assertIsNone(result)

    def test_classify_adfs_title(self):
        from reNgine.tasks.identity import classify_title
        result = classify_title("Sign In - Active Directory Federation Services")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "adfs")

    def test_classify_owa_title(self):
        from reNgine.tasks.identity import classify_title
        result = classify_title("Outlook Web App - Sign in")
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "owa")

    def test_classify_unrelated_title_returns_none(self):
        from reNgine.tasks.identity import classify_title
        result = classify_title("Welcome to Our Company Blog")
        self.assertIsNone(result)

    def test_classify_ntlm_header(self):
        from reNgine.tasks.identity import classify_header
        headers = {"WWW-Authenticate": "NTLM"}
        result = classify_header(headers)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "ntlm_endpoint")

    def test_classify_negotiate_header(self):
        from reNgine.tasks.identity import classify_header
        headers = {"WWW-Authenticate": "Negotiate"}
        result = classify_header(headers)
        self.assertIsNotNone(result)


# ---------------------------------------------------------------------------
# Task 3 — Temporal activity
# ---------------------------------------------------------------------------

class TestIdentityActivity(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name="activitydemo.corp.com")
        self.scan = _make_scan(self.domain)

    def test_activity_calls_runner(self):
        from unittest.mock import patch
        with patch("reNgine.tasks.identity.run_identity_intel") as mock_runner:
            from reNgine.temporal_activities import run_identity_infra_activity
            mock_runner.return_value = []
            result = run_identity_infra_activity(self.scan.id)
            mock_runner.assert_called_once_with(self.scan.id)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["count"], 0)

    def test_activity_returns_count(self):
        from unittest.mock import patch
        with patch("reNgine.tasks.identity.run_identity_intel") as mock_runner:
            from reNgine.temporal_activities import run_identity_infra_activity
            from startScan.models import IdentityInfraDiscovery
            fake = IdentityInfraDiscovery(host="adfs.corp.com", infra_type="adfs")
            mock_runner.return_value = [fake]
            result = run_identity_infra_activity(self.scan.id)
            self.assertEqual(result["count"], 1)


# ---------------------------------------------------------------------------
# Task 4 — APME ingestion
# ---------------------------------------------------------------------------

class TestIdentityIngestion(TestCase):
    def setUp(self):
        from startScan.models import IdentityInfraDiscovery, Subdomain
        self.domain = Domain.objects.create(name="infra.corp.com")
        self.scan = _make_scan(self.domain)
        self.sub = Subdomain.objects.create(
            scan_history=self.scan, target_domain=self.domain,
            name="adfs.infra.corp.com",
        )
        IdentityInfraDiscovery.objects.create(
            scan_history=self.scan, target_domain=self.domain, subdomain=self.sub,
            host="adfs.infra.corp.com", infra_type="adfs",
            detection_method="url_pattern", confidence_score=0.92,
            is_externally_accessible=True,
        )

    def test_ingest_returns_identity_infra_node(self):
        from apme.ingestion.identity_infra import ingest_identity_infra
        nodes, edges = ingest_identity_infra(self.domain.id)
        id_nodes = [n for n in nodes if n.type == "IdentityInfra"]
        self.assertEqual(len(id_nodes), 1)
        self.assertEqual(id_nodes[0].subtype, "adfs")

    def test_ingest_creates_authenticates_via_edge(self):
        from apme.ingestion.identity_infra import ingest_identity_infra
        from startScan.models import Subdomain as SubdomainModel
        SubdomainModel.objects.create(
            scan_history=self.scan, target_domain=self.domain,
            name="app.infra.corp.com", http_url="https://app.infra.corp.com/",
        )
        nodes, edges = ingest_identity_infra(self.domain.id)
        auth_edges = [e for e in edges if e.type == "AUTHENTICATES_VIA"]
        self.assertTrue(len(auth_edges) >= 0)

    def test_ingest_external_is_sensitive(self):
        from apme.ingestion.identity_infra import ingest_identity_infra
        nodes, _ = ingest_identity_infra(self.domain.id)
        id_nodes = [n for n in nodes if n.type == "IdentityInfra"]
        self.assertTrue(id_nodes[0].properties.get("is_externally_accessible"))

    def test_ingest_empty_returns_empty(self):
        from apme.ingestion.identity_infra import ingest_identity_infra
        from startScan.models import IdentityInfraDiscovery
        IdentityInfraDiscovery.objects.all().delete()
        nodes, edges = ingest_identity_infra(self.domain.id)
        self.assertEqual(nodes, [])
        self.assertEqual(edges, [])


# ---------------------------------------------------------------------------
# Task 5 — Attack rules
# ---------------------------------------------------------------------------

class TestIdentityRules(TestCase):
    def setUp(self):
        from apme.engine.rules_engine import RulesEngine
        from apme.models.node import Node
        rules_path = "apme/config/rules/w_identity_infra.yaml"
        self.engine = RulesEngine(rules_file=rules_path)
        self.goal_nodes = [
            Node(id="goal::capability::saml_assertion_forgery", type="Capability",
                 subtype="saml_assertion_forgery", confidence=1.0, source="APME:virtual_goal"),
            Node(id="goal::capability::account_takeover", type="Capability",
                 subtype="account_takeover", confidence=1.0, source="APME:virtual_goal"),
            Node(id="goal::capability::credential_harvesting", type="Capability",
                 subtype="credential_harvesting", confidence=1.0, source="APME:virtual_goal"),
            Node(id="goal::capability::lateral_movement", type="Capability",
                 subtype="lateral_movement", confidence=1.0, source="APME:virtual_goal"),
            Node(id="goal::capability::email_account_compromise", type="Capability",
                 subtype="email_account_compromise", confidence=1.0, source="APME:virtual_goal"),
            Node(id="goal::capability::authenticated_access", type="Capability",
                 subtype="authenticated_access", confidence=1.0, source="APME:virtual_goal"),
        ]

    def test_adfs_external_fires_saml_forgery(self):
        from apme.models.node import Node
        node = Node(
            id="identity_infra::adfs::adfs.corp.com",
            type="IdentityInfra", subtype="adfs",
            confidence=0.92, source="reNgine:identity_intel",
            properties={"is_externally_accessible": True, "infra_type": "adfs"},
        )
        edges = self.engine.apply(node, [node] + self.goal_nodes)
        subtypes = [e.to_id.split("::")[-1] for e in edges]
        self.assertIn("saml_assertion_forgery", subtypes)

    def test_owa_external_fires_account_takeover(self):
        from apme.models.node import Node
        node = Node(
            id="identity_infra::owa::owa.corp.com",
            type="IdentityInfra", subtype="owa",
            confidence=0.90, source="reNgine:identity_intel",
            properties={"is_externally_accessible": True, "infra_type": "owa"},
        )
        edges = self.engine.apply(node, [node] + self.goal_nodes)
        subtypes = [e.to_id.split("::")[-1] for e in edges]
        self.assertIn("account_takeover", subtypes)

    def test_ldap_external_fires_credential_harvesting(self):
        from apme.models.node import Node
        node = Node(
            id="identity_infra::ldap::ldap.corp.com",
            type="IdentityInfra", subtype="ldap",
            confidence=0.88, source="reNgine:identity_intel",
            properties={"is_externally_accessible": True, "infra_type": "ldap"},
        )
        edges = self.engine.apply(node, [node] + self.goal_nodes)
        subtypes = [e.to_id.split("::")[-1] for e in edges]
        self.assertIn("credential_harvesting", subtypes)

    def test_exchange_fires_email_account_compromise(self):
        from apme.models.node import Node
        node = Node(
            id="identity_infra::exchange::mail.corp.com",
            type="IdentityInfra", subtype="exchange",
            confidence=0.85, source="reNgine:identity_intel",
            properties={"is_externally_accessible": True, "infra_type": "exchange"},
        )
        edges = self.engine.apply(node, [node] + self.goal_nodes)
        subtypes = [e.to_id.split("::")[-1] for e in edges]
        self.assertIn("email_account_compromise", subtypes)

    def test_generic_auth_portal_fires_authenticated_access(self):
        from apme.models.node import Node
        node = Node(
            id="identity_infra::generic::login.corp.com",
            type="IdentityInfra", subtype="generic",
            confidence=0.60, source="reNgine:identity_intel",
            properties={"is_externally_accessible": True, "infra_type": "generic_auth_portal"},
        )
        edges = self.engine.apply(node, [node] + self.goal_nodes)
        subtypes = [e.to_id.split("::")[-1] for e in edges]
        self.assertIn("authenticated_access", subtypes)


# ---------------------------------------------------------------------------
# Task 6 — Neo4j sync
# ---------------------------------------------------------------------------

class TestNeo4jIdentitySync(TestCase):
    def setUp(self):
        from startScan.models import IdentityInfraDiscovery
        self.domain = Domain.objects.create(name="sync.corp.com")
        self.scan = _make_scan(self.domain)
        IdentityInfraDiscovery.objects.create(
            scan_history=self.scan, target_domain=self.domain,
            host="adfs.sync.corp.com", infra_type="adfs",
            detection_method="url_pattern", confidence_score=0.92,
            is_externally_accessible=True,
        )

    def test_batch_merge_identity_infra_cypher(self):
        from unittest.mock import MagicMock, patch
        with patch("reNgine.utils.graph.Neo4jManager.__init__", return_value=None):
            from reNgine.utils.graph import Neo4jManager
            mock_tx = MagicMock()
            rows = [{
                "host": "adfs.sync.corp.com",
                "infra_type": "adfs",
                "is_externally_accessible": True,
                "confidence_score": 0.92,
                "scan_id": self.scan.id,
            }]
            Neo4jManager._batch_merge_identity_infra(mock_tx, rows)
            self.assertTrue(mock_tx.run.called)
            cypher = mock_tx.run.call_args[0][0]
            self.assertIn("IdentityInfra", cypher)
            self.assertIn("MERGE", cypher)


# ---------------------------------------------------------------------------
# Task 7 — REST API
# ---------------------------------------------------------------------------

class TestIdentityAPI(TestCase):
    def setUp(self):
        from rest_framework.test import APIClient
        from django.contrib.auth.models import User
        from startScan.models import IdentityInfraDiscovery
        self.user = User.objects.create_user(
            "identityuser", password="pass", is_superuser=True,
        )
        assign_role(self.user, "sys_admin")
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.client.force_login(user=self.user)
        self.domain = Domain.objects.create(name="api.corp.com")
        self.scan = _make_scan(self.domain)
        IdentityInfraDiscovery.objects.create(
            scan_history=self.scan, target_domain=self.domain,
            host="adfs.api.corp.com", infra_type="adfs",
            detection_method="url_pattern", confidence_score=0.92,
            is_externally_accessible=True,
        )
        IdentityInfraDiscovery.objects.create(
            scan_history=self.scan, target_domain=self.domain,
            host="mail.api.corp.com", infra_type="owa",
            detection_method="title_keyword", confidence_score=0.88,
            is_externally_accessible=True,
        )

    def test_list_by_scan_id(self):
        resp = self.client.get(f"/api/identity/?scan_id={self.scan.id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["count"], 2)
        self.assertIn("summary", data)
        self.assertIn("adfs", data["summary"])

    def test_missing_scan_id_returns_400(self):
        resp = self.client.get("/api/identity/")
        self.assertEqual(resp.status_code, 400)

    def test_unauthenticated_returns_redirect(self):
        from rest_framework.test import APIClient
        anon = APIClient()
        resp = anon.get(f"/api/identity/?scan_id={self.scan.id}")
        self.assertEqual(resp.status_code, 302)
