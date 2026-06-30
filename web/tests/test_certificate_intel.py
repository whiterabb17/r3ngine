from django.test import TestCase
from django.utils import timezone
from rolepermissions.roles import assign_role
from scanEngine.models import EngineType
from startScan.models import CertificateIntelligence, ScanHistory
from targetApp.models import Domain


def _make_scan(domain):
    engine = EngineType.objects.create(engine_name="CertTest Engine", yaml_configuration="")
    return ScanHistory.objects.create(
        scan_status=0,
        domain=domain,
        scan_type=engine,
        start_scan_date=timezone.now(),
        tasks=[],
    )


class TestCertificateIntelligenceModel(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name="test.example.com")
        self.scan = _make_scan(self.domain)

    def test_model_creation(self):
        cert = CertificateIntelligence.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            host="test.example.com",
            port=443,
            subject_cn="test.example.com",
            subject_an=["test.example.com", "www.test.example.com"],
            issuer_cn="R3",
            issuer_org="Let's Encrypt",
            tls_version="tls13",
            cipher="TLS_AES_256_GCM_SHA384",
            fingerprint_sha256="aabbcc112233",
            self_signed=False,
            has_weak_cipher=False,
            is_expired=False,
        )
        self.assertIsNotNone(cert.id)

    def test_is_expired_flag(self):
        from django.utils import timezone
        import datetime
        cert = CertificateIntelligence.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            host="expired.example.com",
            port=443,
            not_after=timezone.now() - datetime.timedelta(days=10),
            fingerprint_sha256="expired001",
            is_expired=True,
        )
        self.assertTrue(cert.is_expired)

    def test_weak_cipher_flag(self):
        cert = CertificateIntelligence.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            host="weak.example.com",
            port=443,
            cipher="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            fingerprint_sha256="weak001",
            has_weak_cipher=True,
        )
        self.assertTrue(cert.has_weak_cipher)


class TestCertificateParser(TestCase):
    def test_parse_valid_tlsx_json_line(self):
        from reNgine.tasks.certificate import parse_tlsx_json_line
        line = (
            '{"host":"example.com","ip":"1.2.3.4","port":443,'
            '"tls_version":"tls13","cipher":"TLS_AES_256_GCM_SHA384",'
            '"not_before":"2024-01-01T00:00:00Z","not_after":"2025-01-01T00:00:00Z",'
            '"subject_cn":"example.com","subject_an":["example.com","www.example.com"],'
            '"issuer_cn":"R3","issuer_org":["Let\'s Encrypt"],'
            '"fingerprint_hash":{"sha256":"aabbccdd"},'
            '"self_signed":false,"mismatched":false}'
        )
        result = parse_tlsx_json_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["host"], "example.com")
        self.assertEqual(result["subject_cn"], "example.com")
        self.assertEqual(result["fingerprint_sha256"], "aabbccdd")
        self.assertFalse(result["self_signed"])

    def test_parse_invalid_json_returns_none(self):
        from reNgine.tasks.certificate import parse_tlsx_json_line
        result = parse_tlsx_json_line("not json at all")
        self.assertIsNone(result)

    def test_parse_empty_line_returns_none(self):
        from reNgine.tasks.certificate import parse_tlsx_json_line
        result = parse_tlsx_json_line("")
        self.assertIsNone(result)

    def test_is_weak_cipher_rc4(self):
        from reNgine.tasks.certificate import is_weak_cipher
        self.assertTrue(is_weak_cipher("TLS_RSA_WITH_RC4_128_SHA"))

    def test_is_weak_cipher_3des(self):
        from reNgine.tasks.certificate import is_weak_cipher
        self.assertTrue(is_weak_cipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA"))

    def test_is_strong_cipher(self):
        from reNgine.tasks.certificate import is_weak_cipher
        self.assertFalse(is_weak_cipher("TLS_AES_256_GCM_SHA384"))

    def test_is_weak_cipher_null(self):
        from reNgine.tasks.certificate import is_weak_cipher
        self.assertTrue(is_weak_cipher("TLS_NULL_WITH_NULL_NULL"))


class TestCertificateActivity(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name="activity.example.com")
        self.scan = _make_scan(self.domain)

    def test_activity_calls_runner(self):
        from unittest.mock import patch, MagicMock
        with patch("reNgine.tasks.certificate.run_certificate_intel") as mock_runner, \
             patch("temporalio.activity.heartbeat", MagicMock()):
            from reNgine.temporal_activities import run_certificate_intel_activity
            mock_runner.return_value = []
            result = run_certificate_intel_activity(self.scan.id)
            mock_runner.assert_called_once()
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["count"], 0)

    def test_activity_returns_count(self):
        from unittest.mock import patch, MagicMock
        with patch("reNgine.tasks.certificate.run_certificate_intel") as mock_runner, \
             patch("temporalio.activity.heartbeat", MagicMock()):
            from reNgine.temporal_activities import run_certificate_intel_activity
            fake_cert = CertificateIntelligence(host="a.example.com", port=443)
            mock_runner.return_value = [fake_cert]
            result = run_certificate_intel_activity(self.scan.id)
            self.assertEqual(result["count"], 1)


class TestCertificateIngestion(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name="ingest.example.com")
        self.scan = _make_scan(self.domain)
        from startScan.models import Subdomain
        self.sub = Subdomain.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            name="ingest.example.com",
        )
        CertificateIntelligence.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            subdomain=self.sub,
            host="ingest.example.com",
            port=443,
            subject_cn="ingest.example.com",
            fingerprint_sha256="ingest001",
            self_signed=False,
            is_expired=False,
            has_weak_cipher=False,
        )

    def test_ingest_returns_certificate_node(self):
        from apme.ingestion.certificates import ingest_certificates
        nodes, edges = ingest_certificates(self.domain.id)
        cert_nodes = [n for n in nodes if n.type == "Certificate"]
        self.assertEqual(len(cert_nodes), 1)
        self.assertEqual(cert_nodes[0].subtype, "x509")

    def test_ingest_expired_cert_has_low_confidence(self):
        from apme.ingestion.certificates import ingest_certificates
        CertificateIntelligence.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            subdomain=self.sub,
            host="ingest.example.com",
            port=8443,
            fingerprint_sha256="expiredX01",
            is_expired=True,
            self_signed=False,
        )
        nodes, _ = ingest_certificates(self.domain.id)
        expired = [n for n in nodes if n.properties.get("is_expired")]
        self.assertTrue(len(expired) >= 1)
        self.assertLess(expired[0].confidence, 1.0)

    def test_ingest_empty_returns_empty(self):
        from apme.ingestion.certificates import ingest_certificates
        CertificateIntelligence.objects.all().delete()
        nodes, edges = ingest_certificates(self.domain.id)
        self.assertEqual(nodes, [])
        self.assertEqual(edges, [])


class TestCertificateRules(TestCase):
    def setUp(self):
        from apme.engine.rules_engine import RulesEngine
        from apme.models.node import Node
        rules_path = "apme/config/rules/v_certificate_intel.yaml"
        self.engine = RulesEngine(rules_file=rules_path)
        self.goal_nodes = [
            Node(id="goal::capability::credential_harvesting", type="Capability",
                 subtype="credential_harvesting", confidence=1.0, source="APME:virtual_goal"),
            Node(id="goal::capability::phishing_amplification", type="Capability",
                 subtype="phishing_amplification", confidence=1.0, source="APME:virtual_goal"),
            Node(id="goal::capability::authenticated_access", type="Capability",
                 subtype="authenticated_access", confidence=1.0, source="APME:virtual_goal"),
            Node(id="goal::capability::lateral_movement", type="Capability",
                 subtype="lateral_movement", confidence=1.0, source="APME:virtual_goal"),
        ]

    def test_weak_cipher_fires_credential_harvesting(self):
        from apme.models.node import Node
        cert_node = Node(
            id="cert::weakabc",
            type="Certificate", subtype="x509",
            confidence=0.75, source="reNgine:certificate_intel",
            properties={"has_weak_cipher": True, "is_expired": False, "self_signed": False},
        )
        edges = self.engine.apply(cert_node, [cert_node] + self.goal_nodes)
        subtypes = [e.to_id.split("::")[-1] for e in edges]
        self.assertIn("credential_harvesting", subtypes)

    def test_expired_cert_fires_phishing_amplification(self):
        from apme.models.node import Node
        cert_node = Node(
            id="cert::expiredabc",
            type="Certificate", subtype="x509",
            confidence=0.6, source="reNgine:certificate_intel",
            properties={"is_expired": True, "has_weak_cipher": False, "self_signed": False},
        )
        edges = self.engine.apply(cert_node, [cert_node] + self.goal_nodes)
        subtypes = [e.to_id.split("::")[-1] for e in edges]
        self.assertIn("phishing_amplification", subtypes)

    def test_self_signed_fires_authenticated_access(self):
        from apme.models.node import Node
        cert_node = Node(
            id="cert::selfabc",
            type="Certificate", subtype="x509",
            confidence=0.6, source="reNgine:certificate_intel",
            properties={"self_signed": True, "is_expired": False, "has_weak_cipher": False},
        )
        edges = self.engine.apply(cert_node, [cert_node] + self.goal_nodes)
        subtypes = [e.to_id.split("::")[-1] for e in edges]
        self.assertIn("authenticated_access", subtypes)

    def test_clean_cert_fires_no_rules(self):
        from apme.models.node import Node
        cert_node = Node(
            id="cert::cleanabc",
            type="Certificate", subtype="x509",
            confidence=1.0, source="reNgine:certificate_intel",
            properties={"is_expired": False, "self_signed": False, "has_weak_cipher": False},
        )
        edges = self.engine.apply(cert_node, [cert_node] + self.goal_nodes)
        self.assertEqual(len(edges), 0)


class TestNeo4jCertSync(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name="neo4j.example.com")
        self.scan = _make_scan(self.domain)
        from startScan.models import Subdomain
        self.sub = Subdomain.objects.create(
            scan_history=self.scan, target_domain=self.domain, name="neo4j.example.com",
        )
        CertificateIntelligence.objects.create(
            scan_history=self.scan, target_domain=self.domain, subdomain=self.sub,
            host="neo4j.example.com", port=443,
            fingerprint_sha256="neo4j001",
            subject_cn="neo4j.example.com",
            is_expired=False, self_signed=False, has_weak_cipher=False,
        )

    def test_batch_merge_certificates_cypher(self):
        from unittest.mock import MagicMock, patch
        with patch("reNgine.utils.graph.Neo4jManager.__init__", return_value=None):
            from reNgine.utils.graph import Neo4jManager
            mock_tx = MagicMock()
            rows = [{
                "host": "neo4j.example.com",
                "port": 443,
                "subject_cn": "neo4j.example.com",
                "fingerprint_sha256": "neo4j001",
                "is_expired": False,
                "self_signed": False,
                "has_weak_cipher": False,
                "scan_id": self.scan.id,
            }]
            Neo4jManager._batch_merge_certificates(mock_tx, rows)
            self.assertTrue(mock_tx.run.called)
            cypher = mock_tx.run.call_args[0][0]
            self.assertIn("Certificate", cypher)
            self.assertIn("MERGE", cypher)


class TestCertificateAPI(TestCase):
    def setUp(self):
        from rest_framework.test import APIClient
        from django.contrib.auth.models import User
        self.user = User.objects.create_user(
            "certuser", password="pass", is_superuser=True,
        )
        assign_role(self.user, "sys_admin")
        self.client = APIClient()
        # force_authenticate satisfies DRF; force_login satisfies LoginRequiredMiddleware
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)
        self.domain = Domain.objects.create(name="api.example.com")
        self.scan = _make_scan(self.domain)
        CertificateIntelligence.objects.create(
            scan_history=self.scan, target_domain=self.domain,
            host="api.example.com", port=443,
            fingerprint_sha256="apitest001",
            is_expired=True, self_signed=False, has_weak_cipher=False,
        )

    def test_list_certs_by_scan_id(self):
        resp = self.client.get(f"/api/certs/?scan_id={self.scan.id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["count"], 1)
        self.assertIn("page", data)
        self.assertIn("page_size", data)
        self.assertEqual(data["results"][0]["host"], "api.example.com")
        self.assertTrue(data["results"][0]["is_expired"])

    def test_pagination_params_accepted(self):
        resp = self.client.get(f"/api/certs/?scan_id={self.scan.id}&page=1&page_size=10")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["page"], 1)
        self.assertEqual(data["page_size"], 10)

    def test_invalid_page_param_returns_400(self):
        resp = self.client.get(f"/api/certs/?scan_id={self.scan.id}&page=abc")
        self.assertEqual(resp.status_code, 400)

    def test_missing_scan_id_returns_400(self):
        resp = self.client.get("/api/certs/")
        self.assertEqual(resp.status_code, 400)

    def test_unprivileged_user_cannot_access(self):
        from rest_framework.test import APIClient
        from django.contrib.auth.models import User
        plain = User.objects.create_user("certguest", password="pass")
        c = APIClient()
        c.force_authenticate(user=plain)
        c.force_login(user=plain)
        resp = c.get(f"/api/certs/?scan_id={self.scan.id}")
        self.assertIn(resp.status_code, [401, 403])

    def test_unauthenticated_returns_redirect(self):
        # LoginRequiredMiddleware redirects to login before DRF auth runs
        from rest_framework.test import APIClient
        anon = APIClient()
        resp = anon.get(f"/api/certs/?scan_id={self.scan.id}")
        self.assertEqual(resp.status_code, 302)
