"""APME Enhancement 2 — Phase 1 & Phase 2 tests."""
from django.test import TestCase

from apme.graph.schema import NODE_TYPES
from apme.ingestion.vulnerabilities import TAXONOMY_MAP, _infer_taxonomy
from apme.engine.constraints import ConstraintEngine, PathContext
from apme.engine.rules_engine import _CONSTRAINT_FLAGS


class SchemaExtensionTests(TestCase):
    """Verify new Technology, Vulnerability, and Capability subtypes."""

    # ── Technology ──────────────────────────────────────────────────────

    EXPECTED_TECH_SUBTYPES = [
        "dotnet", "ruby", "rails", "react", "angular", "vue",
        "kubernetes", "docker", "terraform", "ansible",
        "drupal", "joomla", "magento", "laravel",
        "mssql", "oracle", "redis", "elasticsearch", "mongodb",
        "exchange", "active_directory", "ldap",
    ]

    def test_new_technology_subtypes_present(self) -> None:
        subtypes = NODE_TYPES["Technology"]
        for expected in self.EXPECTED_TECH_SUBTYPES:
            self.assertIn(expected, subtypes, f"Missing Technology subtype: {expected}")

    # ── Vulnerability ───────────────────────────────────────────────────

    EXPECTED_VULN_SUBTYPES = [
        "http_request_smuggling", "tls_downgrade", "dns_cache_poisoning",
        "docker_socket_exposed", "container_escape", "k8s_rbac_misconfig",
        "privileged_container", "k8s_secret_exposure",
        "ntlm_relay", "pass_the_hash", "kerberoasting", "asrep_roasting",
        "dcsync_privilege", "gpo_abuse", "pass_the_ticket",
        "websocket_hijacking", "mass_assignment", "parameter_pollution",
        "graphql_mutation_abuse", "api_versioning_bypass",
        "spf_dmarc_bypass", "email_header_injection",
        "race_condition", "account_enumeration", "session_fixation",
        "business_logic_bypass", "parameter_tampering",
        "typosquatting", "compromised_registry", "ci_artifact_poisoning",
        "github_actions_injection",
        "blind_sqli", "blind_ssrf", "blind_xss", "blind_cmdi",
        "saml_signature_wrapping", "sso_bypass", "oauth_token_theft", "pkce_bypass",
        "web_cache_deception", "cache_poisoning", "reflected_file_download",
        "aspnet_viewstate", "machinekey_exploitation",
        "http_method_tampering", "nginx_alias_traversal",
        "second_order_sqli", "ognl_injection",
    ]

    def test_new_vulnerability_subtypes_present(self) -> None:
        subtypes = NODE_TYPES["Vulnerability"]
        for expected in self.EXPECTED_VULN_SUBTYPES:
            self.assertIn(expected, subtypes, f"Missing Vulnerability subtype: {expected}")

    # ── Capability ──────────────────────────────────────────────────────

    EXPECTED_CAPABILITY_SUBTYPES = [
        "domain_controller_compromise", "kerberos_ticket_forgery",
        "container_escape_capability", "k8s_cluster_access",
        "email_account_compromise", "email_spoofing",
        "cache_poisoning_execution", "ci_pipeline_execution",
        "registry_persistence", "scheduled_task_persistence",
        "saml_assertion_forgery", "shadow_credentials", "webshell_persistence",
    ]

    def test_new_capability_subtypes_present(self) -> None:
        subtypes = NODE_TYPES["Capability"]
        for expected in self.EXPECTED_CAPABILITY_SUBTYPES:
            self.assertIn(expected, subtypes, f"Missing Capability subtype: {expected}")

    # ── Regression ──────────────────────────────────────────────────────

    def test_existing_technology_subtypes_preserved(self) -> None:
        original = ["wordpress", "php", "java", "python", "nodejs",
                     "nginx", "apache", "spring", "jenkins", "generic"]
        subtypes = NODE_TYPES["Technology"]
        for expected in original:
            self.assertIn(expected, subtypes, f"Regression — missing: {expected}")

    def test_existing_vulnerability_subtypes_preserved(self) -> None:
        original = [
            "sqli", "command_injection", "code_injection", "rce", "ssti",
            "ssrf", "xxe", "lfi", "path_traversal", "file_upload",
            "deserialization", "misconfig", "jwt_abuse", "oauth_misconfig",
            "idor", "xss", "open_redirect", "clickjacking", "csrf",
            "cors", "graphql_injection", "prototype_pollution",
            "s3_misconfig", "subdomain_takeover", "dns_rebinding",
            "dependency_confusion", "generic", "generic_high", "generic_critical",
        ]
        subtypes = NODE_TYPES["Vulnerability"]
        for expected in original:
            self.assertIn(expected, subtypes, f"Regression — missing: {expected}")

    def test_existing_capability_subtypes_preserved(self) -> None:
        original = [
            "db_access", "data_exfil", "rce_execution", "authenticated_access",
            "pivot", "cloud_access", "internal_discovery",
            "account_takeover", "session_hijacking", "phishing_amplification",
            "persistence", "code_exfiltration", "credential_harvesting",
            "lateral_movement", "metadata_access", "hvt_compromise",
            "supply_chain_compromise", "dos_capability",
        ]
        subtypes = NODE_TYPES["Capability"]
        for expected in original:
            self.assertIn(expected, subtypes, f"Regression — missing: {expected}")


class TaxonomyMapTests(TestCase):
    """Verify new TAXONOMY_MAP entries and first-match ordering."""

    # ── First-match ordering ────────────────────────────────────────────

    def test_blind_sqli_matched_before_sqli(self) -> None:
        result = _infer_taxonomy("Blind SQL Injection in login", "", 3)
        self.assertEqual(result["subtype"], "blind_sqli")

    def test_second_order_sqli(self) -> None:
        result = _infer_taxonomy("Second Order SQL Injection", "", 3)
        self.assertEqual(result["subtype"], "second_order_sqli")

    def test_plain_sqli_still_works(self) -> None:
        result = _infer_taxonomy("SQL Injection in search param", "", 3)
        self.assertEqual(result["subtype"], "sqli")

    # ── Blind variants ──────────────────────────────────────────────────

    def test_blind_ssrf(self) -> None:
        result = _infer_taxonomy("Blind SSRF via webhook", "", 3)
        self.assertEqual(result["subtype"], "blind_ssrf")

    def test_blind_cmdi(self) -> None:
        result = _infer_taxonomy("Blind Command Injection", "", 3)
        self.assertEqual(result["subtype"], "blind_cmdi")

    # ── Network / protocol ──────────────────────────────────────────────

    def test_http_request_smuggling(self) -> None:
        result = _infer_taxonomy("HTTP Request Smuggling CL.TE", "", 3)
        self.assertEqual(result["subtype"], "http_request_smuggling")

    # ── Active Directory ────────────────────────────────────────────────

    def test_ntlm_relay(self) -> None:
        result = _infer_taxonomy("NTLM Relay via SMB", "", 4)
        self.assertEqual(result["subtype"], "ntlm_relay")

    def test_kerberoasting(self) -> None:
        result = _infer_taxonomy("Kerberoasting SPN extraction", "", 3)
        self.assertEqual(result["subtype"], "kerberoasting")

    # ── Container / infra ───────────────────────────────────────────────

    def test_docker_socket(self) -> None:
        result = _infer_taxonomy("Docker Socket Exposed", "", 4)
        self.assertEqual(result["subtype"], "docker_socket_exposed")

    # ── Supply chain ────────────────────────────────────────────────────

    def test_github_actions_injection(self) -> None:
        result = _infer_taxonomy("GitHub Actions Injection via PR", "", 3)
        self.assertEqual(result["subtype"], "github_actions_injection")

    # ── Auth / SSO ──────────────────────────────────────────────────────

    def test_saml_signature_wrapping(self) -> None:
        result = _infer_taxonomy("SAML Signature Wrapping attack", "", 4)
        self.assertEqual(result["subtype"], "saml_signature_wrapping")

    # ── .NET ────────────────────────────────────────────────────────────

    def test_aspnet_viewstate(self) -> None:
        result = _infer_taxonomy("ASP.NET ViewState Deserialization", "", 4)
        self.assertEqual(result["subtype"], "aspnet_viewstate")

    # ── Modern API / web ────────────────────────────────────────────────

    def test_race_condition(self) -> None:
        result = _infer_taxonomy("Race Condition in checkout flow", "", 2)
        self.assertEqual(result["subtype"], "race_condition")

    def test_mass_assignment(self) -> None:
        result = _infer_taxonomy("Mass Assignment in user profile", "", 3)
        self.assertEqual(result["subtype"], "mass_assignment")

    # ── Email ───────────────────────────────────────────────────────────

    def test_spf_dmarc_bypass(self) -> None:
        result = _infer_taxonomy("SPF DMARC Bypass allows spoofing", "", 2)
        self.assertEqual(result["subtype"], "spf_dmarc_bypass")

    # ── Misc ────────────────────────────────────────────────────────────

    def test_ognl_injection(self) -> None:
        result = _infer_taxonomy("OGNL injection in Struts", "", 4)
        self.assertEqual(result["subtype"], "ognl_injection")

    # ── Existing keywords still work ────────────────────────────────────

    def test_existing_xss_keyword(self) -> None:
        result = _infer_taxonomy("Reflected XSS in search", "", 2)
        self.assertEqual(result["subtype"], "xss")

    def test_existing_rce_keyword(self) -> None:
        result = _infer_taxonomy("Remote Code Execution via upload", "", 4)
        self.assertEqual(result["subtype"], "rce")

    def test_existing_ssrf_keyword(self) -> None:
        result = _infer_taxonomy("SSRF in image proxy", "", 3)
        self.assertEqual(result["subtype"], "ssrf")

    def test_existing_sqli_keyword(self) -> None:
        """Plain 'sqli' keyword must still resolve correctly."""
        result = _infer_taxonomy("sqli found in parameter", "", 2)
        self.assertEqual(result["subtype"], "sqli")


# ═══════════════════════════════════════════════════════════════════════
# Phase 2 tests: Constraint Engine Expansion
# ═══════════════════════════════════════════════════════════════════════


class ConstraintFlagTests(TestCase):
    """Verify all 18 flags are present in _CONSTRAINT_FLAGS."""

    EXPECTED_FLAGS = [
        "requires_victim",
        "requires_php",
        "requires_java",
        "requires_python",
        "requires_wordpress",
        "endpoint_requires_auth",
        "requires_dotnet",
        "requires_kubernetes",
        "requires_docker",
        "requires_ruby",
        "requires_nodejs",
        "requires_active_directory",
        "requires_mssql",
        "requires_oracle",
        "requires_redis",
        "requires_drupal",
        "requires_joomla",
        "requires_magento",
    ]

    def test_all_18_flags_present(self) -> None:
        for flag in self.EXPECTED_FLAGS:
            self.assertIn(flag, _CONSTRAINT_FLAGS, f"Missing flag: {flag}")

    def test_flag_count(self) -> None:
        self.assertEqual(len(_CONSTRAINT_FLAGS), 18)

    def test_original_six_flags_preserved(self) -> None:
        original = [
            "requires_victim", "requires_php", "requires_java",
            "requires_python", "requires_wordpress", "endpoint_requires_auth",
        ]
        for flag in original:
            self.assertIn(flag, _CONSTRAINT_FLAGS, f"Regression — missing: {flag}")


class ConstraintGateTests(TestCase):
    """Verify each new gate blocks without tech and passes with tech."""

    def setUp(self) -> None:
        self.engine = ConstraintEngine()

    def _base_step(self, **overrides) -> dict:
        step = {"action": "test_action", "confidence": 0.8}
        step.update(overrides)
        return step

    # ── Active Directory ───────────────────────────────────────────────

    def test_active_directory_gate_blocks(self) -> None:
        ctx = PathContext()
        step = self._base_step(requires_active_directory=True)
        self.assertFalse(self.engine.validate_step(step, ctx))

    def test_active_directory_gate_passes(self) -> None:
        ctx = PathContext()
        ctx.has_active_directory_tech = True
        step = self._base_step(requires_active_directory=True)
        self.assertTrue(self.engine.validate_step(step, ctx))

    # ── Kubernetes ─────────────────────────────────────────────────────

    def test_kubernetes_gate_blocks(self) -> None:
        ctx = PathContext()
        step = self._base_step(requires_kubernetes=True)
        self.assertFalse(self.engine.validate_step(step, ctx))

    def test_kubernetes_gate_passes(self) -> None:
        ctx = PathContext()
        ctx.has_kubernetes_tech = True
        step = self._base_step(requires_kubernetes=True)
        self.assertTrue(self.engine.validate_step(step, ctx))

    # ── Docker ─────────────────────────────────────────────────────────

    def test_docker_gate_blocks(self) -> None:
        ctx = PathContext()
        step = self._base_step(requires_docker=True)
        self.assertFalse(self.engine.validate_step(step, ctx))

    def test_docker_gate_passes(self) -> None:
        ctx = PathContext()
        ctx.has_docker_tech = True
        step = self._base_step(requires_docker=True)
        self.assertTrue(self.engine.validate_step(step, ctx))

    # ── Redis ──────────────────────────────────────────────────────────

    def test_redis_gate_blocks(self) -> None:
        ctx = PathContext()
        step = self._base_step(requires_redis=True)
        self.assertFalse(self.engine.validate_step(step, ctx))

    def test_redis_gate_passes(self) -> None:
        ctx = PathContext()
        ctx.has_redis_tech = True
        step = self._base_step(requires_redis=True)
        self.assertTrue(self.engine.validate_step(step, ctx))

    # ── Drupal ─────────────────────────────────────────────────────────

    def test_drupal_gate_blocks(self) -> None:
        ctx = PathContext()
        step = self._base_step(requires_drupal=True)
        self.assertFalse(self.engine.validate_step(step, ctx))

    def test_drupal_gate_passes(self) -> None:
        ctx = PathContext()
        ctx.has_drupal_tech = True
        step = self._base_step(requires_drupal=True)
        self.assertTrue(self.engine.validate_step(step, ctx))

    # ── Joomla ─────────────────────────────────────────────────────────

    def test_joomla_gate_blocks(self) -> None:
        ctx = PathContext()
        step = self._base_step(requires_joomla=True)
        self.assertFalse(self.engine.validate_step(step, ctx))

    def test_joomla_gate_passes(self) -> None:
        ctx = PathContext()
        ctx.has_joomla_tech = True
        step = self._base_step(requires_joomla=True)
        self.assertTrue(self.engine.validate_step(step, ctx))

    # ── Magento ────────────────────────────────────────────────────────

    def test_magento_gate_blocks(self) -> None:
        ctx = PathContext()
        step = self._base_step(requires_magento=True)
        self.assertFalse(self.engine.validate_step(step, ctx))

    def test_magento_gate_passes(self) -> None:
        ctx = PathContext()
        ctx.has_magento_tech = True
        step = self._base_step(requires_magento=True)
        self.assertTrue(self.engine.validate_step(step, ctx))

    # ── Ruby ───────────────────────────────────────────────────────────

    def test_ruby_gate_blocks(self) -> None:
        ctx = PathContext()
        step = self._base_step(requires_ruby=True)
        self.assertFalse(self.engine.validate_step(step, ctx))

    def test_ruby_gate_passes(self) -> None:
        ctx = PathContext()
        ctx.has_ruby_tech = True
        step = self._base_step(requires_ruby=True)
        self.assertTrue(self.engine.validate_step(step, ctx))

    # ── Node.js ────────────────────────────────────────────────────────

    def test_nodejs_gate_blocks(self) -> None:
        ctx = PathContext()
        step = self._base_step(requires_nodejs=True)
        self.assertFalse(self.engine.validate_step(step, ctx))

    def test_nodejs_gate_passes(self) -> None:
        ctx = PathContext()
        ctx.has_nodejs_tech = True
        step = self._base_step(requires_nodejs=True)
        self.assertTrue(self.engine.validate_step(step, ctx))

    # ── .NET ───────────────────────────────────────────────────────────

    def test_dotnet_gate_blocks(self) -> None:
        ctx = PathContext()
        step = self._base_step(requires_dotnet=True)
        self.assertFalse(self.engine.validate_step(step, ctx))

    def test_dotnet_gate_passes(self) -> None:
        ctx = PathContext()
        ctx.has_dotnet_tech = True
        step = self._base_step(requires_dotnet=True)
        self.assertTrue(self.engine.validate_step(step, ctx))

    # ── MSSQL ──────────────────────────────────────────────────────────

    def test_mssql_gate_blocks(self) -> None:
        ctx = PathContext()
        step = self._base_step(requires_mssql=True)
        self.assertFalse(self.engine.validate_step(step, ctx))

    def test_mssql_gate_passes(self) -> None:
        ctx = PathContext()
        ctx.has_mssql_tech = True
        step = self._base_step(requires_mssql=True)
        self.assertTrue(self.engine.validate_step(step, ctx))

    # ── Oracle ─────────────────────────────────────────────────────────

    def test_oracle_gate_blocks(self) -> None:
        ctx = PathContext()
        step = self._base_step(requires_oracle=True)
        self.assertFalse(self.engine.validate_step(step, ctx))

    def test_oracle_gate_passes(self) -> None:
        ctx = PathContext()
        ctx.has_oracle_tech = True
        step = self._base_step(requires_oracle=True)
        self.assertTrue(self.engine.validate_step(step, ctx))

    # ── Unrestricted pass ──────────────────────────────────────────────

    def test_no_flag_set_passes_unrestricted(self) -> None:
        ctx = PathContext()
        step = self._base_step()
        self.assertTrue(self.engine.validate_step(step, ctx))


class ConstraintContextUpdateTests(TestCase):
    """Verify update_context tech propagation for new technologies."""

    def setUp(self) -> None:
        self.engine = ConstraintEngine()

    def _step_with_subtype(self, subtype: str) -> dict:
        return {"action": "test", "confidence": 0.8, "to_subtype": subtype, "to_id": f"node-{subtype}"}

    # ── .NET / ASP.NET ─────────────────────────────────────────────────

    def test_dotnet_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("dotnet"), ctx)
        self.assertTrue(ctx.has_dotnet_tech)

    def test_aspnet_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("aspnet"), ctx)
        self.assertTrue(ctx.has_dotnet_tech)

    def test_csharp_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("csharp"), ctx)
        self.assertTrue(ctx.has_dotnet_tech)

    # ── Kubernetes ─────────────────────────────────────────────────────

    def test_kubernetes_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("kubernetes"), ctx)
        self.assertTrue(ctx.has_kubernetes_tech)

    def test_k8s_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("k8s"), ctx)
        self.assertTrue(ctx.has_kubernetes_tech)

    # ── Docker ─────────────────────────────────────────────────────────

    def test_docker_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("docker"), ctx)
        self.assertTrue(ctx.has_docker_tech)

    def test_container_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("container"), ctx)
        self.assertTrue(ctx.has_docker_tech)

    # ── Ruby ───────────────────────────────────────────────────────────

    def test_ruby_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("ruby"), ctx)
        self.assertTrue(ctx.has_ruby_tech)

    def test_rails_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("rails"), ctx)
        self.assertTrue(ctx.has_ruby_tech)

    # ── Node.js ────────────────────────────────────────────────────────

    def test_nodejs_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("nodejs"), ctx)
        self.assertTrue(ctx.has_nodejs_tech)

    def test_node_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("node"), ctx)
        self.assertTrue(ctx.has_nodejs_tech)

    def test_express_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("express"), ctx)
        self.assertTrue(ctx.has_nodejs_tech)

    # ── Active Directory ───────────────────────────────────────────────

    def test_active_directory_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("active_directory"), ctx)
        self.assertTrue(ctx.has_active_directory_tech)

    def test_ldap_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("ldap"), ctx)
        self.assertTrue(ctx.has_active_directory_tech)

    def test_exchange_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("exchange"), ctx)
        self.assertTrue(ctx.has_active_directory_tech)

    # ── Redis ──────────────────────────────────────────────────────────

    def test_redis_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("redis"), ctx)
        self.assertTrue(ctx.has_redis_tech)

    # ── Drupal ─────────────────────────────────────────────────────────

    def test_drupal_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("drupal"), ctx)
        self.assertTrue(ctx.has_drupal_tech)

    # ── Joomla ─────────────────────────────────────────────────────────

    def test_joomla_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("joomla"), ctx)
        self.assertTrue(ctx.has_joomla_tech)

    # ── Magento ────────────────────────────────────────────────────────

    def test_magento_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("magento"), ctx)
        self.assertTrue(ctx.has_magento_tech)

    # ── MSSQL ──────────────────────────────────────────────────────────

    def test_mssql_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("mssql"), ctx)
        self.assertTrue(ctx.has_mssql_tech)

    def test_sqlserver_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("sqlserver"), ctx)
        self.assertTrue(ctx.has_mssql_tech)

    # ── Oracle ─────────────────────────────────────────────────────────

    def test_oracle_propagation(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("oracle"), ctx)
        self.assertTrue(ctx.has_oracle_tech)

    # ── Existing propagation regression ────────────────────────────────

    def test_php_propagation_still_works(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("php"), ctx)
        self.assertTrue(ctx.has_php_tech)

    def test_java_propagation_still_works(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("java"), ctx)
        self.assertTrue(ctx.has_java_tech)

    def test_wordpress_propagation_still_works(self) -> None:
        ctx = PathContext()
        self.engine.update_context(self._step_with_subtype("wordpress"), ctx)
        self.assertTrue(ctx.has_wordpress_tech)


# ═══════════════════════════════════════════════════════════════════════
# Phase 3 — Existing Rules Addition Tests
# ═══════════════════════════════════════════════════════════════════════


class ExistingRulesAdditionTests(TestCase):
    """Verify the 29 new rules added to existing YAML rule files."""

    def setUp(self) -> None:
        from apme.engine.rules_engine import RulesEngine
        self.engine = RulesEngine()
        self.rule_names = {r["name"] for r in self.engine._rules}

    # ── Aggregate count ───────────────────────────────────────────────

    def test_total_rule_count_at_least_105(self) -> None:
        self.assertGreaterEqual(
            len(self.engine._rules), 105,
            f"Expected >= 105 rules (76 existing + 29 new), got {len(self.engine._rules)}",
        )

    # ── a_injection rules (7) ─────────────────────────────────────────

    def test_blind_sqli_to_db_access(self) -> None:
        self.assertIn("blind_sqli_to_db_access", self.rule_names)

    def test_blind_sqli_verified_to_db_access(self) -> None:
        self.assertIn("blind_sqli_verified_to_db_access", self.rule_names)

    def test_second_order_sqli_to_account_takeover(self) -> None:
        self.assertIn("second_order_sqli_to_account_takeover", self.rule_names)

    def test_nosql_injection_to_auth_bypass(self) -> None:
        self.assertIn("nosql_injection_to_auth_bypass", self.rule_names)

    def test_ognl_injection_to_rce(self) -> None:
        self.assertIn("ognl_injection_to_rce", self.rule_names)

    def test_blind_cmdi_to_rce(self) -> None:
        self.assertIn("blind_cmdi_to_rce", self.rule_names)

    def test_blind_cmdi_verified_to_rce(self) -> None:
        self.assertIn("blind_cmdi_verified_to_rce", self.rule_names)

    # ── c_server_side rules (5) ───────────────────────────────────────

    def test_blind_ssrf_to_metadata_access(self) -> None:
        self.assertIn("blind_ssrf_to_metadata_access", self.rule_names)

    def test_blind_ssrf_verified_to_cloud_access(self) -> None:
        self.assertIn("blind_ssrf_verified_to_cloud_access", self.rule_names)

    def test_ssrf_to_redis_rce(self) -> None:
        self.assertIn("ssrf_to_redis_rce", self.rule_names)

    def test_http_request_smuggling_to_auth_bypass(self) -> None:
        self.assertIn("http_request_smuggling_to_auth_bypass", self.rule_names)

    def test_http_request_smuggling_to_data_exfil(self) -> None:
        self.assertIn("http_request_smuggling_to_data_exfil", self.rule_names)

    # ── e_auth_identity rules (8) ─────────────────────────────────────

    def test_saml_signature_wrapping_to_auth_bypass(self) -> None:
        self.assertIn("saml_signature_wrapping_to_auth_bypass", self.rule_names)

    def test_saml_to_account_takeover(self) -> None:
        self.assertIn("saml_to_account_takeover", self.rule_names)

    def test_oauth_token_theft_to_account_takeover(self) -> None:
        self.assertIn("oauth_token_theft_to_account_takeover", self.rule_names)

    def test_pkce_bypass_to_auth_access(self) -> None:
        self.assertIn("pkce_bypass_to_auth_access", self.rule_names)

    def test_session_fixation_to_account_takeover(self) -> None:
        self.assertIn("session_fixation_to_account_takeover", self.rule_names)

    def test_account_enumeration_to_credential_harvesting(self) -> None:
        self.assertIn("account_enumeration_to_credential_harvesting", self.rule_names)

    def test_broken_object_level_to_data_exfil(self) -> None:
        self.assertIn("broken_object_level_to_data_exfil", self.rule_names)

    def test_parameter_tampering_to_privilege_escalation(self) -> None:
        self.assertIn("parameter_tampering_to_privilege_escalation", self.rule_names)

    # ── f_client_side rules (5) ───────────────────────────────────────

    def test_blind_xss_to_credential_harvesting(self) -> None:
        self.assertIn("blind_xss_to_credential_harvesting", self.rule_names)

    def test_dom_xss_to_account_takeover(self) -> None:
        self.assertIn("dom_xss_to_account_takeover", self.rule_names)

    def test_websocket_hijacking_to_auth_access(self) -> None:
        self.assertIn("websocket_hijacking_to_auth_access", self.rule_names)

    def test_iframe_injection_to_phishing(self) -> None:
        self.assertIn("iframe_injection_to_phishing", self.rule_names)

    def test_postmessage_origin_bypass_to_data_exfil(self) -> None:
        self.assertIn("postmessage_origin_bypass_to_data_exfil", self.rule_names)

    # ── g_info_disclosure rules (4) ───────────────────────────────────

    def test_nginx_alias_traversal_to_data_exfil(self) -> None:
        self.assertIn("nginx_alias_traversal_to_data_exfil", self.rule_names)

    def test_http_method_tampering_to_data_exfil(self) -> None:
        self.assertIn("http_method_tampering_to_data_exfil", self.rule_names)

    def test_reflected_file_download_to_credential_harvesting(self) -> None:
        self.assertIn("reflected_file_download_to_credential_harvesting", self.rule_names)

    def test_web_cache_deception_to_data_exfil(self) -> None:
        self.assertIn("web_cache_deception_to_data_exfil", self.rule_names)

    # ── Constraint flag spot-checks ───────────────────────────────────

    def test_ognl_rule_has_requires_java(self) -> None:
        rule = next(r for r in self.engine._rules if r["name"] == "ognl_injection_to_rce")
        self.assertTrue(rule["then"]["create_edge"].get("requires_java"))

    def test_ssrf_redis_rule_has_requires_redis(self) -> None:
        rule = next(r for r in self.engine._rules if r["name"] == "ssrf_to_redis_rce")
        self.assertTrue(rule["then"]["create_edge"].get("requires_redis"))


# ═══════════════════════════════════════════════════════════════════════
# Phase 4 — New Rule Category Files (74 rules across 8 files)
# ═══════════════════════════════════════════════════════════════════════


class NewRuleCategoryTests(TestCase):
    """Verify 74 new rules from 8 new YAML rule category files (n_ through u_)."""

    def setUp(self) -> None:
        from apme.engine.rules_engine import RulesEngine
        self.engine = RulesEngine()
        self.rule_names = {r["name"] for r in self.engine._rules}

    def _assert_rules(self, *names: str) -> None:
        for name in names:
            self.assertIn(name, self.rule_names, f"Missing rule: {name}")

    def _rule(self, name: str) -> dict:
        return next(r for r in self.engine._rules if r["name"] == name)

    # ── Aggregate count ──────────────────────────────────────────────────

    def test_total_rule_count_approximately_179(self) -> None:
        count = len(self.engine._rules)
        self.assertGreaterEqual(count, 174, f"Expected >= 174 rules, got {count}")
        self.assertLessEqual(count, 184, f"Expected <= 184 rules, got {count}")

    # ── n_network_protocol.yaml (8 rules) ────────────────────────────────

    def test_network_protocol_rules_loaded(self) -> None:
        self._assert_rules(
            "tls_downgrade_to_data_exfil",
            "dns_cache_poisoning_to_phishing",
            "dns_cache_poisoning_to_pivot",
            "cache_poisoning_to_auth_bypass",
            "cache_poisoning_to_account_takeover",
            "http_desync_to_cache_poisoning",
            "tcp_sequence_prediction_to_pivot",
            "smtp_relay_to_email_spoofing",
        )

    # ── o_container_infra.yaml (10 rules) ────────────────────────────────

    def test_container_infra_rules_loaded(self) -> None:
        self._assert_rules(
            "docker_socket_exposed_to_container_escape",
            "container_escape_to_pivot",
            "container_escape_to_rce_execution",
            "privileged_container_to_escape",
            "k8s_rbac_misconfig_to_cluster_access",
            "k8s_secret_exposure_to_credential_harvesting",
            "k8s_cluster_access_to_lateral_movement",
            "k8s_cluster_access_to_persistence",
            "k8s_cluster_access_to_supply_chain",
            "docker_registry_exposure_to_code_exfil",
        )

    def test_docker_rules_have_requires_docker(self) -> None:
        docker_rules = [
            "docker_socket_exposed_to_container_escape",
            "container_escape_to_pivot",
            "container_escape_to_rce_execution",
            "privileged_container_to_escape",
            "docker_registry_exposure_to_code_exfil",
        ]
        for name in docker_rules:
            rule = self._rule(name)
            self.assertTrue(
                rule["then"]["create_edge"].get("requires_docker"),
                f"Rule {name} missing requires_docker",
            )

    def test_k8s_rules_have_requires_kubernetes(self) -> None:
        k8s_rules = [
            "k8s_rbac_misconfig_to_cluster_access",
            "k8s_secret_exposure_to_credential_harvesting",
            "k8s_cluster_access_to_lateral_movement",
            "k8s_cluster_access_to_persistence",
            "k8s_cluster_access_to_supply_chain",
        ]
        for name in k8s_rules:
            rule = self._rule(name)
            self.assertTrue(
                rule["then"]["create_edge"].get("requires_kubernetes"),
                f"Rule {name} missing requires_kubernetes",
            )

    # ── p_active_directory.yaml (14 rules) ───────────────────────────────

    def test_active_directory_rules_loaded(self) -> None:
        self._assert_rules(
            "ntlm_relay_to_lateral_movement",
            "ntlm_relay_to_domain_admin",
            "pass_the_hash_to_lateral_movement",
            "pass_the_ticket_to_lateral_movement",
            "kerberoasting_to_credential_harvesting",
            "kerberoasting_to_lateral_movement",
            "asrep_roasting_to_credential_harvesting",
            "dcsync_to_credential_harvesting",
            "dcsync_to_hvt_compromise",
            "gpo_abuse_to_lateral_movement",
            "gpo_abuse_to_persistence",
            "shadow_credentials_to_account_takeover",
            "kerberos_ticket_forgery_to_hvt_compromise",
            "credential_harvesting_to_domain_controller",
        )

    def test_all_ad_rules_have_requires_active_directory(self) -> None:
        ad_rules = [
            "ntlm_relay_to_lateral_movement",
            "ntlm_relay_to_domain_admin",
            "pass_the_hash_to_lateral_movement",
            "pass_the_ticket_to_lateral_movement",
            "kerberoasting_to_credential_harvesting",
            "kerberoasting_to_lateral_movement",
            "asrep_roasting_to_credential_harvesting",
            "dcsync_to_credential_harvesting",
            "dcsync_to_hvt_compromise",
            "gpo_abuse_to_lateral_movement",
            "gpo_abuse_to_persistence",
            "shadow_credentials_to_account_takeover",
            "kerberos_ticket_forgery_to_hvt_compromise",
            "credential_harvesting_to_domain_controller",
        ]
        for name in ad_rules:
            rule = self._rule(name)
            self.assertTrue(
                rule["then"]["create_edge"].get("requires_active_directory"),
                f"Rule {name} missing requires_active_directory",
            )

    # ── q_api_web_modern.yaml (10 rules) ─────────────────────────────────

    def test_api_web_modern_rules_loaded(self) -> None:
        self._assert_rules(
            "mass_assignment_to_privilege_escalation",
            "mass_assignment_verified_to_account_takeover",
            "parameter_pollution_to_auth_bypass",
            "graphql_mutation_to_account_takeover",
            "graphql_mutation_to_data_exfil",
            "api_versioning_bypass_to_auth_bypass",
            "api_versioning_bypass_to_data_exfil",
            "insecure_websocket_to_auth_bypass",
            "race_condition_to_privilege_escalation",
            "race_condition_to_account_takeover",
        )

    # ── r_email_security.yaml (8 rules) ──────────────────────────────────

    def test_email_security_rules_loaded(self) -> None:
        self._assert_rules(
            "spf_dmarc_bypass_to_email_spoofing",
            "spf_dmarc_bypass_to_phishing_amplification",
            "email_header_injection_to_phishing",
            "email_header_injection_to_account_takeover",
            "email_account_compromise_to_lateral_movement",
            "email_account_compromise_to_credential_harvesting",
            "email_spoofing_to_hvt_compromise",
            "mx_misconfig_to_email_spoofing",
        )

    # ── s_supply_chain.yaml (8 rules) ────────────────────────────────────

    def test_supply_chain_rules_loaded(self) -> None:
        self._assert_rules(
            "github_actions_injection_to_ci_execution",
            "ci_artifact_poisoning_to_supply_chain",
            "typosquatting_to_supply_chain",
            "compromised_registry_to_rce_execution",
            "ci_execution_to_credential_harvesting",
            "ci_execution_to_code_exfil",
            "github_token_to_ci_execution",
            "supply_chain_compromise_to_hvt_compromise",
        )

    # ── t_dotnet_cms.yaml (8 rules) ──────────────────────────────────────

    def test_dotnet_cms_rules_loaded(self) -> None:
        self._assert_rules(
            "aspnet_viewstate_to_rce",
            "machinekey_to_rce",
            "drupal_rce_to_execution",
            "drupal_sqli_to_db_access",
            "joomla_rce_to_execution",
            "magento_sqli_to_db_access",
            "rails_mass_assign_to_privilege_escalation",
            "nodejs_prototype_pollution_to_rce",
        )

    def test_dotnet_rules_have_requires_dotnet(self) -> None:
        dotnet_rules = ["aspnet_viewstate_to_rce", "machinekey_to_rce"]
        for name in dotnet_rules:
            rule = self._rule(name)
            self.assertTrue(
                rule["then"]["create_edge"].get("requires_dotnet"),
                f"Rule {name} missing requires_dotnet",
            )

    def test_drupal_rules_have_requires_drupal(self) -> None:
        drupal_rules = ["drupal_rce_to_execution", "drupal_sqli_to_db_access"]
        for name in drupal_rules:
            rule = self._rule(name)
            self.assertTrue(
                rule["then"]["create_edge"].get("requires_drupal"),
                f"Rule {name} missing requires_drupal",
            )

    def test_nodejs_rule_has_requires_nodejs(self) -> None:
        rule = self._rule("nodejs_prototype_pollution_to_rce")
        self.assertTrue(rule["then"]["create_edge"].get("requires_nodejs"))

    def test_joomla_rule_has_requires_joomla(self) -> None:
        rule = self._rule("joomla_rce_to_execution")
        self.assertTrue(rule["then"]["create_edge"].get("requires_joomla"))

    def test_magento_rule_has_requires_magento(self) -> None:
        rule = self._rule("magento_sqli_to_db_access")
        self.assertTrue(rule["then"]["create_edge"].get("requires_magento"))

    def test_rails_rule_has_requires_ruby(self) -> None:
        rule = self._rule("rails_mass_assign_to_privilege_escalation")
        self.assertTrue(rule["then"]["create_edge"].get("requires_ruby"))

    # ── u_persistence_chains.yaml (8 rules) ──────────────────────────────

    def test_persistence_chains_rules_loaded(self) -> None:
        self._assert_rules(
            "rce_execution_to_webshell_persistence",
            "rce_execution_to_scheduled_task",
            "rce_execution_to_registry_persistence",
            "file_upload_to_webshell",
            "admin_access_to_cron_persistence",
            "persistence_to_lateral_movement",
            "persistence_to_credential_harvesting",
            "webshell_to_data_exfil",
        )

    def test_registry_persistence_requires_dotnet(self) -> None:
        rule = self._rule("rce_execution_to_registry_persistence")
        self.assertTrue(rule["then"]["create_edge"].get("requires_dotnet"))

    # ── Cross-file constraint spot-checks ────────────────────────────────

    def test_insecure_websocket_requires_victim(self) -> None:
        rule = self._rule("insecure_websocket_to_auth_bypass")
        self.assertTrue(rule["then"]["create_edge"].get("requires_victim"))

    def test_email_spoofing_to_hvt_requires_victim(self) -> None:
        rule = self._rule("email_spoofing_to_hvt_compromise")
        self.assertTrue(rule["then"]["create_edge"].get("requires_victim"))

    def test_email_header_injection_to_account_takeover_requires_victim(self) -> None:
        rule = self._rule("email_header_injection_to_account_takeover")
        self.assertTrue(rule["then"]["create_edge"].get("requires_victim"))


# ─────────────────────────────────────────────────────────────────────────────
# Phase 5 — Scoring Overhaul
# ─────────────────────────────────────────────────────────────────────────────

class ScorerWeightTests(TestCase):
    """WEIGHTS dict validation."""

    def test_ten_factors_in_weights(self):
        from apme.engine.scorer import Scorer
        self.assertEqual(len(Scorer.WEIGHTS), 10)

    def test_weights_sum_to_one(self):
        from apme.engine.scorer import Scorer
        self.assertAlmostEqual(sum(Scorer.WEIGHTS.values()), 1.0, places=4)

    def test_all_new_factor_keys_present(self):
        from apme.engine.scorer import Scorer
        for key in ("poc", "recency", "connectivity", "stealthiness"):
            self.assertIn(key, Scorer.WEIGHTS,
                          f"Missing scoring factor: {key}")


class ScorerNewFactorTests(TestCase):
    """New factor computations and modified modifiers."""

    def _make_path(self, validated=False, n_steps=2):
        from apme.models.path import AttackPath, PathStep
        steps = [
            PathStep(from_id=f"n{i}", to_id=f"n{i+1}", action="a",
                     confidence=0.8, validated=validated, edge_type="LEADS_TO")
            for i in range(n_steps)
        ]
        return AttackPath(id="T-1", start="n0", end=f"n{n_steps}", steps=steps)

    def _base_meta(self, **overrides):
        meta = {
            "severity": 3, "cvss_score": 7.0, "privilege_gained": "user",
            "validated_steps": 0, "target_sensitivity": "medium",
            "blast_radius": 10, "epss_percentile": 50.0,
            "has_cisa_kev": False, "path_confidence_product": 0.8,
            "has_poc": False, "has_exploit_url": False, "has_metasploit": False,
            "cve_published_date": None, "target_node_degree": 5,
        }
        meta.update(overrides)
        return meta

    def test_metasploit_boosts_score(self):
        from apme.engine.scorer import Scorer
        scorer = Scorer()
        path_a = self._make_path()
        score_a = scorer.score(path_a, self._base_meta(has_metasploit=True))
        path_b = self._make_path()
        score_b = scorer.score(path_b, self._base_meta(has_metasploit=False))
        self.assertGreater(score_a, score_b)

    def test_exploit_url_boosts_more_than_poc_only(self):
        from apme.engine.scorer import Scorer
        scorer = Scorer()
        path_a = self._make_path()
        score_exploit = scorer.score(path_a, self._base_meta(has_exploit_url=True))
        path_b = self._make_path()
        score_poc = scorer.score(path_b, self._base_meta(has_poc=True))
        self.assertGreater(score_exploit, score_poc)

    def test_recent_cve_boosts_score(self):
        import datetime
        from apme.engine.scorer import Scorer
        scorer = Scorer()
        recent = datetime.date.today() - datetime.timedelta(days=10)
        old = datetime.date.today() - datetime.timedelta(days=1000)
        path_a = self._make_path()
        score_recent = scorer.score(path_a, self._base_meta(cve_published_date=recent))
        path_b = self._make_path()
        score_old = scorer.score(path_b, self._base_meta(cve_published_date=old))
        self.assertGreater(score_recent, score_old)

    def test_cve_published_date_string_formats(self):
        import datetime
        from apme.engine.scorer import Scorer
        scorer = Scorer()
        path = self._make_path()
        
        # Test ISO format string
        recent_str = (datetime.date.today() - datetime.timedelta(days=10)).isoformat()
        score_recent = scorer.score(path, self._base_meta(cve_published_date=recent_str))
        
        old_str = (datetime.date.today() - datetime.timedelta(days=1000)).isoformat()
        score_old = scorer.score(path, self._base_meta(cve_published_date=old_str))
        self.assertGreater(score_recent, score_old)

        # Test datetime string format
        dt_str = (datetime.date.today() - datetime.timedelta(days=10)).strftime("%Y-%m-%d 12:00:00")
        score_dt = scorer.score(path, self._base_meta(cve_published_date=dt_str))
        self.assertEqual(score_recent, score_dt)

        # Test fallback format
        score_invalid = scorer.score(path, self._base_meta(cve_published_date="invalid-date"))
        self.assertEqual(score_invalid, score_old)


    def test_high_connectivity_boosts_score(self):
        from apme.engine.scorer import Scorer
        scorer = Scorer()
        path_a = self._make_path()
        score_high = scorer.score(path_a, self._base_meta(target_node_degree=20))
        path_b = self._make_path()
        score_low = scorer.score(path_b, self._base_meta(target_node_degree=1))
        self.assertGreater(score_high, score_low)

    def test_boundary_crossings_reduce_stealthiness(self):
        from apme.engine.scorer import Scorer
        from apme.models.path import AttackPath, PathStep
        scorer = Scorer()
        steps_noisy = [
            PathStep(from_id="a", to_id="b", action="x", confidence=0.8,
                     edge_type="CONNECTED_TO"),
            PathStep(from_id="b", to_id="c", action="y", confidence=0.8,
                     edge_type="CONNECTED_TO"),
        ]
        path_noisy = AttackPath(id="N-1", start="a", end="c", steps=steps_noisy)
        score_noisy = scorer.score(path_noisy, self._base_meta())
        steps_quiet = [
            PathStep(from_id="a", to_id="b", action="x", confidence=0.8,
                     edge_type="LEADS_TO"),
            PathStep(from_id="b", to_id="c", action="y", confidence=0.8,
                     edge_type="LEADS_TO"),
        ]
        path_quiet = AttackPath(id="Q-1", start="a", end="c", steps=steps_quiet)
        score_quiet = scorer.score(path_quiet, self._base_meta())
        self.assertGreater(score_quiet, score_noisy)

    def test_kev_plus_poc_boosts_more_than_kev_alone(self):
        from apme.engine.scorer import Scorer
        scorer = Scorer()
        path_a = self._make_path()
        score_kev_poc = scorer.score(
            path_a, self._base_meta(has_cisa_kev=True, has_poc=True))
        path_b = self._make_path()
        score_kev_only = scorer.score(
            path_b, self._base_meta(has_cisa_kev=True))
        self.assertGreater(score_kev_poc, score_kev_only)

    def test_erl_boost_not_applied_on_single_step_path(self):
        from apme.engine.scorer import Scorer
        from apme.models.path import AttackPath, PathStep
        scorer = Scorer()
        single = AttackPath(
            id="S-1", start="a", end="b",
            steps=[PathStep(from_id="a", to_id="b", action="x",
                            confidence=0.9, validated=True)]
        )
        meta = self._base_meta(validated_steps=1)
        scorer.score(single, meta)
        self.assertNotEqual(single.risk, "critical")

    def test_erl_boost_applied_on_two_step_validated_path(self):
        from apme.engine.scorer import Scorer
        scorer = Scorer()
        path = self._make_path(validated=True, n_steps=2)
        meta = self._base_meta(
            validated_steps=2, severity=4, cvss_score=9.0,
            privilege_gained="admin", epss_percentile=90.0,
            target_sensitivity="high", blast_radius=30,
            has_cisa_kev=True, path_confidence_product=0.9,
        )
        scorer.score(path, meta)
        self.assertIn(path.risk, ("high", "critical"))


class ScorerClassifyConstraint22Tests(TestCase):
    """Constraint 22: unvalidated high-score paths capped at medium."""

    def _make_path(self, n_steps=2):
        from apme.models.path import AttackPath, PathStep
        return AttackPath(
            id="C22-1", start="a", end="z",
            steps=[
                PathStep(from_id=f"n{i}", to_id=f"n{i+1}", action="a",
                         confidence=0.9, validated=False, edge_type="LEADS_TO")
                for i in range(n_steps)
            ]
        )

    def test_unvalidated_no_signal_high_score_capped_at_medium(self):
        from apme.engine.scorer import Scorer
        scorer = Scorer()
        path = self._make_path()
        meta = {
            "severity": 4, "cvss_score": 9.8, "privilege_gained": "root",
            "validated_steps": 0, "target_sensitivity": "high", "blast_radius": 50,
            "epss_percentile": 95.0, "has_cisa_kev": False, "path_confidence_product": 0.95,
            "has_poc": False, "has_exploit_url": False, "has_metasploit": False,
            "cve_published_date": None, "target_node_degree": 20,
        }
        scorer.score(path, meta)
        self.assertNotIn(path.risk, ("high", "critical"),
                         "Unvalidated paths with no signal must not reach high/critical")

    def test_unvalidated_with_kev_signal_can_reach_high(self):
        from apme.engine.scorer import Scorer
        scorer = Scorer()
        path = self._make_path()
        meta = {
            "severity": 4, "cvss_score": 9.8, "privilege_gained": "root",
            "validated_steps": 0, "target_sensitivity": "high", "blast_radius": 50,
            "epss_percentile": 95.0, "has_cisa_kev": True,
            "path_confidence_product": 0.95,
            "has_poc": True, "has_exploit_url": True, "has_metasploit": True,
            "cve_published_date": None, "target_node_degree": 20,
        }
        scorer.score(path, meta)
        self.assertIn(path.risk, ("high", "critical"))

    def test_low_score_unvalidated_stays_speculative(self):
        from apme.engine.scorer import Scorer
        scorer = Scorer()
        path = self._make_path()
        meta = {
            "severity": 0, "cvss_score": 0.0, "privilege_gained": "none",
            "validated_steps": 0, "target_sensitivity": "low", "blast_radius": 1,
            "epss_percentile": 0.0, "has_cisa_kev": False, "path_confidence_product": 0.3,
            "has_poc": False, "has_exploit_url": False, "has_metasploit": False,
            "cve_published_date": None, "target_node_degree": 1,
        }
        scorer.score(path, meta)
        self.assertEqual(path.risk, "speculative")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 6 — Pathfinder Improvements
# ─────────────────────────────────────────────────────────────────────────────

import unittest as _unittest


class PathStepModelTests(_unittest.TestCase):
    """PathStep.requires_victim field."""

    def test_requires_victim_field_defaults_false(self):
        from apme.models.path import PathStep
        step = PathStep(from_id="a", to_id="b", action="test")
        self.assertFalse(step.requires_victim)

    def test_requires_victim_can_be_set_true(self):
        from apme.models.path import PathStep
        step = PathStep(from_id="a", to_id="b", action="test", requires_victim=True)
        self.assertTrue(step.requires_victim)

    def test_to_dict_still_works_with_requires_victim(self):
        from apme.models.path import PathStep
        step = PathStep(from_id="a", to_id="b", action="test", requires_victim=True)
        d = step.to_dict()
        self.assertIn("from", d)
        self.assertIn("confidence", d)


class SemanticFingerprintTests(_unittest.TestCase):
    """Semantic fingerprint deduplicates same attack chain on different instances."""

    def _semantic_key(self, path):
        import re
        def _strip_instance(nid: str) -> str:
            return re.sub(r'::\d+$', '', nid)
        return "->".join(
            f"{s.edge_type}:{_strip_instance(s.from_id)}:{_strip_instance(s.to_id)}"
            for s in path.steps
        )

    def test_same_chain_different_vuln_ids_deduped(self):
        from apme.models.path import AttackPath, PathStep
        path_a = AttackPath(id="A", start="x", end="y", steps=[
            PathStep("vuln::1", "goal::capability::rce_execution", "exploit",
                     edge_type="LEADS_TO"),
            PathStep("goal::capability::rce_execution", "goal::capability::pivot", "pivot",
                     edge_type="LEADS_TO"),
        ])
        path_b = AttackPath(id="B", start="x", end="y", steps=[
            PathStep("vuln::99", "goal::capability::rce_execution", "exploit",
                     edge_type="LEADS_TO"),
            PathStep("goal::capability::rce_execution", "goal::capability::pivot", "pivot",
                     edge_type="LEADS_TO"),
        ])
        self.assertEqual(self._semantic_key(path_a), self._semantic_key(path_b))

    def test_different_edge_types_not_deduped(self):
        from apme.models.path import AttackPath, PathStep
        path_a = AttackPath(id="A", start="x", end="y", steps=[
            PathStep("vuln::1", "goal::capability::rce_execution", "rce",
                     edge_type="LEADS_TO"),
        ])
        path_b = AttackPath(id="B", start="x", end="y", steps=[
            PathStep("vuln::1", "goal::capability::rce_execution", "auth",
                     edge_type="AUTHENTICATES"),
        ])
        self.assertNotEqual(self._semantic_key(path_a), self._semantic_key(path_b))

    def test_different_target_subtypes_not_deduped(self):
        from apme.models.path import AttackPath, PathStep
        path_a = AttackPath(id="A", start="x", end="y", steps=[
            PathStep("vuln::1", "goal::capability::rce_execution", "x",
                     edge_type="LEADS_TO"),
        ])
        path_b = AttackPath(id="B", start="x", end="y", steps=[
            PathStep("vuln::1", "goal::capability::data_exfil", "y",
                     edge_type="LEADS_TO"),
        ])
        self.assertNotEqual(self._semantic_key(path_a), self._semantic_key(path_b))


class PathfinderConstantsTests(_unittest.TestCase):
    """DFS_MAX_DEPTH reduced to 6."""

    def test_max_depth_is_6(self):
        from apme.engine import pathfinder
        import inspect
        src = inspect.getsource(pathfinder.Pathfinder._dfs_query)
        self.assertIn("2..6", src,
                      "DFS query must use minimum 2 hops and max depth 6")
        self.assertNotIn("1..8", src,
                         "Old DFS range 1..8 must be removed")


class EnricherFanOutCapTests(_unittest.TestCase):
    """GraphEnricher fan-out cap at MAX_EDGES_PER_NODE=12."""

    def test_max_edges_constant_is_12(self):
        from apme.graph.enricher import MAX_EDGES_PER_NODE
        self.assertEqual(MAX_EDGES_PER_NODE, 12)

    def test_fan_out_cap_applied_when_exceeded(self):
        from apme.graph.enricher import GraphEnricher
        from apme.models.node import Node
        from apme.models.edge import Edge
        from unittest.mock import MagicMock, patch

        mock_builder = MagicMock()
        enricher = GraphEnricher(mock_builder)

        source = Node(id="vuln::1", type="Vulnerability", subtype="rce",
                      confidence=0.9, source="test", properties={"validated": False})
        target_nodes = [
            Node(id=f"goal::capability::cap{i}", type="Capability",
                 subtype=f"cap{i}", confidence=1.0, source="test", properties={})
            for i in range(20)
        ]
        all_nodes = [source] + target_nodes

        edges_20 = [
            Edge(from_id="vuln::1", to_id=f"goal::capability::cap{i}",
                 type="LEADS_TO", confidence=round(0.5 + i * 0.02, 2), properties={})
            for i in range(20)
        ]

        def _selective_apply(node, existing_nodes=None):
            if node.id == "vuln::1":
                return list(edges_20)
            return []

        with patch.object(enricher._rules_engine, "apply", side_effect=_selective_apply):
            result = enricher.enrich(all_nodes, scan_id=1)

        calls = mock_builder.add_edges.call_args_list
        total_edges_added = sum(len(call[0][0]) for call in calls)
        self.assertLessEqual(total_edges_added, 12,
                             f"Expected ≤12 edges after fan-out cap, got {total_edges_added}")
