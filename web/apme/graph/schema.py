"""
APME Configuration

Defines canonical node types and subtypes for the attack graph.
"""

NODE_TYPES = {
    "Asset": ["domain", "ip", "service", "host", "endpoint"],
    "Vulnerability": [
        # Injection
        "sqli", "command_injection", "code_injection", "nosql_injection",
        "xpath_injection", "ldap_injection", "log_injection",
        # Template / Server
        "rce", "ssti", "ssrf", "xxe",
        # File
        "lfi", "path_traversal", "file_upload",
        # Deserialization
        "deserialization",
        # Auth / Identity
        "misconfig", "jwt_abuse", "oauth_misconfig", "idor",
        "crlf_injection", "host_header",
        # Client-side
        "xss", "open_redirect", "clickjacking", "csrf",
        # Info
        "cors", "graphql_injection", "prototype_pollution",
        # Cloud / Supply chain
        "s3_misconfig", "subdomain_takeover", "dns_rebinding",
        "dependency_confusion",
        # Fallbacks
        "generic", "generic_high", "generic_critical",
        # Enhancement 2 — Blind injection variants
        "blind_sqli", "blind_ssrf", "blind_xss", "blind_cmdi",
        "second_order_sqli", "ognl_injection",
        # Enhancement 2 — Network / protocol
        "http_request_smuggling", "tls_downgrade", "dns_cache_poisoning",
        "cache_poisoning", "web_cache_deception", "reflected_file_download",
        # Enhancement 2 — Container / infra
        "docker_socket_exposed", "container_escape", "privileged_container",
        "k8s_rbac_misconfig", "k8s_secret_exposure",
        # Enhancement 2 — Active Directory
        "ntlm_relay", "pass_the_hash", "pass_the_ticket",
        "kerberoasting", "asrep_roasting", "dcsync_privilege", "gpo_abuse",
        # Enhancement 2 — Modern API / web
        "websocket_hijacking", "mass_assignment", "parameter_pollution",
        "graphql_mutation_abuse", "api_versioning_bypass",
        "race_condition", "account_enumeration", "session_fixation",
        "business_logic_bypass", "parameter_tampering",
        # Enhancement 2 — Auth / SSO
        "saml_signature_wrapping", "sso_bypass", "oauth_token_theft", "pkce_bypass",
        # Enhancement 2 — Email
        "spf_dmarc_bypass", "email_header_injection",
        # Enhancement 2 — Supply chain
        "typosquatting", "compromised_registry", "ci_artifact_poisoning",
        "github_actions_injection",
        # Enhancement 2 — .NET
        "aspnet_viewstate", "machinekey_exploitation",
        # Enhancement 2 — Misc
        "http_method_tampering", "nginx_alias_traversal",
    ],
    "Credential": [
        "api_key", "password", "token", "certificate", "ssh_key",
        "cloud_api_key", "jwt_token", "github_token", "db_password",
        "generic_secret",
    ],
    "Identity":  ["user", "admin", "service_account"],
    "Privilege": ["user", "admin", "domain_admin", "root"],
    "Network":   ["internet", "external", "internal", "dmz"],
    "Technology": [
        "wordpress", "php", "java", "python", "nodejs",
        "nginx", "apache", "spring", "jenkins", "generic",
        # Enhancement 2 additions
        "dotnet", "ruby", "rails", "react", "angular", "vue",
        "kubernetes", "docker", "terraform", "ansible",
        "drupal", "joomla", "magento", "laravel",
        "mssql", "oracle", "redis", "elasticsearch", "mongodb",
        "exchange", "active_directory", "ldap",
    ],
    "Capability": [
        # Original
        "db_access", "data_exfil", "rce_execution", "authenticated_access",
        "pivot", "cloud_access", "internal_discovery",
        # New
        "account_takeover", "session_hijacking", "phishing_amplification",
        "persistence", "code_exfiltration", "credential_harvesting",
        "lateral_movement", "metadata_access", "hvt_compromise",
        "supply_chain_compromise", "dos_capability",
        # Enhancement 2 additions
        "domain_controller_compromise", "kerberos_ticket_forgery",
        "container_escape_capability", "k8s_cluster_access",
        "email_account_compromise", "email_spoofing",
        "cache_poisoning_execution", "ci_pipeline_execution",
        "registry_persistence", "scheduled_task_persistence",
        "saml_assertion_forgery", "shadow_credentials", "webshell_persistence",
    ],
}

EDGE_TYPES = [
    "RESOLVES_TO",    # domain -> ip
    "HOSTS",          # ip -> service
    "EXPOSES",        # service/asset -> vulnerability
    "LEADS_TO",       # vulnerability/capability -> capability
    "AUTHENTICATES",  # credential -> service
    "ESCALATES_TO",   # identity -> privilege
    "TRUSTS",         # system -> system
    "CONNECTED_TO",   # network pivot
    "USES_TECH",      # asset -> technology
]
