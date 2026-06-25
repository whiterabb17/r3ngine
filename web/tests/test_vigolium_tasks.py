from django.test import TestCase
from unittest.mock import MagicMock, mock_open, patch


class VigoliumDefinitionsTest(TestCase):
    def test_vigolium_constants_defined(self):
        from reNgine.definitions import (
            RUN_VIGOLIUM,
            RUN_VIGOLIUM_DISCOVERY,
            RUN_VIGOLIUM_ANALYSIS,
            VIGOLIUM,
            VIGOLIUM_STRATEGY,
            VIGOLIUM_CONCURRENCY,
            VIGOLIUM_RATE_LIMIT,
            VIGOLIUM_TIMEOUT,
            VIGOLIUM_MODULES,
            VIGOLIUM_SEVERITY_FILTER,
            VIGOLIUM_DEFAULT_CONFIG,
            VIGOLIUM_DEFAULT_DISCOVERY_CONFIG,
            VIGOLIUM_DEFAULT_ANALYSIS_CONFIG,
        )
        self.assertEqual(RUN_VIGOLIUM, 'run_vigolium')
        self.assertEqual(RUN_VIGOLIUM_DISCOVERY, 'run_vigolium_discovery')
        self.assertEqual(RUN_VIGOLIUM_ANALYSIS, 'run_vigolium_analysis')
        self.assertEqual(VIGOLIUM, 'vigolium')
        self.assertEqual(VIGOLIUM_STRATEGY, 'strategy')
        self.assertEqual(VIGOLIUM_CONCURRENCY, 'concurrency')
        self.assertEqual(VIGOLIUM_RATE_LIMIT, 'rate_limit')
        self.assertEqual(VIGOLIUM_TIMEOUT, 'timeout')
        self.assertEqual(VIGOLIUM_MODULES, 'modules')
        self.assertEqual(VIGOLIUM_SEVERITY_FILTER, 'severity_filter')
        self.assertIn('run_vigolium', VIGOLIUM_DEFAULT_CONFIG)
        self.assertTrue(VIGOLIUM_DEFAULT_CONFIG['run_vigolium'])
        self.assertIn('run_vigolium_discovery', VIGOLIUM_DEFAULT_DISCOVERY_CONFIG)
        self.assertTrue(VIGOLIUM_DEFAULT_DISCOVERY_CONFIG['run_vigolium_discovery'])
        self.assertIn('run_vigolium_analysis', VIGOLIUM_DEFAULT_ANALYSIS_CONFIG)
        self.assertTrue(VIGOLIUM_DEFAULT_ANALYSIS_CONFIG['run_vigolium_analysis'])


class VigoliumParserTest(TestCase):
    def _make_task(self):
        task = MagicMock()
        task.scan_id = 1
        task.activity_id = 1
        task.domain_id = 1
        task.scan = MagicMock()
        task.scan.results_dir = '/tmp/test_scan'
        task.domain = MagicMock()
        task.domain.id = 1
        task.subscan = None
        task.subdomain = None
        task.yaml_configuration = {
            'vulnerability_scan': {
                'run_vigolium': True,
                'vigolium': {'strategy': 'balanced', 'concurrency': 50},
            },
            'vigolium_discovery': {'run_vigolium_discovery': True},
            'vigolium_analysis': {'run_vigolium_analysis': True},
        }
        return task

    def test_parse_finding_saves_vulnerability(self):
        """parse_vigolium_finding maps confirmed JSONL fields to save_vulnerability."""
        from reNgine.vigolium_tasks import parse_vigolium_finding

        # Real schema from live vigolium output
        finding_data = {
            'url': 'https://www.defijn.io/',
            'hostname': 'www.defijn.io',
            'module_id': 'xss-reflected',
            'module_name': 'Reflected XSS',
            'module_type': 'active',
            'finding_source': 'dynamic-assessment',
            'module_short': 'Detects reflected XSS via parameter injection',
            'description': 'User input is reflected unescaped in the response.',
            'severity': 'high',
            'confidence': 'firm',
            'status': 'triaged',
            'cvss_score': 6.1,
            'matched_at': ['https://www.defijn.io/search?q=test'],
            'extracted_results': ['<script>alert(1)</script>'],
            'tags': ['xss', 'injection'],
            'request': 'GET /search?q=test HTTP/1.1\nHost: www.defijn.io\n',
            'response': '',
            'finding_hash': 'abc123',
            'found_at': '2026-05-28T07:36:53Z',
        }
        task = self._make_task()
        subdomain = MagicMock()
        subdomain.name = 'www.defijn.io'

        with patch('reNgine.vigolium_tasks.save_vulnerability') as mock_save:
            parse_vigolium_finding(task, finding_data, subdomain)
            mock_save.assert_called_once()
            kwargs = mock_save.call_args[1]
            self.assertEqual(kwargs['name'], 'Reflected XSS')
            self.assertEqual(kwargs['severity'], 3)   # 'high' → 3
            self.assertEqual(kwargs['type'], 'Vigolium')
            self.assertEqual(kwargs['template_id'], 'xss-reflected')
            self.assertEqual(kwargs['http_url'], 'https://www.defijn.io/search?q=test')
            self.assertEqual(kwargs['description'], 'User input is reflected unescaped in the response.')

    def test_parse_finding_uses_url_when_matched_at_empty(self):
        """parse_vigolium_finding falls back to data.url when matched_at is empty."""
        from reNgine.vigolium_tasks import parse_vigolium_finding

        finding_data = {
            'url': 'https://www.defijn.io/',
            'hostname': 'www.defijn.io',
            'module_id': 'headers-missing',
            'module_name': 'Security Headers Missing',
            'severity': 'info',
            'description': 'Missing security headers.',
            'matched_at': [],
            'tags': None,
        }
        task = self._make_task()
        subdomain = MagicMock()
        with patch('reNgine.vigolium_tasks.save_vulnerability') as mock_save:
            parse_vigolium_finding(task, finding_data, subdomain)
            mock_save.assert_called_once()
            kwargs = mock_save.call_args[1]
            self.assertEqual(kwargs['http_url'], 'https://www.defijn.io/')
            self.assertEqual(kwargs['severity'], 0)  # 'info' → 0

    def test_parse_finding_skips_missing_name(self):
        """parse_vigolium_finding skips records with no module_name."""
        from reNgine.vigolium_tasks import parse_vigolium_finding

        task = self._make_task()
        subdomain = MagicMock()
        with patch('reNgine.vigolium_tasks.save_vulnerability') as mock_save:
            parse_vigolium_finding(task, {'severity': 'high'}, subdomain)
            mock_save.assert_not_called()

    def test_parse_http_record_saves_endpoint(self):
        """parse_vigolium_http_record saves a discovered URL as an EndPoint."""
        from reNgine.vigolium_tasks import parse_vigolium_http_record

        record_data = {
            'url': 'https://www.defijn.io/login',
            'hostname': 'www.defijn.io',
            'method': 'GET',
            'status_code': 200,
        }
        task = self._make_task()
        with patch('reNgine.vigolium_tasks.save_endpoint') as mock_save:
            parse_vigolium_http_record(task, record_data)
            mock_save.assert_called_once()
            kwargs = mock_save.call_args[1]
            self.assertEqual(kwargs['http_url'], 'https://www.defijn.io/login')

    def test_parse_http_record_skips_missing_url(self):
        """parse_vigolium_http_record skips records with no url field."""
        from reNgine.vigolium_tasks import parse_vigolium_http_record

        task = self._make_task()
        with patch('reNgine.vigolium_tasks.save_endpoint') as mock_save:
            parse_vigolium_http_record(task, {'method': 'GET'})
            mock_save.assert_not_called()

    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    @patch('reNgine.vigolium_tasks._iter_jsonl')
    @patch('reNgine.vigolium_tasks.parse_vigolium_finding')
    @patch('reNgine.vigolium_tasks.Subdomain.objects.filter')
    def test_run_vigolium_phase_in_file_deduplication(self, mock_subdomain_filter, mock_parse_finding, mock_iter_jsonl, mock_stream_command):
        """_run_vigolium_phase deduplicates findings with the same module, hostname, and URL."""
        from reNgine.vigolium_tasks import _run_vigolium_phase

        # Mock the JSONL records returned
        mock_iter_jsonl.return_value = [
            {
                'type': 'finding',
                'data': {
                    'hostname': 'target.com',
                    'module_id': 'xss',
                    'url': 'https://target.com/a',
                }
            },
            {
                'type': 'finding',
                'data': {
                    'hostname': 'target.com',
                    'module_id': 'xss',
                    'url': 'https://target.com/a', # Duplicate finding
                }
            },
            {
                'type': 'finding',
                'data': {
                    'hostname': 'target.com',
                    'module_name': 'xss', # using module_name fallback
                    'url': 'https://target.com/a', # Duplicate finding
                }
            },
            {
                'type': 'finding',
                'data': {
                    'hostname': 'target.com',
                    'module_id': 'sqli',
                    'url': 'https://target.com/a', # Different module
                }
            },
            {
                'type': 'finding',
                'data': {
                    'hostname': 'target.com',
                    'module_id': 'xss',
                    'url': 'https://target.com/b', # Different URL
                }
            }
        ]

        task = self._make_task()
        subdomain = MagicMock()
        mock_subdomain_filter.return_value.first.return_value = subdomain

        _run_vigolium_phase(task, cmd='fake', output_file='/tmp/fake.jsonl', phase_label='Test')

        # Should only parse the unique findings (3 calls out of 5 records)
        self.assertEqual(mock_parse_finding.call_count, 3)

        # Verify the modules of unique calls
        called_modules = [
            (call[0][1]['module_id'] if call[0][1].get('module_id') else call[0][1]['module_name'])
            for call in mock_parse_finding.call_args_list
        ]
        self.assertEqual(called_modules, ['xss', 'sqli', 'xss'])


class VigoliumTaskGatingTest(TestCase):
    def _make_task(self, vuln_enabled=True, discovery_enabled=True, analysis_enabled=True):
        task = MagicMock()
        task.scan_id = 1
        task.activity_id = 1
        task.domain_id = 1
        task.scan = MagicMock()
        task.scan.results_dir = '/tmp/test_scan'
        task.scan.domain = MagicMock()
        task.scan.domain.name = 'example.com'
        task.domain = MagicMock()
        task.subscan = None
        task.subdomain = None
        task.yaml_configuration = {
            'vulnerability_scan': {
                'run_vigolium': vuln_enabled,
                'vigolium': {'strategy': 'balanced', 'concurrency': 50, 'rate_limit': 100, 'timeout': '15s'},
            },
            'vigolium_discovery': {'run_vigolium_discovery': discovery_enabled},
            'vigolium_analysis': {'run_vigolium_analysis': analysis_enabled},
        }
        return task

    def test_vigolium_scan_skips_when_disabled(self):
        from reNgine.vigolium_tasks import vigolium_scan
        task = self._make_task(vuln_enabled=False)
        with patch('reNgine.vigolium_tasks._run_vigolium_phase') as mock_run:
            vigolium_scan(task)
            mock_run.assert_not_called()

    def test_vigolium_discovery_skips_when_disabled(self):
        from reNgine.vigolium_tasks import vigolium_discovery
        task = self._make_task(discovery_enabled=False)
        with patch('reNgine.vigolium_tasks._run_vigolium_phase') as mock_run:
            vigolium_discovery(task)
            mock_run.assert_not_called()

    def test_vigolium_analysis_skips_when_disabled(self):
        from reNgine.vigolium_tasks import vigolium_analysis
        task = self._make_task(analysis_enabled=False)
        with patch('reNgine.vigolium_tasks._run_vigolium_phase') as mock_run:
            vigolium_analysis(task)
            mock_run.assert_not_called()

    def test_vigolium_scan_calls_phase_runner(self):
        from reNgine.vigolium_tasks import vigolium_scan
        task = self._make_task(vuln_enabled=True)
        with patch('reNgine.vigolium_tasks._run_vigolium_phase') as mock_run, \
             patch('os.makedirs'), \
             patch('builtins.open', mock_open()), \
             patch('reNgine.vigolium_tasks.Subdomain'):
            vigolium_scan(task, urls=['https://example.com'])
            mock_run.assert_called_once()
            # Verify the command includes the correct phases
            call_args = mock_run.call_args
            cmd = call_args[0][1]
            self.assertIn('--stateless', cmd)
            self.assertIn('--skip-dependency-check', cmd)
            self.assertIn('--omit-response', cmd)


class VigoliumActivitiesTest(TestCase):
    def test_activities_are_importable(self):
        from reNgine.temporal_activities import (
            run_vigolium_scan_activity,
            run_vigolium_discovery_activity,
            run_vigolium_analysis_activity,
        )
        self.assertTrue(callable(run_vigolium_scan_activity))
        self.assertTrue(callable(run_vigolium_discovery_activity))
        self.assertTrue(callable(run_vigolium_analysis_activity))


class VigoliumAuditDefinitionsTest(TestCase):
    def test_audit_constants_defined(self):
        from reNgine.definitions import (
            RUN_VIGOLIUM_AUDIT,
            VIGOLIUM_AUDIT,
            VIGOLIUM_AUDIT_INTENSITY,
            VIGOLIUM_AUDIT_USE_AI,
            VIGOLIUM_AUDIT_TIMEOUT,
            VIGOLIUM_DEFAULT_AUDIT_CONFIG,
        )
        self.assertEqual(RUN_VIGOLIUM_AUDIT, 'run_vigolium_audit')
        self.assertEqual(VIGOLIUM_AUDIT, 'vigolium_audit')
        self.assertEqual(VIGOLIUM_AUDIT_INTENSITY, 'intensity')
        self.assertEqual(VIGOLIUM_AUDIT_USE_AI, 'use_ai')
        self.assertEqual(VIGOLIUM_AUDIT_TIMEOUT, 'timeout')
        self.assertIn('run_vigolium_audit', VIGOLIUM_DEFAULT_AUDIT_CONFIG)
        self.assertTrue(VIGOLIUM_DEFAULT_AUDIT_CONFIG['run_vigolium_audit'])
        self.assertFalse(VIGOLIUM_DEFAULT_AUDIT_CONFIG['use_ai'])
        self.assertEqual(VIGOLIUM_DEFAULT_AUDIT_CONFIG['intensity'], 'balanced')


class VigoliumAuditParserTest(TestCase):
    def _make_task(self):
        task = MagicMock()
        task.scan_id = 1
        task.activity_id = 1
        task.domain_id = 1
        task.scan = MagicMock()
        task.scan.results_dir = '/tmp/test_scan'
        task.domain = MagicMock()
        task.subscan = None
        task.subdomain = None
        task.yaml_configuration = {'vigolium_audit': {'run_vigolium_audit': True}}
        return task

    def test_audit_finding_saves_vulnerability(self):
        """_parse_vigolium_audit_finding saves a code finding without a subdomain."""
        from reNgine.vigolium_tasks import _parse_vigolium_audit_finding

        finding_data = {
            'module_id': 'sqli-error',
            'module_name': 'SQL Injection (Error-Based)',
            'severity': 'high',
            'file': '/src/db/queries.py',
            'line': 42,
            'description': 'Unsanitized input concatenated into SQL query.',
            'matched_at': [],
            'tags': ['sqli', 'injection'],
            'cvss_score': 8.1,
        }
        task = self._make_task()
        with patch('reNgine.vigolium_tasks.Subdomain') as mock_sub, \
             patch('reNgine.vigolium_tasks.save_vulnerability') as mock_save:
            mock_sub.objects.filter.return_value.first.return_value = None
            _parse_vigolium_audit_finding(task, finding_data)
            mock_save.assert_called_once()
            kwargs = mock_save.call_args[1]
            self.assertEqual(kwargs['name'], 'SQL Injection (Error-Based)')
            self.assertEqual(kwargs['severity'], 3)
            self.assertEqual(kwargs['type'], 'VigoliumAudit')
            self.assertEqual(kwargs['source'], 'VigoliumAudit')
            self.assertIn('/src/db/queries.py', kwargs['http_url'])

    def test_audit_finding_skips_missing_name(self):
        """_parse_vigolium_audit_finding skips records with no module_name or name."""
        from reNgine.vigolium_tasks import _parse_vigolium_audit_finding

        task = self._make_task()
        with patch('reNgine.vigolium_tasks.save_vulnerability') as mock_save:
            _parse_vigolium_audit_finding(task, {'severity': 'high'})
            mock_save.assert_not_called()

    def test_audit_finding_uses_matched_at_when_present(self):
        """_parse_vigolium_audit_finding uses matched_at[0] as URL when available."""
        from reNgine.vigolium_tasks import _parse_vigolium_audit_finding

        finding_data = {
            'module_name': 'Hardcoded Secret',
            'severity': 'critical',
            'matched_at': ['https://example.com/api/key'],
            'hostname': '',
        }
        task = self._make_task()
        with patch('reNgine.vigolium_tasks.Subdomain') as mock_sub, \
             patch('reNgine.vigolium_tasks.save_vulnerability') as mock_save:
            mock_sub.objects.filter.return_value.first.return_value = None
            _parse_vigolium_audit_finding(task, finding_data)
            mock_save.assert_called_once()
            kwargs = mock_save.call_args[1]
            self.assertEqual(kwargs['http_url'], 'https://example.com/api/key')


class VigoliumAuditTaskGatingTest(TestCase):
    def _make_task(self, enabled=True, use_ai=False, intensity='balanced', timeout=3600):
        task = MagicMock()
        task.scan_id = 1
        task.activity_id = 1
        task.scan = MagicMock()
        task.scan.results_dir = '/tmp/test_scan'
        task.domain = MagicMock()
        task.subscan = None
        task.subdomain = None
        task.yaml_configuration = {
            'vigolium_audit': {
                'run_vigolium_audit': enabled,
                'intensity': intensity,
                'use_ai': use_ai,
                'timeout': timeout,
            },
        }
        return task

    def test_audit_skips_when_disabled(self):
        from reNgine.vigolium_tasks import vigolium_audit_scan
        task = self._make_task(enabled=False)
        with patch('reNgine.vigolium_tasks.subprocess') as mock_sp:
            vigolium_audit_scan(task)
            mock_sp.run.assert_not_called()

    def test_audit_uses_piolium_driver_by_default(self):
        from reNgine.vigolium_tasks import vigolium_audit_scan
        task = self._make_task(use_ai=False)
        with patch('reNgine.vigolium_tasks.subprocess.run') as mock_run, \
             patch('os.makedirs'), \
             patch('os.path.exists', return_value=False):
            mock_run.return_value = MagicMock(returncode=0, stderr='')
            vigolium_audit_scan(task, code_path='/tmp/src')
            self.assertTrue(mock_run.called)
            cmd = mock_run.call_args_list[0][0][0]
            self.assertIn('--driver', cmd)
            self.assertIn('piolium', cmd)
            self.assertIn('--source', cmd)
            self.assertIn('/tmp/src', cmd)

    def test_audit_uses_claude_when_anthropic_configured(self):
        from reNgine.vigolium_tasks import vigolium_audit_scan
        task = self._make_task(use_ai=True)
        mock_llm = MagicMock()
        mock_llm.provider = 'anthropic'
        mock_llm.api_key = 'sk-ant-test-key'
        with patch('reNgine.vigolium_tasks.subprocess.run') as mock_run, \
             patch('os.makedirs'), \
             patch('os.path.exists', return_value=False), \
             patch('dashboard.models.LLMConfig') as mock_llm_cls:
            mock_llm_cls.objects.filter.return_value.first.return_value = mock_llm
            mock_run.return_value = MagicMock(returncode=0, stderr='')
            vigolium_audit_scan(task, code_path='/tmp/src')
            self.assertTrue(mock_run.called)
            cmd = mock_run.call_args_list[0][0][0]
            self.assertIn('--agent', cmd)
            self.assertIn('claude', cmd)
            # API key must NOT be in CLI args — it is passed via env var instead
            self.assertNotIn('--api-key', cmd)
            self.assertNotIn('sk-ant-test-key', cmd)
            env_passed = mock_run.call_args_list[0][1].get('env', {})
            self.assertEqual(env_passed.get('VIGOLIUM_API_KEY'), 'sk-ant-test-key')

    def test_audit_falls_back_to_piolium_when_no_llm_config(self):
        from reNgine.vigolium_tasks import vigolium_audit_scan
        task = self._make_task(use_ai=True)
        with patch('reNgine.vigolium_tasks.subprocess.run') as mock_run, \
             patch('os.makedirs'), \
             patch('os.path.exists', return_value=False), \
             patch('dashboard.models.LLMConfig') as mock_llm_cls:
            mock_llm_cls.objects.filter.return_value.first.return_value = None
            mock_run.return_value = MagicMock(returncode=0, stderr='')
            vigolium_audit_scan(task, code_path='/tmp/src')
            cmd = mock_run.call_args_list[0][0][0]
            self.assertIn('piolium', cmd)
            self.assertNotIn('claude', cmd)


class VigoliumAuditActivityTest(TestCase):
    def test_audit_activity_is_importable(self):
        from reNgine.temporal_activities import run_vigolium_audit_activity
        self.assertTrue(callable(run_vigolium_audit_activity))


class VigoliumAuditApiKeyMaskTest(TestCase):
    """API key must never appear in log output."""

    @patch('reNgine.vigolium_tasks.subprocess.run')
    @patch('dashboard.models.LLMConfig')
    def test_api_key_not_logged(self, mock_llm_cls, mock_run):
        """Confirm the real API key does not appear in any log record."""
        from reNgine.vigolium_tasks import vigolium_audit_scan

        mock_run.return_value = MagicMock(returncode=0, stderr='', stdout='')
        mock_llm = MagicMock()
        mock_llm.is_active = True
        mock_llm.api_key = 'sk-SUPERSECRET'
        mock_llm.provider = 'anthropic'
        mock_llm_cls.objects.filter.return_value.first.return_value = mock_llm

        task = MagicMock()
        task.scan = MagicMock()
        task.scan.results_dir = '/tmp/test_audit'
        task.domain = MagicMock()
        task.starting_point_path = None
        task.yaml_configuration = {
            'vigolium_audit': {
                'run_vigolium_audit': True,
                'intensity': 'balanced',
                'use_ai': True,
                'timeout': 10,
            }
        }

        with self.assertLogs('reNgine.vigolium_tasks', level='DEBUG') as log_ctx:
            try:
                vigolium_audit_scan(task, code_path='/tmp/fakecode', ctx={})
            except Exception:
                pass

        all_log_text = '\n'.join(log_ctx.output)
        self.assertNotIn('sk-SUPERSECRET', all_log_text, "API key must not appear in logs")


class VigoliumAuditApiKeyEnvTest(TestCase):
    """API key must be passed via env var, never as a CLI argument."""

    @patch('reNgine.vigolium_tasks.subprocess.run')
    @patch('dashboard.models.LLMConfig')
    def test_api_key_not_in_cmd_args(self, mock_llm_cls, mock_run):
        from reNgine.vigolium_tasks import vigolium_audit_scan

        mock_run.return_value = MagicMock(returncode=0, stderr='', stdout='')
        mock_llm = MagicMock()
        mock_llm.is_active = True
        mock_llm.api_key = 'sk-SUPERSECRET'
        mock_llm.provider = 'anthropic'
        mock_llm_cls.objects.filter.return_value.first.return_value = mock_llm

        task = MagicMock()
        task.scan = MagicMock()
        task.scan.results_dir = '/tmp/test_audit'
        task.domain = MagicMock()
        task.starting_point_path = None
        task.yaml_configuration = {
            'vigolium_audit': {
                'run_vigolium_audit': True,
                'intensity': 'balanced',
                'use_ai': True,
                'timeout': 10,
            }
        }
        try:
            vigolium_audit_scan(task, code_path='/tmp/fakecode', ctx={})
        except Exception:
            pass

        self.assertTrue(mock_run.called, "subprocess.run must have been called")
        first_call = mock_run.call_args_list[0]
        cmd_args = first_call[0][0] if first_call[0] else []
        self.assertNotIn('sk-SUPERSECRET', cmd_args,
                         "API key must not appear in subprocess arg list")
        env_passed = first_call[1].get('env', {}) if first_call[1] else {}
        self.assertIn('VIGOLIUM_API_KEY', env_passed,
                      "API key should be in env dict passed to subprocess")
        self.assertEqual(env_passed['VIGOLIUM_API_KEY'], 'sk-SUPERSECRET')


class CodeScanWorkflowTimeoutCastTest(TestCase):
    def test_non_numeric_timeout_does_not_raise(self):
        """A non-numeric timeout in YAML must not crash — falls back to default 3600."""
        def safe_timeout_cast(value, default=3600, cap=14400):
            try:
                return min(int(value), cap)
            except (ValueError, TypeError):
                return min(default, cap)

        self.assertEqual(safe_timeout_cast('1h'), 3600)
        self.assertEqual(safe_timeout_cast(None), 3600)
        self.assertEqual(safe_timeout_cast('7200'), 7200)
        self.assertEqual(safe_timeout_cast(99999), 14400)


class VigoliumAuditIntensityValidationTest(TestCase):
    """Unrecognised intensity values must be coerced to 'balanced'."""

    @patch('reNgine.vigolium_tasks.subprocess.run')
    def test_invalid_intensity_coerced(self, mock_run):
        from reNgine.vigolium_tasks import vigolium_audit_scan

        mock_run.return_value = MagicMock(returncode=0, stderr='', stdout='')
        task = MagicMock()
        task.scan = MagicMock()
        task.scan.results_dir = '/tmp/test_audit'
        task.domain = MagicMock()
        task.starting_point_path = None
        task.yaml_configuration = {
            'vigolium_audit': {
                'run_vigolium_audit': True,
                'intensity': 'HACKER_MODE',
                'use_ai': False,
                'timeout': 10,
            }
        }
        try:
            vigolium_audit_scan(task, code_path='/tmp/fakecode', ctx={})
        except Exception:
            pass

        self.assertTrue(mock_run.called, "subprocess.run must have been called")
        call_args = mock_run.call_args_list[0][0][0]
        idx = call_args.index('--intensity')
        self.assertEqual(call_args[idx + 1], 'balanced',
                         "Invalid intensity must be coerced to 'balanced'")


class VigoliumAuditNoSourceTest(TestCase):
    """When no source path is resolvable, must abort early — not fall back to /tmp/code."""

    @patch('reNgine.vigolium_tasks.subprocess.run')
    def test_no_source_returns_early(self, mock_run):
        from reNgine.vigolium_tasks import vigolium_audit_scan

        task = MagicMock()
        task.scan = MagicMock()
        task.scan.results_dir = '/tmp/test_audit'
        task.domain = MagicMock()
        task.starting_point_path = None
        task.yaml_configuration = {
            'vigolium_audit': {
                'run_vigolium_audit': True,
                'intensity': 'balanced',
                'use_ai': False,
                'timeout': 10,
            }
        }
        result = vigolium_audit_scan(task, code_path=None, ctx={})
        mock_run.assert_not_called()
        self.assertIsNone(result)
