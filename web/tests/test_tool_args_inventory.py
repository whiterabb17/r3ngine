"""Tests for tool inventory sync, arg schema cache, and validation."""
import json
import os
from django.contrib.auth import get_user_model
from django.test import TestCase, TransactionTestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role
from unittest.mock import patch

from dashboard.models import Project
from reNgine.definitions import SUCCESS_TASK
from reNgine.tool_args import (
    ToolArgsError,
    parse_help_text,
    validate_tool_args,
    get_or_refresh_schema,
)
from scanEngine.models import EngineType, InstalledExternalTool, ToolArgSchemaCache
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain

User = get_user_model()


class ToolArgsParseTests(TestCase):
    def test_parse_help_and_denylist(self):
        help_text = """
Usage:
  nuclei [flags]

Flags:
  -c, --concurrency int         number of templates (default 25)
  -rl, --rate-limit int         max requests per second
  -u, --url string              target URL (denied)
  -update                       update nuclei templates (denied)
  -s, --severity string[]     severities
"""
        schema = parse_help_text(help_text)
        names = {e['name'] for e in schema}
        self.assertIn('concurrency', names)
        self.assertIn('rate-limit', names)
        self.assertIn('severity', names)
        self.assertNotIn('url', names)
        self.assertNotIn('update', names)

    def test_validate_rejects_unknown_and_target(self):
        with self.assertRaises(ToolArgsError):
            validate_tool_args('port_scan', {'not-a-real-flag': 1}, schema_payload={
                'schema': [
                    {'name': 'threads', 'long_flag': '--threads', 'type': 'int', 'takes_value': True},
                ],
            })
        with self.assertRaises(ToolArgsError):
            validate_tool_args('port_scan', {'url': 'https://evil.example'}, schema_payload={
                'schema': [
                    {'name': 'url', 'long_flag': '-u', 'type': 'string', 'takes_value': True},
                ],
            })
        with self.assertRaises(ToolArgsError):
            validate_tool_args('port_scan', {'ports': '80 -host evil.internal'}, schema_payload={
                'schema': [
                    {'name': 'ports', 'long_flag': '-p', 'type': 'string', 'takes_value': True},
                ],
            })

    def test_singular_activity_name_helpers(self):
        from reNgine.task_plan import (
            is_singular_activity_name,
            pipeline_task_name,
            singular_activity_name,
            get_task_tier,
        )
        self.assertEqual(singular_activity_name('port_scan'), 'single_tool_port_scan')
        self.assertEqual(singular_activity_name('single_tool_port_scan'), 'single_tool_port_scan')
        self.assertEqual(pipeline_task_name('single_tool_port_scan'), 'port_scan')
        self.assertEqual(pipeline_task_name('port_scan'), 'port_scan')
        self.assertTrue(is_singular_activity_name('single_tool_waf_detection'))
        self.assertFalse(is_singular_activity_name('waf_detection'))
        self.assertEqual(get_task_tier('single_tool_port_scan'), get_task_tier('port_scan'))

    def test_validate_accepts_known(self):
        result = validate_tool_args('port_scan', {'threads': 10}, schema_payload={
            'schema': [
                {'name': 'threads', 'long_flag': '--threads', 'type': 'int', 'takes_value': True},
            ],
        })
        self.assertEqual(result['sanitized']['threads'], 10)
        self.assertIn('--threads', result['extra_cli_args'])
        self.assertEqual(result['yaml_overlay'].get('threads'), 10)

    def test_ports_string_becomes_list_and_rate_maps_for_naabu(self):
        from reNgine.tool_args import merge_yaml_overlay

        result = validate_tool_args('port_scan', {'ports': '8080,443', 'rate': 150}, schema_payload={
            'schema': [
                {'name': 'ports', 'long_flag': '-p', 'type': 'string', 'takes_value': True},
                {'name': 'rate', 'long_flag': '-rate', 'type': 'int', 'takes_value': True},
            ],
        })
        self.assertEqual(result['yaml_overlay']['ports'], ['8080', '443'])
        self.assertEqual(result['yaml_overlay']['rate'], 150)
        merged = merge_yaml_overlay({}, 'port_scan', {'ports': '80,443', 'rate_limit': 200})
        self.assertEqual(merged['port_scan']['ports'], ['80', '443'])
        self.assertEqual(merged['port_scan']['rate'], 200)

    def test_nuclei_severity_and_dalfox_section_merge(self):
        from reNgine.tool_args import merge_yaml_overlay

        result = validate_tool_args('nuclei_scan', {'severity': 'critical,high'}, schema_payload={
            'schema': [
                {'name': 'severity', 'long_flag': '-s', 'type': 'string', 'takes_value': True},
            ],
        })
        self.assertEqual(result['yaml_overlay']['severities'], ['critical', 'high'])
        merged_n = merge_yaml_overlay({}, 'nuclei_scan', result['yaml_overlay'])
        self.assertEqual(
            merged_n['vulnerability_scan']['nuclei']['severities'],
            ['critical', 'high'],
        )
        merged_d = merge_yaml_overlay({}, 'dalfox_xss_scan', {'threads': 8, 'delay': 100})
        self.assertEqual(merged_d['vulnerability_scan']['dalfox']['threads'], 8)
        self.assertEqual(merged_d['vulnerability_scan']['dalfox']['delay'], 100)
        self.assertNotIn('dalfox_xss_scan', merged_d)

    def test_http_crawl_threads_and_waf_yaml_only(self):
        from reNgine.tool_args import merge_yaml_overlay

        result = validate_tool_args('http_crawl', {'threads': 25}, schema_payload={
            'schema': [
                {'name': 'threads', 'long_flag': '-t', 'type': 'int', 'takes_value': True},
            ],
        })
        self.assertEqual(result['yaml_overlay']['threads'], 25)
        self.assertEqual(result['extra_cli_args'][:2], ['-t', '25'])
        merged = merge_yaml_overlay({}, 'http_crawl', result['yaml_overlay'])
        self.assertEqual(merged['http_crawl']['threads'], 25)

        waf = validate_tool_args('waf_detection', {'enable_http_crawl': True}, schema_payload={
            'schema': [
                {'name': 'enable_http_crawl', 'long_flag': '', 'type': 'bool', 'takes_value': False},
            ],
        })
        self.assertEqual(waf['extra_cli_args'], [])
        self.assertTrue(waf['yaml_overlay']['enable_http_crawl'])
        merged_w = merge_yaml_overlay({}, 'waf_detection', waf['yaml_overlay'])
        self.assertTrue(merged_w['waf_detection']['enable_http_crawl'])


class ToolInventorySyncTests(TestCase):
    def test_sync_marks_missing_and_present(self):
        from reNgine.tool_inventory import sync_installed_tools

        tool = InstalledExternalTool.objects.create(
            name='__missing_tool_xyz__',
            description='x',
            github_url='https://example.com',
            install_command='echo x',
            is_default=True,
        )
        with patch('reNgine.tool_inventory.resolve_binary_path', return_value=None):
            result = sync_installed_tools(probe_versions=False)
        tool.refresh_from_db()
        self.assertFalse(tool.is_present)
        self.assertGreaterEqual(result['missing'], 1)

        with patch('reNgine.tool_inventory.resolve_binary_path', return_value='/usr/local/bin/naabu'):
            with patch('reNgine.tool_inventory.os.path.isfile', return_value=True):
                with patch('reNgine.tool_inventory.probe_version', return_value=('1.2.3', None)):
                    InstalledExternalTool.objects.filter(pk=tool.pk).update(name='naabu')
                    sync_installed_tools(probe_versions=True)
        tool.refresh_from_db()
        self.assertTrue(tool.is_present)
        self.assertEqual(tool.resolved_path, '/usr/local/bin/naabu')
        self.assertEqual(tool.detected_version, '1.2.3')


class ToolArgsApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='tool-args', password='x')
        assign_role(self.user, 'penetration_tester')
        self.client = APIClient()
        self.client.force_login(self.user)
        self.project = Project.objects.create(
            name='TA', slug='ta-project', insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(engine_name='E', yaml_configuration='port_scan: {}\n')
        self.domain = Domain.objects.create(
            name='ta.example.com', project=self.project, insert_date=timezone.now(),
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=SUCCESS_TASK,
            start_scan_date=timezone.now(),
            tasks=['port_scan'],
        )
        self.sub = Subdomain.objects.create(
            name='ta.example.com',
            target_domain=self.domain,
            scan_history=self.scan,
        )

    def test_get_args_seed_fallback(self):
        res = self.client.get('/api/action/tool/port_scan/args/')
        self.assertEqual(res.status_code, 200, res.content)
        body = res.json()
        self.assertEqual(body['pipeline_tool'], 'port_scan')
        self.assertTrue(isinstance(body['schema'], list))
        self.assertTrue(len(body['schema']) >= 1)

    @patch('api.tool_run.TemporalClientProvider.get_client')
    @patch('api.tool_run.run_and_close', return_value=None)
    def test_run_with_tool_args(self, _run, _client):
        args_res = self.client.get('/api/action/tool/port_scan/args/')
        self.assertEqual(args_res.status_code, 200, args_res.content)
        schema = args_res.json().get('schema') or []
        int_field = next((f for f in schema if f.get('type') == 'int'), None)
        tool_args = {int_field['name']: 5} if int_field else {}
        res = self.client.post('/api/action/tool/run/', {
            'tool': 'port_scan',
            'asset_type': 'subdomain',
            'asset_id': self.sub.id,
            'scan_history_id': self.scan.id,
            'tool_args': tool_args or None,
        }, format='json')
        self.assertEqual(res.status_code, 200, res.content)
        body = res.json()
        self.assertTrue(body.get('status'))
        if int_field:
            self.assertEqual(body.get('tool_args', {}).get(int_field['name']), 5)

    def test_cache_hit_skips_help_when_version_matches(self):
        ToolArgSchemaCache.objects.create(
            pipeline_tool='port_scan',
            binary_name='naabu',
            version_fingerprint='9.9.9',
            schema=[{'name': 'threads', 'long_flag': '--threads', 'type': 'int', 'takes_value': True}],
            source='help',
            fetched_at=timezone.now(),
        )
        InstalledExternalTool.objects.create(
            name='naabu',
            description='naabu',
            github_url='https://example.com',
            install_command='go install naabu',
            is_default=True,
            is_present=True,
            resolved_path='/usr/local/bin/naabu',
            detected_version='9.9.9',
        )
        with patch('reNgine.tool_args._run_help') as help_mock:
            payload = get_or_refresh_schema('port_scan', force=False)
            help_mock.assert_not_called()
        self.assertEqual(payload['version'], '9.9.9')
        self.assertEqual(payload['schema'][0]['name'], 'threads')


class ExternalToolsFixtureArgCacheTests(TransactionTestCase):
    """Load fixtures/external_tools.yaml and populate ToolArgSchemaCache by
    probing *real* binaries on go-executor / python-orchestrator via docker
    (no help mocks; kr and friends stay on workers — not the web image).

    TransactionTestCase: long docker probes would trip Postgres
    idle-in-transaction timeouts under a wrapping TestCase atomic block.
    """

    # Secondaries not required in the fixture (primary still covers the cache key).
    _OPTIONAL_BINARIES = frozenset({'nmap', 'dirsearch', 'wafw00f'})

    # Flags that must never appear in a cached schema (retarget / filesystem / update).
    _DENIED_NAMES = frozenset({
        'url', 'urls', 'u', 'target', 'targets', 'host', 'hosts', 'domain', 'domains',
        'list', 'l', 'update', 'output', 'o', 'json-export', 'templates', 't', 'wordlist', 'w',
        'help', 'h',
    })

    def setUp(self):
        from django.core.management import call_command
        from reNgine.tool_args import _last_refresh_at
        from reNgine.tool_workers import clear_resolve_cache

        clear_resolve_cache()
        call_command('loaddata', 'external_tools', verbosity=0)
        self.assertGreater(
            InstalledExternalTool.objects.count(),
            20,
            'external_tools fixture should load a full inventory',
        )
        # Avoid cooldown from a prior refresh in the same process.
        _last_refresh_at.clear()

    def test_fixture_covers_pipeline_primary_binaries(self):
        from reNgine.tool_args import PIPELINE_BINARIES, _tool_row

        missing = []
        for pipeline_tool, binaries in PIPELINE_BINARIES.items():
            if not binaries:
                continue
            primary = binaries[0]
            if primary in self._OPTIONAL_BINARIES:
                continue
            if _tool_row(primary) is None:
                missing.append(f'{pipeline_tool}:{primary}')
        self.assertEqual(
            missing,
            [],
            'PIPELINE_BINARIES primaries must exist in fixtures/external_tools.yaml',
        )

    def test_populate_arg_cache_from_real_installed_binaries(self):
        from reNgine.tool_args import (
            PIPELINE_BINARIES,
            _SEED_SCHEMAS,
            refresh_all_present_schemas,
            resolve_binary_path,
            validate_tool_args,
        )
        from reNgine.tool_workers import decode_worker_path, worker_probe_summary

        workers = worker_probe_summary()
        self.assertTrue(
            workers.get('docker_available'),
            'docker socket/SDK required to probe go/python worker tools',
        )
        self.assertGreaterEqual(
            len(workers.get('workers') or []),
            2,
            f'expected go-executor + python-orchestrator running; got {workers}',
        )

        # One pass: sync (resolve on workers) + help refresh. Skip version probes —
        # they add docker round-trips without improving schema coverage.
        result = refresh_all_present_schemas(probe_versions=False)
        sync_result = result.get('sync') or {}
        self.assertIsInstance(sync_result, dict)
        self.assertEqual(result.get('errors'), [], result)
        self.assertEqual(
            sorted(result.get('refreshed') or []),
            sorted(PIPELINE_BINARIES.keys()),
        )

        present_primaries = []
        missing_primaries = []
        for pipeline_tool, binaries in PIPELINE_BINARIES.items():
            if not binaries:
                continue
            primary = binaries[0]
            row = InstalledExternalTool.objects.filter(name__iexact=primary).first()
            path = (row.resolved_path if row and row.is_present else None) or resolve_binary_path(primary)
            role, remote = decode_worker_path(path)
            if role and remote:
                present_primaries.append(f'{pipeline_tool}:{primary}@{role}:{remote}')
            elif path and os.path.isfile(path):
                present_primaries.append(f'{pipeline_tool}:{primary}@local:{path}')
            else:
                missing_primaries.append(f'{pipeline_tool}:{primary}')

        self.assertGreaterEqual(
            len(present_primaries),
            8,
            'expected most pipeline primaries on go/python workers; '
            f'present={present_primaries} missing={missing_primaries}',
        )
        # kiterunner/kr must resolve on a worker — never require it on web.
        kr_path = resolve_binary_path('kiterunner')
        kr_role, kr_remote = decode_worker_path(kr_path)
        self.assertTrue(
            kr_role and kr_remote,
            f'kiterunner/kr must resolve on go/python workers, got {kr_path!r}',
        )

        dump = []
        help_sourced = 0
        for pipeline_tool, binaries in sorted(PIPELINE_BINARIES.items()):
            if not binaries:
                payload = get_or_refresh_schema(pipeline_tool, force=False)
                self.assertEqual(payload['source'], 'seed')
                self.assertTrue(payload['schema'])
                dump.append({
                    'pipeline_tool': pipeline_tool,
                    'binary_name': '',
                    'source': payload['source'],
                    'flag_count': len(payload['schema']),
                    'flags': [e.get('name') for e in payload['schema']],
                })
                continue

            primary = binaries[0]
            row = InstalledExternalTool.objects.filter(name__iexact=primary).first()
            path = (row.resolved_path if row and row.is_present else None) or resolve_binary_path(primary)
            role, remote = decode_worker_path(path)
            installed = bool(role and remote) or bool(path and os.path.isfile(path))

            cache = ToolArgSchemaCache.objects.filter(
                pipeline_tool=pipeline_tool, binary_name=primary,
            ).first()
            self.assertIsNotNone(
                cache,
                f'missing ToolArgSchemaCache for {pipeline_tool}/{primary}',
            )

            names = [entry.get('name') for entry in (cache.schema or [])]
            name_set = set(names)
            dump.append({
                'pipeline_tool': pipeline_tool,
                'binary_name': primary,
                'binary_path': cache.binary_path,
                'version': cache.version_fingerprint,
                'source': cache.source,
                'installed': installed,
                'flag_count': len(names),
                'flags': names,
            })

            leaked = name_set & self._DENIED_NAMES
            self.assertFalse(
                leaked,
                f'denied flags leaked into {pipeline_tool} schema: {leaked}',
            )

            for entry in cache.schema or []:
                self.assertIn('name', entry)
                self.assertIn('type', entry)
                self.assertIn('takes_value', entry)
                self.assertIn(entry['type'], ('string', 'int', 'float', 'bool'))

            if installed:
                self.assertEqual(
                    cache.source,
                    ToolArgSchemaCache.SOURCE_HELP,
                    f'{pipeline_tool}/{primary} is installed but cache source is '
                    f'{cache.source!r} (worker help parse likely failed). '
                    f'path={cache.binary_path!r} flags={names}',
                )
                seed_names = {e['name'] for e in (_SEED_SCHEMAS.get(pipeline_tool) or [])}
                self.assertGreaterEqual(
                    len(names),
                    5,
                    f'{pipeline_tool}/{primary} help schema too thin ({len(names)}): {names}',
                )
                self.assertTrue(
                    set(names) - seed_names or len(names) > len(seed_names),
                    f'{pipeline_tool}/{primary} looks like seed-only, not real help: {names}',
                )
                help_sourced += 1

                sample = next(
                    (
                        e for e in cache.schema
                        if e.get('type') == 'int' and e.get('takes_value')
                    ),
                    None,
                )
                if sample is None:
                    sample = next(
                        (
                            e for e in cache.schema
                            if e.get('type') == 'string' and e.get('takes_value')
                        ),
                        None,
                    )
                if sample:
                    raw = 3 if sample['type'] == 'int' else 'safe-value'
                    validated = validate_tool_args(
                        pipeline_tool,
                        {sample['name']: raw},
                        schema_payload={'schema': cache.schema},
                    )
                    self.assertEqual(validated['sanitized'][sample['name']], raw)
                    self.assertTrue(
                        validated['extra_cli_args'] or validated['yaml_overlay'],
                    )

                with self.assertRaises(ToolArgsError):
                    validate_tool_args(
                        pipeline_tool,
                        {'url': 'https://evil.example'},
                        schema_payload={'schema': cache.schema},
                    )
            else:
                self.assertTrue(cache.schema, f'empty schema for missing {pipeline_tool}')

        self.assertGreaterEqual(
            help_sourced,
            8,
            f'expected >=8 help-sourced schemas from worker tools; dump={dump}',
        )

        print('\n=== REAL ToolArgSchemaCache (from go/python workers) ===')
        for row in dump:
            print(
                f"  {row['pipeline_tool']:22} {row.get('binary_name') or '-':12} "
                f"source={row['source']:14} path={row.get('binary_path')!s:40} "
                f"flags={row['flag_count']:3} "
                f"{row['flags'][:12]}{'…' if row['flag_count'] > 12 else ''}"
            )
        out_path = os.environ.get(
            'TOOL_ARG_CACHE_DUMP',
            '/tmp/tool_arg_schema_cache_real.json',
        )
        with open(out_path, 'w', encoding='utf-8') as fh:
            json.dump(
                {'sync': sync_result, 'workers': workers, 'refresh': result, 'cache': dump},
                fh,
                indent=2,
            )
        print(f'Wrote full cache dump to {out_path}')
