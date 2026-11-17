"""Copilot MSF catalog + proposal validation tests (no live MSFRPC)."""
from __future__ import annotations

from django.test import SimpleTestCase, TestCase, tag
from unittest.mock import patch

from copilot.msf_aux_catalog import (
    MsfCatalogError,
    get_module_entry,
    load_catalog,
    reload_catalog,
    validate_module_options,
)
from copilot.service import CopilotError, _normalize_msf_payload, create_proposal


@tag('unit')
class MsfCatalogTests(SimpleTestCase):
    def setUp(self):
        reload_catalog()

    def test_catalog_loads_aux_only(self):
        rows = load_catalog()
        self.assertGreater(len(rows), 5)
        for row in rows:
            mod = row['module']
            self.assertTrue(mod.startswith('auxiliary/') or mod.startswith('post/'))
            self.assertFalse(mod.startswith('exploit/'))

    def test_validate_known_module(self):
        entry, opts = validate_module_options(
            'auxiliary/scanner/http/http_version',
            {'RHOSTS': 'example.com', 'RPORT': '80'},
        )
        self.assertEqual(entry['module'], 'auxiliary/scanner/http/http_version')
        self.assertEqual(opts['RHOSTS'], 'example.com')

    def test_reject_unknown_module(self):
        with self.assertRaises(MsfCatalogError):
            validate_module_options('exploit/windows/smb/ms17_010_eternalblue', {'RHOSTS': 'x'})

    def test_reject_payload_option(self):
        with self.assertRaises(MsfCatalogError):
            validate_module_options(
                'auxiliary/scanner/http/http_version',
                {'RHOSTS': 'example.com', 'PAYLOAD': 'windows/meterpreter/reverse_tcp'},
            )

    def test_reject_option_control_chars(self):
        with self.assertRaises(MsfCatalogError):
            validate_module_options(
                'auxiliary/scanner/http/title',
                {'RHOSTS': 'example.com\nuse post/multi/gather'},
            )

    def test_get_module_entry(self):
        self.assertIsNotNone(get_module_entry('auxiliary/scanner/http/title'))
        self.assertIsNone(get_module_entry('exploit/unix/webapp/whatever'))


@tag('unit')
class MsfProposalNormalizeTests(SimpleTestCase):
    def test_normalize_msf_payload(self):
        out = _normalize_msf_payload({
            'module': 'auxiliary/scanner/http/title',
            'options': {'RHOSTS': 'target.example'},
            'mode': 'recommend',
        })
        self.assertEqual(out['mode'], 'recommend')
        self.assertEqual(out['module'], 'auxiliary/scanner/http/title')

    def test_normalize_rejects_bad_mode(self):
        with self.assertRaises(CopilotError):
            _normalize_msf_payload({
                'module': 'auxiliary/scanner/http/title',
                'options': {'RHOSTS': 'target.example'},
                'mode': 'pwn',
            })


@tag('unit')
class MsfCreateProposalTests(TestCase):
    @patch('copilot.msf_aux.assert_rhosts_in_scope')
    def test_create_msf_proposal(self, scope_mock):
        scope_mock.return_value = None
        proposal = create_proposal(
            project_slug='demo',
            action_type='msf_module',
            summary='HTTP title',
            payload={
                'module': 'auxiliary/scanner/http/title',
                'options': {'RHOSTS': 'target.example'},
                'mode': 'recommend',
            },
        )
        self.assertEqual(proposal.action_type, 'msf_module')
        self.assertEqual(proposal.payload['module'], 'auxiliary/scanner/http/title')
        self.assertEqual(proposal.payload['mode'], 'recommend')
        scope_mock.assert_called_once()

    @patch('copilot.msf_aux.assert_rhosts_in_scope')
    def test_recommend_approve_requires_vulnerability(self, scope_mock):
        from copilot.service import approve_proposal

        scope_mock.return_value = None
        proposal = create_proposal(
            project_slug='demo',
            action_type='msf_module',
            summary='HTTP title',
            payload={
                'module': 'auxiliary/scanner/http/title',
                'options': {'RHOSTS': 'target.example'},
                'mode': 'recommend',
            },
        )
        with self.assertRaises(CopilotError) as ctx:
            approve_proposal(proposal)
        self.assertIn('vulnerability_id', str(ctx.exception).lower())
