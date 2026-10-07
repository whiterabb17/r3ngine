"""Target Deduplication: hosts that serve the same site as another host."""
from types import SimpleNamespace
from unittest import TestCase as SimpleTestCase

from django.test import TestCase
from django.utils import timezone

from reNgine.host_dedup import (
    REDIRECT, WWW, apply_target_dedup, compute_duplicates, drop_duplicate_targets, target_dedup_config,
)
from reNgine.task_plan import build_scan_task_plan
from reNgine.tasks.dedup import target_dedup
from reNgine.tasks.persistence import _record_final_url
from scanEngine.models import EngineType
from startScan.models import Command, ScanHistory, Subdomain
from targetApp.models import Domain


class ComputeDuplicatesTests(SimpleTestCase):

    def test_www_twin_of_a_live_host(self):
        hosts = {'shop.example.test': None, 'www.shop.example.test': None, 'www.only.example.test': None}

        self.assertEqual(compute_duplicates(hosts), {'www.shop.example.test': ('shop.example.test', WWW)})

    def test_a_redirect_to_another_hosts_root(self):
        hosts = {'old.example.test': 'https://new.example.test/', 'new.example.test': None}

        self.assertEqual(compute_duplicates(hosts), {'old.example.test': ('new.example.test', REDIRECT)})

    def test_a_redirect_to_a_shared_login_page_is_not_a_duplicate(self):
        hosts = {
            'crm.example.test': 'https://sso.example.test/login?next=crm',
            'hr.example.test': 'https://sso.example.test/login?next=hr',
            'sso.example.test': None,
        }

        self.assertEqual(compute_duplicates(hosts), {}, 'unrelated apps behind one SSO stay separate')

    def test_a_redirect_off_the_scan_is_ignored(self):
        self.assertEqual(compute_duplicates({'a.example.test': 'https://elsewhere.example.org/'}), {})

    def test_chains_resolve_to_the_end_and_cycles_are_left_alone(self):
        hosts = {
            'a.example.test': 'https://www.b.example.test/',
            'www.b.example.test': None, 'b.example.test': None,
            'x.example.test': 'https://y.example.test/', 'y.example.test': 'https://x.example.test/',
        }

        duplicates = compute_duplicates(hosts)

        self.assertEqual(duplicates['a.example.test'], ('b.example.test', REDIRECT))
        self.assertNotIn('x.example.test', duplicates)
        self.assertNotIn('y.example.test', duplicates)

    def test_rules_can_be_narrowed_or_turned_off(self):
        hosts = {'www.a.example.test': None, 'a.example.test': None}

        self.assertEqual(compute_duplicates(hosts, rules=(REDIRECT,)), {})
        self.assertEqual(target_dedup_config({'target_dedup': {'enabled': False}})[0], False)
        self.assertEqual(target_dedup_config({'target_dedup': {'group_by': ['www', 'bogus']}}), (True, (WWW,)))
        self.assertEqual(target_dedup_config(None), (True, (REDIRECT, WWW)))


class TargetDedupDbTests(TestCase):

    def setUp(self):
        domain = Domain.objects.create(name='dd.example.test', insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='dd-engine', yaml_configuration='')
        self.scan = ScanHistory.objects.create(
            domain=domain, scan_type=engine, scan_status=1, start_scan_date=timezone.now())
        for name, status in (('dd.example.test', 200), ('www.dd.example.test', 200),
                             ('old.dd.example.test', 0), ('api.dd.example.test', 200)):
            Subdomain.objects.create(scan_history=self.scan, target_domain=domain, name=name, http_status=status)

    def test_a_root_probe_records_where_it_ended(self):
        ctx = {'scan_history_id': self.scan.id}
        _record_final_url('https://old.dd.example.test', 'https://dd.example.test/', ctx)
        _record_final_url('https://api.dd.example.test/v1/login', 'https://dd.example.test/', ctx)

        self.assertEqual(Subdomain.objects.get(name='old.dd.example.test').final_url, 'https://dd.example.test/')
        self.assertIsNone(Subdomain.objects.get(name='api.dd.example.test').final_url, 'deep paths do not count')

    def test_duplicates_are_stored_and_recomputed(self):
        Subdomain.objects.filter(name='old.dd.example.test').update(final_url='https://dd.example.test/')

        found = apply_target_dedup(self.scan.id)

        self.assertEqual(set(found), {'www.dd.example.test', 'old.dd.example.test'})
        old = Subdomain.objects.get(name='old.dd.example.test')
        self.assertEqual((old.duplicate_of.name, old.dedup_reason), ('dd.example.test', REDIRECT))

        Subdomain.objects.filter(name='old.dd.example.test').update(final_url=None)
        apply_target_dedup(self.scan.id)
        self.assertIsNone(Subdomain.objects.get(name='old.dd.example.test').duplicate_of)

    def test_duplicate_hosts_are_left_out_of_heavy_tool_targets(self):
        apply_target_dedup(self.scan.id)
        targets = ['https://dd.example.test/', 'https://www.dd.example.test/', 'https://www.dd.example.test/admin/']

        kept, dropped = drop_duplicate_targets(self.scan.id, targets, {})
        self.assertEqual(kept, ['https://dd.example.test/'])
        self.assertEqual(len(dropped), 2)

        kept, _ = drop_duplicate_targets(self.scan.id, targets, {'subdomain_id': 5})
        self.assertEqual(kept, targets, 'a run aimed at one host keeps it')

    def test_the_step_lists_every_skipped_host(self):
        task = SimpleNamespace(yaml_configuration={}, scan_id=self.scan.id, activity_id=None)

        self.assertTrue(target_dedup(task, ctx={'scan_history_id': self.scan.id}))

        outputs = list(Command.objects.filter(scan_history=self.scan).values_list('command', 'output'))
        self.assertIn(('target_dedup www.dd.example.test', 'SKIPPED for heavy tools — same site as dd.example.test (www)'), outputs)
        self.assertTrue(any(command == 'target_dedup summary' for command, _ in outputs))

    def test_the_step_is_planned_after_http_crawl(self):
        names = [e['name'] for e in build_scan_task_plan(['http_crawl'], {})]
        self.assertIn('target_dedup', names)
        names = [e['name'] for e in build_scan_task_plan(['http_crawl'], {'target_dedup': {'enabled': False}})]
        self.assertNotIn('target_dedup', names)
        self.assertNotIn('target_dedup', [e['name'] for e in build_scan_task_plan(['port_scan'], {})])
