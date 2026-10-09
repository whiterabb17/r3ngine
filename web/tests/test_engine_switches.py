"""Engine YAML switches the editor writes, and the backend steps they gate."""
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from reNgine.task_plan import build_scan_task_plan, canonical_scan_task_name, get_task_tier
from reNgine.tasks.osint.pipeline import post_crawl_osint
from reNgine.tasks.subdomain import _amass_intel_uses_config, amass_intel_discovery
from scanEngine.models import EngineType


def _planned(tasks: list, yaml_configuration: dict) -> set:
    return {entry['name'] for entry in build_scan_task_plan(tasks, yaml_configuration)}


class CredSpyTaskTests(unittest.TestCase):

    def test_credspy_under_osint_schedules_the_post_crawl_step(self) -> None:
        engine = EngineType(engine_name='t', yaml_configuration='osint:\n  credspy: true\n')
        self.assertIn('post_crawl_osint', engine.tasks)

    def test_without_credspy_nothing_is_added(self) -> None:
        engine = EngineType(engine_name='t', yaml_configuration='osint:\n  credspy: false\n')
        self.assertNotIn('post_crawl_osint', engine.tasks)

    @patch('reNgine.tasks.osint.pipeline.get_opsec_manager')
    @patch('reNgine.osint.credspy.run_credspy')
    def test_post_crawl_step_runs_credspy_without_its_own_section(self, mock_credspy, _opsec) -> None:
        task = SimpleNamespace(
            yaml_configuration={'osint': {'credspy': True}},
            domain=SimpleNamespace(name='example.test'),
            scan=MagicMock(),
            scan_id=1,
            results_dir='/tmp/unused',
        )
        post_crawl_osint(task)
        mock_credspy.assert_called_once()

    @patch('reNgine.tasks.osint.pipeline.get_opsec_manager')
    @patch('reNgine.osint.credspy.run_credspy')
    def test_post_crawl_step_skips_when_nothing_is_on(self, mock_credspy, mock_opsec) -> None:
        task = SimpleNamespace(yaml_configuration={}, domain=None, scan=None, scan_id=1, results_dir='/tmp/unused')
        self.assertTrue(post_crawl_osint(task))
        mock_credspy.assert_not_called()
        mock_opsec.assert_not_called()


class AttackPathPlanTests(unittest.TestCase):

    def test_apme_is_planned_by_default(self) -> None:
        self.assertIn('run_apme', _planned(['subdomain_discovery'], {}))

    def test_apme_is_not_planned_when_switched_off(self) -> None:
        conf = {'attack_path_modeling': {'enabled': False}}
        self.assertNotIn('run_apme', _planned(['subdomain_discovery', 'attack_path_modeling'], conf))


class PostCrawlOsintPlanTests(unittest.TestCase):

    def test_section_schedules_the_step(self) -> None:
        engine = EngineType(engine_name='t', yaml_configuration='post_crawl_osint:\n  swaggerspy: true\n')
        self.assertIn('post_crawl_osint', engine.tasks)

    def test_step_is_planned_in_tier_4(self) -> None:
        plan = build_scan_task_plan(['dir_file_fuzz', 'post_crawl_osint'], {'post_crawl_osint': {'metagoofil': True}})
        tiers = {entry['name']: entry['tier'] for entry in plan}
        self.assertEqual(tiers['post_crawl_osint'], 4)
        self.assertEqual(get_task_tier('post_crawl_osint'), 4)

    def test_step_survives_a_resume(self) -> None:
        self.assertEqual(canonical_scan_task_name('post_crawl_osint'), 'post_crawl_osint')


class TopLevelDiscoveryTaskTests(unittest.TestCase):

    def test_baddns_and_amass_intel_sections_schedule_their_steps(self) -> None:
        engine = EngineType(engine_name='t', yaml_configuration='baddns: {}\namass_intel_discovery: {}\n')
        self.assertIn('baddns', engine.tasks)
        self.assertIn('amass_intel_discovery', engine.tasks)
        planned = _planned(engine.tasks, {'baddns': {}, 'amass_intel_discovery': {}})
        self.assertLessEqual({'baddns', 'amass_intel_discovery'}, planned)


class AmassIntelConfigTests(unittest.TestCase):

    def test_own_section_wins(self) -> None:
        conf = {
            'amass_intel_discovery': {'use_amass_config': False},
            'subdomain_discovery': {'use_amass_config': True},
        }
        self.assertFalse(_amass_intel_uses_config(conf))

    def test_falls_back_to_subdomain_discovery(self) -> None:
        conf = {'amass_intel_discovery': {}, 'subdomain_discovery': {'use_amass_config': True}}
        self.assertTrue(_amass_intel_uses_config(conf))

    def test_section_given_without_a_mapping(self) -> None:
        self.assertFalse(_amass_intel_uses_config({'amass_intel_discovery': None}))
        self.assertTrue(_amass_intel_uses_config({
            'amass_intel_discovery': True, 'subdomain_discovery': {'use_amass_config': True},
        }))

    @patch('reNgine.tasks.subdomain.run_command')
    def test_command_uses_the_config_file_when_switched_on(self, mock_run) -> None:
        task = SimpleNamespace(
            yaml_configuration={'amass_intel_discovery': {'use_amass_config': True}},
            results_dir='/nonexistent-results',
            history_file=None,
            scan_id=1,
            activity_id=1,
        )
        amass_intel_discovery(task, 'example.test')
        self.assertIn('-config /root/.config/amass.ini', mock_run.call_args.args[0])
