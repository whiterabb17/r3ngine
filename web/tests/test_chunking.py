"""Planning batches for a per-host tool run (reNgine/chunking.py)."""
from unittest import TestCase

from reNgine.chunking import BatchingConfig, batching_config, plan_batches, target_host


class PlanBatchesTests(TestCase):

    def test_all_targets_of_a_host_stay_in_one_batch(self) -> None:
        targets = [
            'https://b.example.test/', 'https://a.example.test/', 'https://b.example.test/admin/',
            'https://c.example.test/', 'https://a.example.test/api/',
        ]

        batches = plan_batches(targets, batch_size=2, max_batches=10)

        self.assertEqual(batches, [
            ['https://a.example.test/', 'https://a.example.test/api/',
             'https://b.example.test/', 'https://b.example.test/admin/'],
            ['https://c.example.test/'],
        ])

    def test_the_plan_does_not_depend_on_input_order(self) -> None:
        targets = [f'https://h{i}.example.test/' for i in range(30)]

        self.assertEqual(
            plan_batches(targets, 7, 100),
            plan_batches(list(reversed(targets)), 7, 100),
        )

    def test_batches_grow_rather_than_exceed_the_cap(self) -> None:
        targets = [f'https://h{i:03d}.example.test/' for i in range(100)]

        batches = plan_batches(targets, batch_size=5, max_batches=4)

        self.assertEqual(len(batches), 4)
        self.assertEqual(sum(len(b) for b in batches), 100)

    def test_duplicates_and_empty_input(self) -> None:
        self.assertEqual(plan_batches([], 5, 5), [])
        self.assertEqual(plan_batches(['https://a.example.test/'] * 3, 5, 5), [['https://a.example.test/']])

    def test_ports_are_separate_hosts(self) -> None:
        self.assertEqual(target_host('https://A.example.test:8443/x'), 'a.example.test:8443')
        self.assertEqual(target_host('a.example.test'), 'a.example.test')


class BatchingConfigTests(TestCase):

    def test_defaults_when_the_section_is_missing(self) -> None:
        self.assertEqual(batching_config(None), BatchingConfig())
        self.assertEqual(batching_config({'batching': 'yes'}), BatchingConfig())

    def test_values_are_bounded_and_bad_ones_fall_back(self) -> None:
        config = batching_config({'batching': {
            'enabled': False, 'batch_size': 0, 'max_parallel': 50, 'max_total_hours': 'soon',
        }})

        self.assertFalse(config.enabled)
        self.assertEqual(config.batch_size, 1)
        self.assertEqual(config.max_parallel, 5)
        self.assertEqual(config.max_total_hours, BatchingConfig().max_total_hours)
