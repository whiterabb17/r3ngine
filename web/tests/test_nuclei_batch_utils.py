from unittest import TestCase
from unittest.mock import patch, MagicMock
from reNgine.nuclei_batch_utils import count_templates_for_tag, build_tag_batches


class TestBuildTagBatches(TestCase):
    def test_empty_tags_returns_empty(self):
        result = build_tag_batches([], {})
        self.assertEqual(result, [])

    def test_all_tags_under_threshold_is_one_batch(self):
        tags = ['apache', 'nginx']
        counts = {'apache': 30, 'nginx': 40}
        result = build_tag_batches(tags, counts, max_per_batch=100)
        self.assertEqual(len(result), 1)
        self.assertIn('apache', result[0])
        self.assertIn('nginx', result[0])

    def test_tags_split_when_cumulative_count_exceeds_threshold(self):
        tags = ['apache', 'wordpress']
        counts = {'apache': 30, 'wordpress': 500}
        result = build_tag_batches(tags, counts, max_per_batch=100)
        self.assertGreater(len(result), 1)
        # Every tag must appear in exactly one batch
        flat = [t for batch in result for t in batch]
        self.assertEqual(sorted(flat), sorted(tags))

    def test_single_tag_exceeding_limit_gets_own_batch(self):
        # Tags that individually exceed the limit still get one batch (we don't split at file level)
        tags = ['wordpress']
        counts = {'wordpress': 2000}
        result = build_tag_batches(tags, counts, max_per_batch=100)
        self.assertEqual(result, [['wordpress']])

    def test_no_batch_exceeds_max_per_batch(self):
        tags = ['a', 'b', 'c', 'd', 'e', 'f']
        counts = {'a': 60, 'b': 50, 'c': 30, 'd': 25, 'e': 80, 'f': 10}
        result = build_tag_batches(tags, counts, max_per_batch=100)
        for batch in result:
            total = sum(counts[t] for t in batch)
            self.assertLessEqual(
                total, 100,
                msg=f"Batch {batch} total {total} exceeds max_per_batch=100",
            )

    def test_unknown_tags_default_to_zero_cost(self):
        tags = ['raretag']
        result = build_tag_batches(tags, {}, max_per_batch=100)
        self.assertEqual(result, [['raretag']])

    def test_all_zero_counts_still_splits_by_max_tags(self):
        """Regression: when count_templates_for_tag returns 0 for every tag,
        all tags must NOT collapse into a single batch and crash nuclei."""
        tags = ['wordpress', 'wp-plugin', 'wp-theme', 'wp', 'nginx',
                'apache', 'php', 'jquery', 'react', 'drupal', 'joomla']
        counts = {t: 0 for t in tags}
        result = build_tag_batches(tags, counts, max_per_batch=100, max_tags=3)
        self.assertGreater(len(result), 1,
            "11 tags with all-zero counts must not collapse into one batch")
        for batch in result:
            self.assertLessEqual(len(batch), 3,
                f"Batch {batch} has {len(batch)} tags, exceeds max_tags=3")

    def test_max_tags_splits_even_when_under_template_limit(self):
        """max_tags=3 triggers a split even when total template count is well under max_per_batch."""
        tags = ['a', 'b', 'c', 'd', 'e', 'f']
        counts = {t: 1 for t in tags}  # total=6, under 100
        result = build_tag_batches(tags, counts, max_per_batch=100, max_tags=3)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], ['a', 'b', 'c'])
        self.assertEqual(result[1], ['d', 'e', 'f'])

    def test_default_max_tags_is_3(self):
        """Default max_tags must be 3 — no batch ever exceeds 3 tags."""
        tags = ['a', 'b', 'c', 'd']
        counts = {t: 0 for t in tags}
        result = build_tag_batches(tags, counts, max_per_batch=100)
        for batch in result:
            self.assertLessEqual(len(batch), 3)

    def test_all_tags_appear_across_batches(self):
        tags = ['a', 'b', 'c', 'd', 'e']
        counts = {t: 90 for t in tags}
        result = build_tag_batches(tags, counts, max_per_batch=100)
        flat = sorted(t for batch in result for t in batch)
        self.assertEqual(flat, sorted(tags))

    def test_two_small_tags_grouped_in_one_batch(self):
        tags = ['nginx', 'apache']
        counts = {'nginx': 20, 'apache': 20}
        result = build_tag_batches(tags, counts, max_per_batch=100)
        self.assertEqual(len(result), 1)


class TestCountTemplatesForTag(TestCase):
    @patch('reNgine.nuclei_batch_utils.subprocess.run')
    def test_counts_non_empty_lines(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            '/root/nuclei-templates/wordpress/wp-login.yaml\n'
            '/root/nuclei-templates/wordpress/wp-version.yaml\n'
            '\n'
        )
        count = count_templates_for_tag('wordpress', ['/root/nuclei-templates'])
        self.assertEqual(count, 2)

    @patch('reNgine.nuclei_batch_utils.subprocess.run')
    def test_returns_zero_on_empty_output(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ''
        count = count_templates_for_tag('sometag', ['/root/nuclei-templates'])
        self.assertEqual(count, 0)

    @patch('reNgine.nuclei_batch_utils.subprocess.run')
    def test_returns_zero_on_subprocess_exception(self, mock_run):
        mock_run.side_effect = Exception('nuclei not found')
        count = count_templates_for_tag('wordpress', ['/root/nuclei-templates'])
        self.assertEqual(count, 0)

    @patch('reNgine.nuclei_batch_utils.subprocess.run')
    def test_passes_correct_flags(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ''
        count_templates_for_tag('wordpress', ['/root/nuclei-templates'])
        cmd = mock_run.call_args[0][0]
        self.assertIn('nuclei', cmd)
        self.assertIn('-tl', cmd)
        self.assertIn('-tags', cmd)
        self.assertIn('wordpress', cmd)
        self.assertIn('-t', cmd)
        self.assertIn('/root/nuclei-templates', cmd)

    @patch('reNgine.nuclei_batch_utils.subprocess.run')
    def test_empty_tag_returns_zero_without_subprocess(self, mock_run):
        count = count_templates_for_tag('', ['/root/nuclei-templates'])
        self.assertEqual(count, 0)
        mock_run.assert_not_called()


class TestGatherNucleiTagsActivity(TestCase):
    @patch('reNgine.nuclei_batch_utils.subprocess.run')
    def test_returns_dict_with_tags_and_batches(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = '\n'.join(
            [f'/root/nuclei-templates/wp-{i}.yaml' for i in range(50)]
        )

        with patch('reNgine.temporal_activities.Subdomain') as mock_sub:
            mock_qs = MagicMock()
            mock_qs.__iter__ = MagicMock(return_value=iter([]))
            mock_sub.objects.filter.return_value = mock_qs

            from reNgine.temporal_activities import gather_nuclei_tags_activity
            ctx = {
                'scan_history_id': 1,
                'yaml_configuration': {
                    'vulnerability_scan': {
                        'nuclei': {
                            'tags': ['wordpress'],
                            'max_templates_per_batch': 100,
                        }
                    }
                },
            }
            result = gather_nuclei_tags_activity(ctx)

        self.assertIsInstance(result, dict)
        self.assertIn('tags', result)
        self.assertIn('batches', result)
        self.assertIsInstance(result['tags'], list)
        self.assertIsInstance(result['batches'], list)

    @patch('reNgine.nuclei_batch_utils.subprocess.run')
    def test_empty_tags_returns_empty_batches(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ''

        with patch('reNgine.temporal_activities.Subdomain') as mock_sub:
            mock_qs = MagicMock()
            mock_qs.__iter__ = MagicMock(return_value=iter([]))
            mock_sub.objects.filter.return_value = mock_qs

            from reNgine.temporal_activities import gather_nuclei_tags_activity
            ctx = {'scan_history_id': 1, 'yaml_configuration': {}}
            result = gather_nuclei_tags_activity(ctx)

        self.assertEqual(result['tags'], [])
        self.assertEqual(result['batches'], [])

    @patch('reNgine.nuclei_batch_utils.subprocess.run')
    def test_null_max_templates_per_batch_uses_default(self, mock_run):
        """max_templates_per_batch: null in YAML must not crash GatherNucleiTagsActivity."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ''

        with patch('reNgine.temporal_activities.Subdomain') as mock_sub:
            mock_qs = MagicMock()
            mock_qs.__iter__ = MagicMock(return_value=iter([]))
            mock_sub.objects.filter.return_value = mock_qs

            from reNgine.temporal_activities import gather_nuclei_tags_activity
            ctx = {
                'scan_history_id': 1,
                'yaml_configuration': {
                    'vulnerability_scan': {
                        'nuclei': {
                            'tags': ['wordpress'],
                            'max_templates_per_batch': None,
                        }
                    }
                },
            }
            result = gather_nuclei_tags_activity(ctx)

        self.assertIsInstance(result, dict)
        self.assertIn('batches', result)

    @patch('reNgine.nuclei_batch_utils.subprocess.run')
    def test_batches_never_exceed_three_tags(self, mock_run):
        """GatherNucleiTagsActivity must never produce a batch with more than 3 tags."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ''

        with patch('reNgine.temporal_activities.Subdomain') as mock_sub:
            mock_qs = MagicMock()
            mock_qs.__iter__ = MagicMock(return_value=iter([]))
            mock_sub.objects.filter.return_value = mock_qs

            from reNgine.temporal_activities import gather_nuclei_tags_activity
            ctx = {
                'scan_history_id': 1,
                'yaml_configuration': {
                    'vulnerability_scan': {
                        'nuclei': {
                            'tags': ['wordpress', 'apache', 'nginx', 'php', 'spring', 'jenkins'],
                        }
                    }
                },
            }
            result = gather_nuclei_tags_activity(ctx)

        for batch in result['batches']:
            self.assertLessEqual(
                len(batch), 3,
                msg=f"Batch {batch} has {len(batch)} tags, exceeds max_tags=3",
            )
