import os
import unittest
import json
import base64
from unittest.mock import patch, MagicMock
from django.test import TransactionTestCase
from django.utils import timezone

# Import tasks and their underlying functions
from reNgine.tasks import nuclei_scan, amass_intel_discovery, dir_file_fuzz
from reNgine.tech_mapping import get_nuclei_tags_from_techs
from startScan.models import ScanHistory, Subdomain, Technology, DirectoryFile, EndPoint, DirectoryScan
from targetApp.models import Domain
from scanEngine.models import EngineType, OpSec, Proxy

class BackendOptimizationTest(TransactionTestCase):
    def setUp(self):
        self.domain_name = "test-optimization.io"
        self.domain = Domain.objects.create(name=self.domain_name)
        self.engine = EngineType.objects.create(engine_name="Optimization Test Engine")
        
        # Ensure OpSec and Proxy exist
        OpSec.objects.get_or_create(id=1)
        Proxy.objects.get_or_create(id=1)
        
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=1,
            start_scan_date=timezone.now(),
            scan_type=self.engine
        )
        self.results_dir = f"/tmp/rengine_results/{self.scan.id}"
        os.makedirs(self.results_dir, exist_ok=True)
        self.scan.results_dir = self.results_dir
        self.scan.save()
        
        self.subdomain = Subdomain.objects.create(
            name=self.domain_name,
            scan_history=self.scan,
            target_domain=self.domain
        )
        
        self.ctx = {
            'scan_history_id': self.scan.id,
            'domain_id': self.domain.id,
            'results_dir': self.results_dir,
            'yaml_configuration': {
                'vulnerability_scan': {
                    'nuclei': {
                        'severities': ['critical'],
                        'tags': ['cve']
                    }
                }
            }
        }

    def test_tech_mapping_logic(self):
        """Test that technology mapping returns correct Nuclei tags."""
        techs = ['WordPress', 'Nginx', 'PHP']
        tags = get_nuclei_tags_from_techs(techs)
        self.assertIn('wordpress', tags)
        self.assertIn('nginx', tags)
        self.assertIn('php', tags)

    def test_tech_normalization(self):
        """Verify that version suffixes like -4-0-4, -7.0, and -v5.8 are properly stripped
        from technology names, while names like moment-js are kept intact.
        """
        # List of technology tags with various version suffixes
        techs_with_versions = [
            'elementor-4-0-4',
            'wordpress-7-0',
            'woocommerce-10-7-0',
            'parallax-js-1-0',
            'wow-7-0',
            'Apache/2.4.51',
            'nginx-1.18.0',
            'moment-js',
        ]
        
        # Call the tech mapping utility
        tags = get_nuclei_tags_from_techs(techs_with_versions)
        
        # Verify base tags exist and version-specific tags are stripped
        self.assertIn('elementor', tags)
        self.assertNotIn('elementor-4-0-4', tags)
        self.assertIn('wordpress', tags)
        self.assertNotIn('wordpress-7-0', tags)
        self.assertIn('woocommerce', tags)
        self.assertNotIn('woocommerce-10-7-0', tags)
        self.assertIn('parallax-js', tags)
        self.assertNotIn('parallax-js-1-0', tags)
        self.assertIn('wow', tags)
        self.assertNotIn('wow-7-0', tags)
        self.assertIn('apache', tags)
        self.assertNotIn('apache-2-4-51', tags)
        self.assertIn('nginx', tags)
        self.assertNotIn('nginx-1-18-0', tags)
        self.assertIn('moment-js', tags)

    @patch('reNgine.tasks.get_http_urls')
    @patch('reNgine.tasks.Subdomain.objects.filter')
    @patch('reNgine.tasks.stream_command')
    @patch('reNgine.tasks.run_command')
    def test_nuclei_tag_injection(self, mock_run_cmd, mock_stream, mock_subdomain_filter, mock_get_urls):
        """Test that nuclei_scan correctly runs without restricting tags based on discovered technologies."""
        mock_sub = MagicMock()
        mock_sub.name = self.domain_name
        mock_sub.technologies.values_list.return_value = ['WordPress', 'Nginx']
        mock_subdomain_filter.return_value = [mock_sub]
        
        def get_urls_side_effect(write_filepath=None, **kwargs):
            if write_filepath:
                os.makedirs(os.path.dirname(write_filepath), exist_ok=True)
                with open(write_filepath, 'w') as f:
                    f.write(f"http://{self.domain_name}\n")
            return [f"http://{self.domain_name}"]
        mock_get_urls.side_effect = get_urls_side_effect
        
        # mock stream_command to yield nothing
        mock_stream.return_value = iter([])
        
        task_instance = MagicMock()
        task_instance.scan = self.scan
        task_instance.scan_id = self.scan.id
        task_instance.activity_id = None
        task_instance.results_dir = self.results_dir
        task_instance.starting_point_path = ""
        task_instance.yaml_configuration = self.ctx['yaml_configuration']
        
        actual_func = getattr(nuclei_scan, 'run', getattr(nuclei_scan, '__wrapped__', nuclei_scan))
        # Signature: (self, urls=[], ctx={}, description=None)
        actual_func(task_instance, [f"http://{self.domain_name}"], self.ctx)
        
        self.assertTrue(mock_stream.called)
        cmd = mock_stream.call_args[0][0]
        self.assertIn('-tags', cmd)
        # Verify that discovered technology tags are properly injected
        self.assertIn('wordpress', cmd)

    @patch('reNgine.tasks.get_http_urls')
    @patch('reNgine.tasks.Subdomain.objects.filter')
    @patch('reNgine.tasks.stream_command')
    @patch('reNgine.tasks.run_command')
    def test_nuclei_tag_batch_limit_in_fallback_path(self, mock_run_cmd, mock_stream, mock_subdomain_filter, mock_get_urls):
        """When tags_override is not provided (legacy path) and many tech tags are found,
        the command must never receive more than 3 tags via -tags to prevent overload."""
        mock_sub = MagicMock()
        mock_sub.name = self.domain_name
        # Technologies that produce many nuclei tags
        mock_sub.technologies.values_list.return_value = [
            'WordPress', 'Nginx', 'Spring Boot', 'Jenkins', 'Drupal'
        ]
        mock_subdomain_filter.return_value = [mock_sub]

        def get_urls_side_effect(write_filepath=None, **kwargs):
            if write_filepath:
                os.makedirs(os.path.dirname(write_filepath), exist_ok=True)
                with open(write_filepath, 'w') as f:
                    f.write(f"http://{self.domain_name}\n")
            return [f"http://{self.domain_name}"]
        mock_get_urls.side_effect = get_urls_side_effect
        mock_stream.return_value = iter([])

        task_instance = MagicMock()
        task_instance.scan = self.scan
        task_instance.scan_id = self.scan.id
        task_instance.activity_id = None
        task_instance.results_dir = self.results_dir
        task_instance.starting_point_path = ""
        task_instance.yaml_configuration = self.ctx['yaml_configuration']

        actual_func = getattr(nuclei_scan, 'run', getattr(nuclei_scan, '__wrapped__', nuclei_scan))
        actual_func(task_instance, [f"http://{self.domain_name}"], self.ctx)

        self.assertTrue(mock_stream.called)
        cmd = mock_stream.call_args[0][0]
        if '-tags' in cmd:
            import re
            match = re.search(r"-tags\s+'([^']+)'", cmd)
            self.assertIsNotNone(match, "Could not parse -tags value from command")
            tag_list = [t.strip() for t in match.group(1).split(',') if t.strip()]
            self.assertLessEqual(
                len(tag_list), 3,
                msg=f"Non-Temporal fallback passed {len(tag_list)} tags at once: {tag_list}",
            )

    @patch('reNgine.tasks.http_crawl')
    @patch('reNgine.tasks.fuzzing.Redis')
    @patch('reNgine.tasks.fuzzing.get_http_urls')
    @patch('reNgine.common_func.get_http_urls')
    @patch('reNgine.tasks.fuzzing.stream_command')
    @patch('reNgine.tasks.fuzzing.run_command')
    def test_dir_file_fuzz_deduplication(self, mock_run, mock_stream, mock_get_urls_common, mock_get_urls_fuzz, mock_redis_cls, mock_http_crawl):
        """Test that dir_file_fuzz correctly merges and deduplicates results from ffuf and dirsearch."""
        mock_redis = MagicMock()
        mock_redis_cls.from_url.return_value = mock_redis
        mock_redis.lock.return_value.__enter__.return_value = True
        
        mock_get_urls_fuzz.return_value = [f"http://{self.domain_name}"]
        mock_get_urls_common.return_value = [f"http://{self.domain_name}"]
        
        ffuf_output = [
            {"url": f"http://{self.domain_name}/admin", "status": 200, "length": 1234},
            {"url": f"http://{self.domain_name}/login", "status": 200, "length": 567}
        ]
        
        dirsearch_results = {
            "results": [
                {"url": f"http://{self.domain_name}/admin", "status": 200, "content-length": 1234},
                {"url": f"http://{self.domain_name}/new-page", "status": 200, "content-length": 888}
            ]
        }
        
        def stream_side_effect(cmd, *args, **kwargs):
            if 'ffuf' in cmd:
                for item in ffuf_output:
                    yield item
            else:
                yield "Done"
        
        def run_side_effect(cmd, *args, **kwargs):
            if 'dirsearch' in cmd:
                import re
                match = re.search(r'-o\s+([^\s]+)', cmd)
                if match:
                    output_file = match.group(1)
                    os.makedirs(os.path.dirname(output_file), exist_ok=True)
                    with open(output_file, 'w') as f:
                        json.dump(dirsearch_results, f)
        
        mock_stream.side_effect = stream_side_effect
        mock_run.side_effect = run_side_effect
        
        actual_func = getattr(dir_file_fuzz, 'run', getattr(dir_file_fuzz, '__wrapped__', dir_file_fuzz))
        
        task_instance = MagicMock()
        task_instance.scan = self.scan
        task_instance.scan_id = self.scan.id
        task_instance.activity_id = None
        task_instance.results_dir = self.results_dir
        task_instance.history_file = "/tmp/history.txt"
        task_instance.starting_point_path = ""
        task_instance.subscan = None
        task_instance.yaml_configuration = {
            'fuzzing': {
                'ffuf': True,
                'dirsearch': True
            }
        }
        
        # Signature: (self, ctx={}, description=None)
        actual_func(task_instance, self.ctx)
        
        # Verify that only the 3 unique directories (/admin, /login, /new-page) are discovered and saved
        unique_df_count = DirectoryFile.objects.values('url').distinct().count()
        self.assertEqual(unique_df_count, 3)

    @patch('reNgine.tasks.run_command')
    def test_amass_intel_discovery(self, mock_run):
        """Test that amass_intel_discovery runs and attempts to save results."""
        output_file = f"{self.results_dir}/amass_intel.txt"
        
        def run_side_effect(cmd, *args, **kwargs):
            if 'amass intel' in cmd:
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                with open(output_file, 'w') as f:
                    f.write("associated-domain.com\n")
        
        mock_run.side_effect = run_side_effect
        
        actual_func = getattr(amass_intel_discovery, 'run', getattr(amass_intel_discovery, '__wrapped__', amass_intel_discovery))
        
        task_instance = MagicMock()
        task_instance.scan = self.scan
        task_instance.scan_id = self.scan.id
        task_instance.activity_id = None
        task_instance.domain = self.domain
        task_instance.results_dir = self.results_dir
        task_instance.starting_point_path = ""
        task_instance.yaml_configuration = {}
        
        # Signature: (self, host, ctx={}, description=None)
        actual_func(task_instance, self.domain_name, self.ctx)
        
        self.assertTrue(mock_run.called)
