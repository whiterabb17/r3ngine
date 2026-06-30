import os
from django.test import TestCase
from unittest.mock import patch, mock_open, MagicMock

from dashboard.models import SpiderfootAPIKey
from reNgine.tasks.osint import spiderfoot_scan

class TestSpiderfootAPIKeyInjection(TestCase):
	def setUp(self):
		SpiderfootAPIKey.objects.create(
			module_name="sfp_hunter",
			key_name="api_key",
			key_value="test_hunter_key_123"
		)
		SpiderfootAPIKey.objects.create(
			module_name="sfp_shodan",
			key_name="api_key",
			key_value="test_shodan_key_456"
		)
		SpiderfootAPIKey.objects.create(
			module_name="sfp_newmodule",
			key_name="api_key",
			key_value="test_new_module"
		)
		
	@patch('reNgine.tasks.osint.subprocess.Popen')
	@patch('reNgine.tasks.osint.os.path.exists')
	def test_api_key_injection_existing_config(self, mock_exists, mock_popen):
		mock_exists.side_effect = lambda path: True
		mock_popen.return_value.stdout = []
		mock_popen.return_value.wait.return_value = 0
		
		# Define original configuration (newline separated)
		original_config = (
			"sfp_abstractapi:companyenrichment_api_key=\n"
			"sfp_hunter:api_key=old_hunter_key\n"
			"sfp_someother:api_key=old\n"
		)
		
		m = mock_open(read_data=original_config)
		
		with patch('builtins.open', m):
			proxy = MagicMock()
			proxy.yaml_configuration = {}
			proxy.scan_id = 1
			proxy.subscan_id = None
			proxy.domain = MagicMock()
			proxy.domain.name = "example.com"
			proxy.engine = MagicMock()
			proxy.engine.yaml_configuration = "{}"
			
			spiderfoot_scan(proxy, host="example.com", ctx={})
			
			# Check that write was called
			m.assert_called_with('/usr/src/github/spiderfoot/spiderfoot.cfg', 'w')
			
			# Verify written lines
			handle = m()
			args, kwargs = handle.writelines.call_args
			written_lines = args[0]
			
			self.assertIn("sfp_hunter:api_key=test_hunter_key_123\n", written_lines)
			self.assertIn("sfp_shodan:api_key=test_shodan_key_456\n", written_lines)
			self.assertIn("sfp_newmodule:api_key=test_new_module\n", written_lines)
			self.assertIn("sfp_someother:api_key=old\n", written_lines)
			self.assertIn("sfp_abstractapi:companyenrichment_api_key=\n", written_lines)
			
	@patch('reNgine.tasks.osint.subprocess.Popen')
	@patch('reNgine.tasks.osint.os.path.exists')
	def test_no_write_if_no_changes(self, mock_exists, mock_popen):
		mock_exists.side_effect = lambda path: True
		mock_popen.return_value.stdout = []
		mock_popen.return_value.wait.return_value = 0
		
		original_config = (
			"sfp_hunter:api_key=test_hunter_key_123\n"
			"sfp_shodan:api_key=test_shodan_key_456\n"
			"sfp_newmodule:api_key=test_new_module\n"
		)
		
		m = mock_open(read_data=original_config)
		
		with patch('builtins.open', m):
			proxy = MagicMock()
			proxy.yaml_configuration = {}
			proxy.scan_id = 1
			proxy.subscan_id = None
			proxy.domain = MagicMock()
			proxy.domain.name = "example.com"
			proxy.engine = MagicMock()
			proxy.engine.yaml_configuration = "{}"
			
			spiderfoot_scan(proxy, host="example.com", ctx={})
			
			# file should not be opened for writing if no changes were needed
			# m.call_args_list should only have open(..., 'r')
			writes = [call for call in m.call_args_list if call.args[1] == 'w']
			self.assertEqual(len(writes), 0)
