from rest_framework import serializers

from scanEngine.models import Configuration, EngineType, HardwareProfile, ScanProfile, Wordlist


class EngineTypeSerializer(serializers.ModelSerializer):
	class Meta:
		model = EngineType
		fields = '__all__'


class ConfigurationSerializer(serializers.ModelSerializer):
	class Meta:
		model = Configuration
		fields = '__all__'


class EngineSerializer(serializers.ModelSerializer):

	tasks = serializers.SerializerMethodField('get_tasks')
	subscan_tasks = serializers.SerializerMethodField('get_subscan_tasks')
	configured_tools_count = serializers.SerializerMethodField('get_configured_tools_count')

	def get_tasks(self, instance):
		return instance.tasks

	def get_subscan_tasks(self, instance):
		"""The engine's tasks a subscan can run; the YAML also holds settings-only sections."""
		from reNgine.temporal.workflows.subscan import is_subscan_task
		return [task for task in instance.tasks if is_subscan_task(task)]

	def get_configured_tools_count(self, instance):
		"""
		Calculates the total number of unique tools configured in the scan engine
		by parsing its YAML configuration.

		Args:
			instance (EngineType): The EngineType model instance.

		Returns:
			int: The number of configured tools.
		"""
		if not instance.yaml_configuration:
			return 0
		try:
			import yaml
			config = yaml.safe_load(instance.yaml_configuration)
			if not isinstance(config, dict):
				return 0
			tools = set()
			boolean_tool_flags = [
				('port_scan', 'enable_nmap'),
				('port_scan', 'enable_network_enum'),
				('vulnerability_scan', 'run_nuclei'),
				('vulnerability_scan', 'run_dalfox'),
				('vulnerability_scan', 'run_crlfuzz'),
				('vulnerability_scan', 'run_acunetix'),
				('vulnerability_scan', 'run_wpscan'),
				('vulnerability_scan', 'run_s3scanner'),
				('vulnerability_scan', 'run_vigolium'),
				('vigolium_discovery', 'run_vigolium_discovery'),
				('vigolium_analysis', 'run_vigolium_analysis'),
				('firewall_vpn_scan', 'run_ike_scan'),
				('firewall_vpn_scan', 'run_sslscan'),
				('firewall_vpn_scan', 'enable_testssl'),
				('firewall_vpn_scan', 'enable_crt_sh'),
				('waf_detection', 'use_shodan'),
				('waf_detection', 'use_censys'),
				('waf_bypass', 'use_nuclei'),
				('waf_bypass', 'use_benchmarking'),
				('dir_file_fuzz', 'run_dirsearch'),
				('dir_file_fuzz', 'run_feroxbuster'),
			]
			# Add section-level default tools
			if 'spiderfoot_scan' in config:
				tools.add('spiderfoot')
			if 'screenshot' in config:
				tools.add('playwright')
			dir_file_fuzz_cfg = config.get('dir_file_fuzz')
			if 'dir_file_fuzz' in config and not (
				isinstance(dir_file_fuzz_cfg, dict) and dir_file_fuzz_cfg.get('run_ffuf') is False
			):
				tools.add('ffuf')

			for section_name, section_data in config.items():
				if not isinstance(section_data, dict):
					continue
				if 'uses_tools' in section_data and isinstance(section_data['uses_tools'], list):
					for t in section_data['uses_tools']:
						if isinstance(t, str):
							tools.add(t.strip().lower())
				if 'discover' in section_data and isinstance(section_data['discover'], list):
					for t in section_data['discover']:
						if isinstance(t, str):
							tools.add(t.strip().lower())
				if 'leaks_and_secrets' in section_data and isinstance(section_data['leaks_and_secrets'], dict):
					for tool_name, enabled in section_data['leaks_and_secrets'].items():
						if enabled is True:
							tools.add(tool_name.strip().lower())
			for section, flag in boolean_tool_flags:
				section_data = config.get(section)
				if isinstance(section_data, dict) and section_data.get(flag) is True:
					clean_name = flag.replace('run_', '').replace('enable_', '').replace('use_', '')
					tools.add(clean_name.strip().lower())
			return len(tools)
		except Exception:
			return 0

	class Meta:
		model = EngineType
		fields = [
			'id',
			'default_engine',
			'engine_name',
			'yaml_configuration',
			'tasks',
			'subscan_tasks',
			'configured_tools_count'
		]


class WordlistSerializer(serializers.ModelSerializer):
	class Meta:
		model = Wordlist
		fields = '__all__'


class HardwareProfileSerializer(serializers.ModelSerializer):
	class Meta:
		model = HardwareProfile
		fields = '__all__'


class ScanProfileSerializer(serializers.ModelSerializer):
	class Meta:
		model = ScanProfile
		fields = '__all__'
		read_only_fields = ['id', 'is_builtin', 'created_at', 'updated_at']
