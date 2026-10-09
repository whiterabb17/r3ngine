"""Scan engine YAML dump/load, ScanHistory creation and per-task file/cache naming.

Split out of the former reNgine/common_func.py; re-exported by
reNgine.common_func for backward compatibility.
"""
import os
import traceback
import logging

from django.contrib.auth.models import User
from django.utils import timezone

from reNgine.definitions import INITIATED_TASK
from reNgine.settings import RENGINE_TASK_IGNORE_CACHE_KWARGS
from scanEngine.models import EngineType, HardwareProfile
from startScan.models import ScanHistory
from targetApp.models import Domain

logger = logging.getLogger(__name__)


# web_api_discovery tools the engine editor exposes as run_<tool> checkboxes
# (and the built-in engines set) next to the uses_tools list.
API_DISCOVERY_FLAG_TOOLS = ('favirecon', 'sourcemapper', 'grpcurl', 'julius', 'gqlspection')


def resolve_api_discovery_tools(section: dict, default: list[str] | None = None) -> list[str]:
	"""Return the web_api_discovery tools to run.

	Starts from ``uses_tools`` (or ``default`` when the key is absent) and adds
	every tool whose ``run_<tool>`` flag is true. A false flag does not remove a
	tool listed in ``uses_tools``: the checkbox and the list are alternatives.
	"""
	section = section or {}
	tools = list(section.get('uses_tools', default or []))
	for tool in API_DISCOVERY_FLAG_TOOLS:
		if section.get(f'run_{tool}') is True and tool not in tools:
			tools.append(tool)
	return tools


#------------------#
# EngineType utils #
#------------------#
def dump_custom_scan_engines(results_dir):
	"""Dump custom scan engines to YAML files.

	Args:
		results_dir (str): Results directory (will be created if non-existent).
	"""
	custom_engines = EngineType.objects.filter(default_engine=False)
	if not os.path.exists(results_dir):
		os.makedirs(results_dir, exist_ok=True)
	for engine in custom_engines:
		with open(os.path.join(results_dir, f"{engine.engine_name}.yaml"), 'w') as f:
			f.write(engine.yaml_configuration)


def load_custom_scan_engines(results_dir):
	"""Load custom scan engines from YAML files. The filename without .yaml will
	be used as the engine name.

	Args:
		results_dir (str): Results directory containing engines configs.
	"""
	config_paths = [
		f for f in os.listdir(results_dir)
		if os.path.isfile(os.path.join(results_dir, f)) and f.endswith('.yaml')
	]
	for path in config_paths:
		engine_name = os.path.splitext(os.path.basename(path))[0]
		full_path = os.path.join(results_dir, path)
		with open(full_path, 'r') as f:
			yaml_configuration = f.read()

		engine, _ = EngineType.objects.get_or_create(engine_name=engine_name)
		engine.yaml_configuration = yaml_configuration
		engine.save()


def create_scan_object(host_id, engine_id, initiated_by_id=None, hardware_profile_id=None):
	'''
	create task with pending status so that celery task will execute when
	threads are free
	Args:
		host_id: int: id of Domain model
		engine_id: int: id of EngineType model
		initiated_by_id: int : id of User model (Optional)
		hardware_profile_id: int: id of HardwareProfile model (Optional)
	'''
	# get current time
	current_scan_time = timezone.now()
	# fetch engine and domain object
	engine = EngineType.objects.get(pk=engine_id)
	domain = Domain.objects.get(pk=host_id)
	scan = ScanHistory()
	scan.scan_status = INITIATED_TASK
	scan.domain = domain
	scan.scan_type = engine
	scan.start_scan_date = current_scan_time
	if initiated_by_id:
		user = User.objects.get(pk=initiated_by_id)
		scan.initiated_by = user
	if hardware_profile_id:
		try:
			profile = HardwareProfile.objects.get(pk=hardware_profile_id)
			scan.hardware_profile = profile
		except HardwareProfile.DoesNotExist:
			pass
	scan.save()
	# save last scan date for domain model
	domain.start_scan_date = current_scan_time
	domain.save()
	return scan.id


def get_task_cache_key(func_name, *args, **kwargs):
	args_str = '_'.join([str(arg) for arg in args])
	kwargs_str = '_'.join([f'{k}={v}' for k, v in kwargs.items() if k not in RENGINE_TASK_IGNORE_CACHE_KWARGS])
	return f'{func_name}__{args_str}__{kwargs_str}'


def get_output_file_name(scan_history_id, subscan_id, filename):
	title = f'#{scan_history_id}'
	if subscan_id:
		title += f'-{subscan_id}'
	title += f'_{filename}'
	return title


def get_traceback_path(task_name, results_dir, scan_history_id=None, subscan_id=None):
	path = results_dir
	if scan_history_id:
		path += f'/#{scan_history_id}'
		if subscan_id:
			path += f'-#{subscan_id}'
	path += f'-{task_name}.txt'
	return path


def fmt_traceback(exc):
	return '\n'.join(traceback.format_exception(None, exc, exc.__traceback__))
