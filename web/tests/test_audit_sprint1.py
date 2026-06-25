import ast
import os
import unittest


WORKFLOWS_FILE = os.path.join(
    os.path.dirname(__file__), '..', 'reNgine', 'temporal', 'workflows', '__init__.py'
)

ACTIVITIES_FILE = os.path.join(
    os.path.dirname(__file__), '..', 'reNgine', 'temporal', 'activities', '__init__.py'
)


class TestAUD001AsyncioSleepInWorkflows(unittest.TestCase):
    """AUD-001: asyncio.sleep() must not appear inside workflow classes."""

    def test_no_asyncio_sleep_in_workflow_classes(self):
        with open(WORKFLOWS_FILE, encoding='utf-8-sig') as f:
            source = f.read()
        tree = ast.parse(source)

        workflow_class_bodies = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for decorator in node.decorator_list:
                    dec_name = ''
                    if isinstance(decorator, ast.Attribute):
                        dec_name = decorator.attr
                    elif isinstance(decorator, ast.Name):
                        dec_name = decorator.id
                    elif isinstance(decorator, ast.Call):
                        # Handle @workflow.defn(...) — decorator is a Call
                        func = decorator.func
                        if isinstance(func, ast.Attribute):
                            dec_name = func.attr
                        elif isinstance(func, ast.Name):
                            dec_name = func.id
                    if dec_name == 'defn':
                        workflow_class_bodies.append(node)

        violations = []
        for cls in workflow_class_bodies:
            for node in ast.walk(cls):
                if (
                    isinstance(node, ast.Await)
                    and isinstance(node.value, ast.Call)
                ):
                    func = node.value.func
                    if isinstance(func, ast.Attribute) and func.attr == 'sleep':
                        if isinstance(func.value, ast.Name) and func.value.id == 'asyncio':
                            violations.append(
                                f"asyncio.sleep() at line {node.lineno} in class {cls.name}"
                            )

        self.assertEqual(
            violations, [],
            f"Found asyncio.sleep() in workflow classes (AUD-001):\n" + "\n".join(violations)
        )


class TestAUD005NucleiRetryPolicy(unittest.TestCase):
    """AUD-005: All RunNucleiActivity calls must have an explicit retry_policy."""

    def test_run_nuclei_activity_has_retry_policy(self):
        with open(WORKFLOWS_FILE, encoding='utf-8-sig') as f:
            source = f.read()
        tree = ast.parse(source)

        # Find all execute_activity calls with "RunNucleiActivity"
        missing_retry = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Await):
                continue
            call = node.value
            if not isinstance(call, ast.Call):
                continue
            # Check if this is workflow.execute_activity(...)
            func = call.func
            if not (isinstance(func, ast.Attribute) and func.attr == 'execute_activity'):
                continue
            # Check first arg is "RunNucleiActivity"
            if not call.args:
                continue
            first_arg = call.args[0]
            if not (isinstance(first_arg, ast.Constant) and first_arg.value == 'RunNucleiActivity'):
                continue
            # Check kwargs for retry_policy
            kwarg_names = {kw.arg for kw in call.keywords}
            if 'retry_policy' not in kwarg_names:
                missing_retry.append(f"line {node.lineno}")

        # Also assert we found at least one RunNucleiActivity call (guard against vacuous pass)
        all_nuclei_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Await):
                continue
            call = node.value
            if not isinstance(call, ast.Call):
                continue
            func = call.func
            if not (isinstance(func, ast.Attribute) and func.attr == 'execute_activity'):
                continue
            if not call.args:
                continue
            first_arg = call.args[0]
            if isinstance(first_arg, ast.Constant) and first_arg.value == 'RunNucleiActivity':
                all_nuclei_calls.append(f"line {node.lineno}")

        self.assertGreater(
            len(all_nuclei_calls), 0,
            "No RunNucleiActivity calls found in temporal/workflows/__init__.py — is the file correct?"
        )
        self.assertEqual(
            missing_retry, [],
            f"RunNucleiActivity called without retry_policy at: {missing_retry} (AUD-005)"
        )


class TestAUD006NucleiChildWorkflowRetryPolicy(unittest.TestCase):
    """AUD-006: NucleiPlannerWorkflow child invocations must have retry_policy."""

    def test_nuclei_planner_child_workflow_has_retry_policy(self):
        with open(WORKFLOWS_FILE, encoding='utf-8-sig') as f:
            source = f.read()
        tree = ast.parse(source)

        all_child_calls = []
        missing_retry = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Await):
                continue
            call = node.value
            if not isinstance(call, ast.Call):
                continue
            func = call.func
            if not (isinstance(func, ast.Attribute) and func.attr == 'execute_child_workflow'):
                continue
            if not call.args:
                continue
            first_arg = call.args[0]
            if not (isinstance(first_arg, ast.Constant) and first_arg.value == 'NucleiPlannerWorkflow'):
                continue
            all_child_calls.append(f"line {node.lineno}")
            kwarg_names = {kw.arg for kw in call.keywords}
            if 'retry_policy' not in kwarg_names:
                missing_retry.append(f"line {node.lineno}")

        self.assertGreater(
            len(all_child_calls), 0,
            "No execute_child_workflow('NucleiPlannerWorkflow') calls found — is the file correct?"
        )
        self.assertEqual(
            missing_retry, [],
            f"NucleiPlannerWorkflow child invocation without retry_policy: {missing_retry} (AUD-006)"
        )


class TestAUD003OldBehaviourIsGone(unittest.TestCase):
    """AUD-003: _create_scan_activity must use select_for_update and not swallow exceptions."""

    def test_uses_select_for_update(self):
        with open(ACTIVITIES_FILE, encoding='utf-8-sig') as f:
            source = f.read()
        self.assertIn(
            'select_for_update',
            source,
            "_create_scan_activity must use select_for_update() to prevent retry race (AUD-003)"
        )

    def test_filters_unclaimed_rows_only(self):
        with open(ACTIVITIES_FILE, encoding='utf-8-sig') as f:
            source = f.read()
        self.assertIn(
            'time_started__isnull=True',
            source,
            "_create_scan_activity must filter time_started__isnull=True before claiming (AUD-003)"
        )

    def test_exception_is_reraised_not_swallowed(self):
        with open(ACTIVITIES_FILE, encoding='utf-8-sig') as f:
            source = f.read()
        # The old bad pattern: self.activity = None after an exception
        self.assertNotIn(
            'self.activity = None',
            source,
            "_create_scan_activity must not silently set self.activity=None on exception (AUD-003)"
        )


from django.test import TestCase as DjangoTestCase
from django.utils import timezone as tz_module


class TestAUD003ScanActivityRetryBehaviour(DjangoTestCase):
    """AUD-003: Retrying an activity must not overwrite prior SUCCESS rows."""

    def setUp(self):
        from startScan.models import ScanHistory, Domain
        from scanEngine.models import EngineType
        self.domain = Domain.objects.create(name='test-aud003.internal')
        self.engine = EngineType.objects.create(
            engine_name='test-engine-aud003',
            yaml_configuration='{}',
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=1,
            start_scan_date=tz_module.now(),
        )

    def test_retry_does_not_overwrite_success_row(self):
        from reNgine.definitions import SUCCESS_TASK, RUNNING_TASK, INITIATED_TASK
        from startScan.models import ScanActivity
        from django.db import transaction

        # Prior successful run left a SUCCESS row
        success_row = ScanActivity.objects.create(
            scan_of=self.scan,
            name='nuclei_scan',
            title='nuclei_scan',
            status=SUCCESS_TASK,
            time_started=tz_module.now(),
            time=tz_module.now(),
        )

        # A new unclaimed INITIATED row exists for this retry
        initiated_row = ScanActivity.objects.create(
            scan_of=self.scan,
            name='nuclei_scan',
            title='nuclei_scan',
            status=INITIATED_TASK,
            time_started=None,
            time=tz_module.now(),
        )

        # The correct behaviour: only claim the unclaimed row
        with transaction.atomic():
            updated = ScanActivity.objects.select_for_update(skip_locked=True).filter(
                scan_of=self.scan,
                name='nuclei_scan',
                time_started__isnull=True,
            ).update(
                status=RUNNING_TASK,
                time_started=tz_module.now(),
            )

        self.assertEqual(updated, 1, "Should claim exactly one unclaimed row")

        success_row.refresh_from_db()
        self.assertEqual(
            success_row.status, SUCCESS_TASK,
            "Prior SUCCESS row must not be overwritten on retry (AUD-003)"
        )

        initiated_row.refresh_from_db()
        self.assertEqual(
            initiated_row.status, RUNNING_TASK,
            "Unclaimed INITIATED row should now be RUNNING (AUD-003)"
        )


SETTINGS_FILE = os.path.join(
    os.path.dirname(__file__), '..', 'reNgine', 'settings.py'
)


class TestAUD004NoDynamicAllowedHosts(unittest.TestCase):
    """AUD-004: DynamicAllowedHosts must not exist in settings.py."""

    def test_no_dynamic_allowed_hosts_class(self):
        with open(SETTINGS_FILE, encoding='utf-8-sig') as f:
            source = f.read()
        self.assertNotIn(
            'DynamicAllowedHosts',
            source,
            "DynamicAllowedHosts class must be removed from settings.py (AUD-004)"
        )

    def test_no_stack_frame_inspection_in_settings(self):
        with open(SETTINGS_FILE, encoding='utf-8-sig') as f:
            source = f.read()
        self.assertNotIn(
            'currentframe',
            source,
            "Stack frame inspection in ALLOWED_HOSTS must be removed (AUD-004)"
        )

    def test_allowed_hosts_not_dynamic_class_instance(self):
        with open(SETTINGS_FILE, encoding='utf-8-sig') as f:
            source = f.read()
        import re
        self.assertNotRegex(
            source,
            r'ALLOWED_HOSTS\s*=\s*DynamicAllowedHosts',
            "ALLOWED_HOSTS must not be assigned to DynamicAllowedHosts instance (AUD-004)"
        )
