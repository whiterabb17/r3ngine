"""Static guard: every activity call in a workflow must set an explicit retry_policy.

Temporal's default activity retry policy is unlimited attempts, so a single
unreachable backend can keep an activity failing for hours (see
.claude/rules/r3ngine-temporal.md, "Retry policies"). This test parses the
workflow modules instead of importing them, so it needs no Temporal server and
no worker.
"""
import ast
import unittest
from pathlib import Path

WORKFLOWS_DIR = Path(__file__).resolve().parent.parent / 'reNgine' / 'temporal' / 'workflows'

# execute_child_workflow is deliberately absent: its default is a single attempt.
ACTIVITY_CALLS = frozenset({
    'execute_activity',
    'start_activity',
    'execute_local_activity',
    'start_local_activity',
})


def find_calls_without_retry_policy(source: str, filename: str) -> list[str]:
    """Return 'file:line activity' for each activity call lacking retry_policy=.

    A ``**kwargs`` splat is reported too: the policy it may carry cannot be
    checked statically, and the rule asks for an explicit keyword.
    """
    violations: list[str] = []
    for node in ast.walk(ast.parse(source, filename=filename)):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ACTIVITY_CALLS):
            continue
        if any(kw.arg == 'retry_policy' for kw in node.keywords):
            continue
        activity = node.args[0] if node.args else None
        if isinstance(activity, ast.Constant):
            name = str(activity.value)
        elif activity is not None:
            name = ast.unparse(activity)
        else:
            name = '<unknown>'
        violations.append(f'{filename}:{node.lineno} {name}')
    return violations


class WorkflowRetryPolicyTest(unittest.TestCase):

    def test_workflow_modules_exist(self):
        self.assertTrue(list(WORKFLOWS_DIR.glob('*.py')), f'No workflow modules under {WORKFLOWS_DIR}')

    def test_every_activity_call_sets_retry_policy(self):
        violations: list[str] = []
        for path in sorted(WORKFLOWS_DIR.glob('*.py')):
            violations += find_calls_without_retry_policy(path.read_text(encoding='utf-8'), path.name)
        self.assertEqual(
            violations, [],
            'Activity calls without an explicit retry_policy (use a _RETRY_* preset):\n'
            + '\n'.join(violations),
        )


class FindCallsWithoutRetryPolicyTest(unittest.TestCase):

    def test_call_with_policy_passes(self):
        src = 'await workflow.execute_activity("A", ctx, retry_policy=_RETRY_INTERNAL)'
        self.assertEqual(find_calls_without_retry_policy(src, 'wf.py'), [])

    def test_call_without_policy_is_reported(self):
        src = 'await workflow.execute_activity("A", ctx, start_to_close_timeout=t)'
        self.assertEqual(find_calls_without_retry_policy(src, 'wf.py'), ['wf.py:1 A'])

    def test_kwargs_splat_is_reported(self):
        src = 'await workflow.start_activity(run_a, ctx, **opts)'
        self.assertEqual(find_calls_without_retry_policy(src, 'wf.py'), ['wf.py:1 run_a'])

    def test_child_workflow_is_ignored(self):
        src = 'await workflow.execute_child_workflow(Child.run, ctx, **opts)'
        self.assertEqual(find_calls_without_retry_policy(src, 'wf.py'), [])


if __name__ == '__main__':
    unittest.main()
