"""Logger messages take their values as arguments, never pre-formatted f-strings.

Security rule 2.1: an f-string bakes target names, URLs and exception text into
the format string itself, where a stray ``%`` breaks formatting and log
filters cannot tell the message template from the data.
"""
import ast
import unittest
from pathlib import Path

WEB_ROOT = Path(__file__).resolve().parent.parent
LEVELS = {'debug', 'info', 'warning', 'warn', 'error', 'exception', 'critical'}
SKIP_PARTS = {'tests', 'migrations', 'node_modules', '.local_test'}


def _is_logger(node: ast.expr) -> bool:
    if isinstance(node, ast.Call):
        return 'getLogger' in ast.unparse(node.func)
    name = node.attr if isinstance(node, ast.Attribute) else getattr(node, 'id', '')
    return 'log' in name.lower()


def f_string_log_calls() -> list:
    found = []
    for path in sorted(WEB_ROOT.rglob('*.py')):
        if SKIP_PARTS & set(path.relative_to(WEB_ROOT).parts):
            continue
        tree = ast.parse(path.read_text(encoding='utf-8-sig'))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in LEVELS and node.args
                    and isinstance(node.args[0], ast.JoinedStr) and _is_logger(node.func.value)):
                found.append(f'{path.relative_to(WEB_ROOT)}:{node.lineno}')
    return found


class LogFormattingTest(unittest.TestCase):

    def test_no_f_string_log_messages(self):
        found = f_string_log_calls()
        self.assertEqual(
            found, [],
            'Pass values as logger arguments instead of an f-string, e.g. '
            'logger.info("Scanning %s", target):\n' + '\n'.join(found),
        )


class ActivityLogRoutingTest(unittest.TestCase):

    def test_activity_modules_log_to_temporal_file(self):
        import logging

        # Loggers are named after their module; the shim name never logs.
        handlers = logging.getLogger('reNgine.temporal.activities').handlers
        self.assertIn('temporal_file', [getattr(h, 'name', None) for h in handlers])
        self.assertTrue(logging.getLogger('reNgine.temporal.activities.core').propagate)
