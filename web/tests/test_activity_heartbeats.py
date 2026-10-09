"""Activities given a heartbeat_timeout shorter than their run time must heartbeat.

Otherwise the server times them out after heartbeat_timeout however healthy
they are, and the retry policy starts them again. This test parses the
workflow and activity modules, so it needs no Temporal server.
"""
import ast
import threading
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from reNgine.temporal import heartbeat as heartbeat_module
from reNgine.temporal.heartbeat import keep_alive

TEMPORAL_DIR = Path(__file__).resolve().parent.parent / 'reNgine' / 'temporal'


def _seconds(expr: ast.expr):
    try:
        value = eval(compile(ast.Expression(expr), '<timeout>', 'eval'), {'timedelta': timedelta})  # noqa: S307
    except Exception:
        return None
    return value.total_seconds() if isinstance(value, timedelta) else None


def _short_heartbeat_calls() -> dict:
    """Activity name -> 'file:line' of a call whose heartbeat_timeout < start_to_close_timeout."""
    found = {}
    for path in sorted((TEMPORAL_DIR / 'workflows').glob('*.py')):
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8-sig'))):
            if not (isinstance(node, ast.Call) and getattr(node.func, 'attr', '') == 'execute_activity'):
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant):
                continue
            kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
            if 'heartbeat_timeout' not in kwargs or 'start_to_close_timeout' not in kwargs:
                continue
            heartbeat_s = _seconds(kwargs['heartbeat_timeout'])
            run_s = _seconds(kwargs['start_to_close_timeout'])
            if heartbeat_s is not None and run_s is not None and heartbeat_s < run_s:
                found.setdefault(node.args[0].value, f'{path.name}:{node.lineno}')
    return found


def _activity_functions():
    """(activity name -> function node, function name -> node) across the activities package."""
    by_activity, by_name = {}, {}
    for path in sorted((TEMPORAL_DIR / 'activities').glob('*.py')):
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8-sig'))):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            by_name[node.name] = node
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and getattr(dec.func, 'attr', '') == 'defn':
                    name = next((kw.value.value for kw in dec.keywords if kw.arg == 'name'), node.name)
                    by_activity[name] = node
    return by_activity, by_name


def _heartbeats(node, by_name, seen=frozenset()) -> bool:
    """True if the function is keep_alive-wrapped or reaches a heartbeat (or _run_task)."""
    if node.name in seen:
        return False
    if any(getattr(dec, 'id', getattr(dec, 'attr', '')) == 'keep_alive' for dec in node.decorator_list):
        return True
    for sub in ast.walk(node):
        name = getattr(sub, 'id', None) or getattr(sub, 'attr', None)
        if not name:
            continue
        if 'heartbeat' in name.lower() or name == '_run_task':
            return True
        callee = by_name.get(name)
        if isinstance(sub, (ast.Name, ast.Attribute)) and callee is not None and callee is not node:
            if _heartbeats(callee, by_name, seen | {node.name}):
                return True
    return False


class ActivityHeartbeatTest(unittest.TestCase):

    def test_activities_with_short_heartbeat_timeout_heartbeat(self):
        by_activity, by_name = _activity_functions()
        silent = [
            f'{name} ({where})'
            for name, where in sorted(_short_heartbeat_calls().items())
            if name in by_activity and not _heartbeats(by_activity[name], by_name)
        ]
        self.assertEqual(
            silent, [],
            'These activities get a heartbeat_timeout but never heartbeat; wrap them '
            'with @keep_alive (reNgine.temporal.heartbeat):\n' + '\n'.join(silent),
        )


class KeepAliveTest(unittest.TestCase):

    def test_heartbeats_while_the_call_runs_and_returns_its_result(self):
        beat = threading.Event()
        release = threading.Event()

        def fake_heartbeat(*_):
            beat.set()

        @keep_alive
        def slow(x):
            release.wait(5)
            return x * 2

        with patch.object(heartbeat_module, 'HEARTBEAT_INTERVAL_SECONDS', 0.01), \
                patch.object(heartbeat_module.activity, 'heartbeat', side_effect=fake_heartbeat):
            result = []
            worker = threading.Thread(target=lambda: result.append(slow(21)))
            worker.start()
            self.assertTrue(beat.wait(5), 'no heartbeat was sent while the call ran')
            release.set()
            worker.join(5)

        self.assertEqual(result, [42])

    def test_exception_from_the_call_propagates(self):
        @keep_alive
        def broken():
            raise RuntimeError('boom')

        with patch.object(heartbeat_module.activity, 'heartbeat'):
            with self.assertRaises(RuntimeError):
                broken()

    def test_preserves_the_signature_temporal_inspects(self):
        @keep_alive
        def typed(scan_id: int, ctx: dict) -> bool:
            return True

        self.assertEqual(typed.__name__, 'typed')
        self.assertEqual(typed.__annotations__, {'scan_id': int, 'ctx': dict, 'return': bool})
