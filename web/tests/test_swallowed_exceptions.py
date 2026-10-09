"""No broad exception handler may silently swallow a failure.

A handler that catches ``Exception``, ``BaseException`` or everything (bare
``except:``) and then only ``pass``es, ``continue``s or ``return``s ``None``
hides DB write errors, failed security checks and lost audit rows alike.
Either narrow it to what the ``try`` body can actually raise, or log it.
"""
import ast
import unittest
from pathlib import Path

WEB_ROOT = Path(__file__).resolve().parent.parent
SKIP_PARTS = {'tests', 'migrations', 'node_modules', '.local_test'}
BROAD = {'Exception', 'BaseException'}

# Sites kept on purpose, as 'path/relative/to/web.py:function', each with the
# reason it is safe. Prefer narrowing the handler over adding an entry here.
ALLOWED: set[str] = set()


def _is_broad(node) -> bool:
    if node is None:
        return True
    if isinstance(node, ast.Name):
        return node.id in BROAD
    if isinstance(node, ast.Tuple):
        return any(_is_broad(elt) for elt in node.elts)
    return False


def _is_silent(body: list) -> bool:
    if len(body) != 1:
        return False
    stmt = body[0]
    if isinstance(stmt, (ast.Pass, ast.Continue)):
        return True
    if isinstance(stmt, ast.Return):
        return stmt.value is None or (isinstance(stmt.value, ast.Constant) and stmt.value.value is None)
    # `...` or a lone string used as a placeholder body
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)


def _function_name(node, parents: dict) -> str:
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name
    return '<module>'


def silent_broad_handlers() -> list:
    """Return 'path:function:line' for every silent broad handler under web/."""
    found = []
    for path in sorted(WEB_ROOT.rglob('*.py')):
        rel = path.relative_to(WEB_ROOT)
        if SKIP_PARTS & set(rel.parts):
            continue
        tree = ast.parse(path.read_text(encoding='utf-8-sig'))
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and _is_broad(node.type) and _is_silent(node.body):
                found.append(f'{rel.as_posix()}:{_function_name(node, parents)}:{node.lineno}')
    return found


class SwallowedExceptionTest(unittest.TestCase):

    def test_no_silent_broad_except(self):
        found = [site for site in silent_broad_handlers() if site.rsplit(':', 1)[0] not in ALLOWED]
        self.assertEqual(
            found, [],
            'Narrow these handlers to the exceptions the try body raises, or log them '
            '(logger.warning("...", exc_info=True)):\n' + '\n'.join(found),
        )

    def test_detector_flags_the_patterns_it_guards(self):
        cases = {
            'try:\n    f()\nexcept:\n    pass\n': True,
            'try:\n    f()\nexcept Exception:\n    pass\n': True,
            'try:\n    f()\nexcept (ValueError, Exception):\n    return None\n': True,
            'try:\n    f()\nexcept BaseException:\n    ...\n': True,
            'try:\n    f()\nexcept OSError:\n    pass\n': False,
            'try:\n    f()\nexcept Exception:\n    log.warning("x", exc_info=True)\n': False,
            'try:\n    f()\nexcept Exception:\n    return False\n': False,
        }
        for source, expected in cases.items():
            handler = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.ExceptHandler))
            with self.subTest(source=source):
                self.assertEqual(_is_broad(handler.type) and _is_silent(handler.body), expected)
