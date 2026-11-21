"""Static guard for security rule 8: no exception text in HTTP responses.

Walks every view module and flags an ``except ... as exc`` block that puts
``exc`` into a Response/JsonResponse call or into a dict literal (the usual
``response = {...}; return Response(response)`` shape). Exceptions that exist to
carry a user-facing message are allowed.
"""
import ast
import unittest
from pathlib import Path

WEB_ROOT = Path(__file__).resolve().parent.parent

VIEW_MODULE_GLOBS = (
    'api/**/*.py',
    'dashboard/views.py',
    'engagements/views.py',
    'evidence/views.py',
    'mcp/views/*.py',
    'plugins/views.py',
    'reNgine/stress/views.py',
    'reNgine/views.py',
    'recon_note/views.py',
    'scanEngine/views.py',
    'startScan/views.py',
    'targetApp/views.py',
)

# Raised on purpose with a message meant for the user. HTTPError covers the LLM
# connection tests, which show the provider's own error body (_parse_http_error).
USER_FACING_EXCEPTIONS = frozenset({
    'ValueError', 'ValidationError', 'ToolArgsError', 'ToolRunError', 'HTTPError',
    # Domain exceptions whose message/detail is intentionally returned to the client.
    'AttackPathProposalError', 'SafePocError', 'McpPluginUnavailable', 'AdAssessmentNotFound',
})


def _exception_names(handler: ast.ExceptHandler) -> set[str]:
    types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    names = set()
    for node in types:
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
    return names


def _is_response_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, 'id', '')
    return name.endswith('Response')


def _uses(node: ast.AST, name: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(node))


def _leaks_via_assignment(node: ast.AST, exc_name: str) -> bool:
    """Catch ``response['error'] = str(e)`` (and ``response.error = str(e)``).

    The Response/dict-literal walk misses subscript assignment after the dict
    already exists, which is how OllamaManager used to leak exception text.
    """
    if isinstance(node, ast.Assign):
        if not _uses(node.value, exc_name):
            return False
        for target in node.targets:
            if isinstance(target, (ast.Subscript, ast.Attribute)):
                return True
    if isinstance(node, ast.AugAssign):
        return isinstance(node.target, (ast.Subscript, ast.Attribute)) and _uses(node.value, exc_name)
    return False


def find_leaks(source: str, filename: str) -> list[str]:
    leaks = []
    for handler in ast.walk(ast.parse(source, filename=filename)):
        if not isinstance(handler, ast.ExceptHandler) or not handler.name or handler.type is None:
            continue
        if _exception_names(handler) & USER_FACING_EXCEPTIONS:
            continue
        for stmt in handler.body:
            for node in ast.walk(stmt):
                if (
                    (_is_response_call(node) or isinstance(node, ast.Dict)) and _uses(node, handler.name)
                ) or _leaks_via_assignment(node, handler.name):
                    leaks.append(f'{filename}:{node.lineno}')
                    break
    return leaks


class NoExceptionTextInResponsesTest(unittest.TestCase):

    def test_view_modules_do_not_return_exception_text(self):
        leaks = []
        for pattern in VIEW_MODULE_GLOBS:
            for path in sorted(WEB_ROOT.glob(pattern)):
                rel = path.relative_to(WEB_ROOT).as_posix()
                leaks += find_leaks(path.read_text(encoding='utf-8-sig'), rel)
        self.assertEqual(
            sorted(set(leaks)), [],
            'Exception text returned to the client (log it and return '
            'INTERNAL_ERROR_MESSAGE instead):\n' + '\n'.join(sorted(set(leaks))),
        )


class FindLeaksTest(unittest.TestCase):

    def test_str_of_exception_in_response_is_flagged(self):
        src = 'try:\n    f()\nexcept Exception as e:\n    return Response({"error": str(e)})\n'
        self.assertEqual(find_leaks(src, 'v.py'), ['v.py:4'])

    def test_dict_built_then_returned_is_flagged(self):
        src = 'try:\n    f()\nexcept Exception as e:\n    r = {"message": f"boom {e}"}\n'
        self.assertEqual(find_leaks(src, 'v.py'), ['v.py:4'])

    def test_logging_the_exception_is_fine(self):
        src = ('try:\n    f()\nexcept Exception as e:\n    logger.error("x %s", e)\n'
               '    return Response({"error": MSG})\n')
        self.assertEqual(find_leaks(src, 'v.py'), [])

    def test_user_facing_exception_types_are_allowed(self):
        src = 'try:\n    f()\nexcept ValueError as e:\n    return Response({"error": str(e)})\n'
        self.assertEqual(find_leaks(src, 'v.py'), [])

    def test_subscript_assignment_of_exception_is_flagged(self):
        src = (
            'try:\n    f()\nexcept Exception as e:\n'
            '    response = {"status": False}\n'
            '    response["error"] = str(e)\n'
        )
        self.assertEqual(find_leaks(src, 'v.py'), ['v.py:5'])
