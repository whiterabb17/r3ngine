---
description: Testing conventions for r3ngine — test location, Django TestCase patterns, Temporal activity testing, and running tests in Docker.
---

# r3ngine – Testing conventions

## Scope

Use this rule when writing or updating tests in `web/tests/` (unit, integration, and functional tests).

## Test location and structure

- All tests must live under `web/tests/`.
- Mirror the module being tested:
  - Tests for `web/reNgine/fuzzing_tasks.py` → `web/tests/test_fuzzing_tasks.py`
  - Tests for `web/startScan/views.py` → `web/tests/test_startScan_views.py`

## Test base classes and data

- Use `django.test.TestCase` as the base class for tests that need database access.
- Use `unittest.TestCase` for pure-logic tests that need no DB.
- Use `django.test.RequestFactory` or `django.test.Client` for view tests; never make real HTTP calls.
- Anonymise all test data (IP addresses, hostnames, DNS records, emails) — do not use real domains or credentials.

### Example — basic TestCase

```python
from django.test import TestCase
from startScan.models import ScanHistory

class TestMyActivity(TestCase):
    def setUp(self):
        self.scan = ScanHistory.objects.create(
            scan_status='pending',
            # use fake/anonymised data
        )

    def test_expected_behavior(self):
        result = my_function(self.scan.id)
        self.assertIsNotNone(result)
```

## Temporal activity testing

- Test activity functions directly (call the Python function) — do not spin up a Temporal worker in unit tests.
- Mock subprocess calls and external tool invocations using `unittest.mock.patch`.
- For integration tests that require a real Temporal worker, tag them clearly and exclude from the standard `python manage.py test` run.

```python
from unittest.mock import patch
from reNgine.temporal.activities import run_port_scan_activity

class TestPortScanActivity(TestCase):
    # Patch at the module where the function is defined (temporal/activities/__init__.py)
    @patch('reNgine.temporal.activities.subprocess.run')
    def test_port_scan_parses_output(self, mock_run):
        mock_run.return_value.stdout = b'...'
        result = run_port_scan_activity(scan_id=1, target='192.0.2.1')
        self.assertIn('ports', result)
```

**Patch target rule**: always patch where the name is looked up, not where it is defined. After the modular refactor, functions extracted to domain modules (e.g. `reNgine.tasks.vuln`, `reNgine.tasks.scan_init`, `reNgine.temporal.activities`) must be patched at their new location, not via the shim path.

## Determinism and isolation

- Tests must be deterministic and independent of timing.
- Never call `time.sleep()` in tests — mock time-dependent code.
- Never make real network calls; mock all outbound HTTP and subprocess calls.
- Cover edge cases, especially around error handling and empty results.

## Running tests (always inside Docker)

All `manage.py` test commands must be run **inside the Docker container**:

```bash
# Run full test suite — always use --keepdb and --verbosity=2
docker exec r3ngine-web-1 bash -c "cd /usr/src/app && python3 manage.py test --keepdb --verbosity=2 2>&1 | tail -20"

# Run a specific test module
docker exec r3ngine-web-1 bash -c "cd /usr/src/app && python3 manage.py test tests.test_fuzzing_tasks --keepdb --verbosity=2"

# Run with coverage (if coverage is installed)
docker exec r3ngine-web-1 bash -c \
  "cd /usr/src/app && coverage run --source='.' manage.py test --keepdb && coverage report"
```

**`--keepdb` is mandatory** — it prevents Django from dropping the test database between runs. **`--verbosity=2`** ensures error tracebacks and test names are captured in the first pass. Remove `-it` (TTY flag) when running inside scripts or Claude Code.

## Temporary test files

If you generate temporary Python validation scripts outside of the tests directory, delete them once they are no longer needed.