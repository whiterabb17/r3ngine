import unittest
from unittest.mock import patch, MagicMock


def _make_response(status_code: int, json_data: dict) -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.ok = status_code < 400
    r.json.return_value = json_data
    return r


DOMAIN_SEARCH_PAGE_1 = {
    "data": {
        "pattern": "{first}.{last}",
        "emails": [
            {
                "value": "alice.smith@example.org",
                "confidence": 91,
                "type": "personal",
                "first_name": "Alice",
                "last_name": "Smith",
                "position": "CTO",
                "department": "Executive",
                "linkedin": "",
            },
            {
                "value": "info@example.org",
                "confidence": 72,
                "type": "generic",
                "first_name": None,
                "last_name": None,
                "position": None,
                "department": None,
                "linkedin": "",
            },
        ],
    },
    "meta": {"total": 2},
}


class TestHunterDomainSearch(unittest.TestCase):

    @patch("reNgine.osint.hunter_lookup.requests.get")
    def test_returns_emails_and_pattern(self, mock_get):
        mock_get.return_value = _make_response(200, DOMAIN_SEARCH_PAGE_1)

        from reNgine.osint.hunter_lookup import _hunter_domain_search
        emails, pattern = _hunter_domain_search("test-key", "example.org")

        self.assertEqual(len(emails), 2)
        self.assertEqual(emails[0]["value"], "alice.smith@example.org")
        self.assertEqual(pattern, "{first}.{last}")

    @patch("reNgine.osint.hunter_lookup.requests.get")
    def test_empty_domain_returns_empty(self, mock_get):
        mock_get.return_value = _make_response(200, {
            "data": {"pattern": "", "emails": []},
            "meta": {"total": 0},
        })

        from reNgine.osint.hunter_lookup import _hunter_domain_search
        emails, pattern = _hunter_domain_search("test-key", "empty.org")

        self.assertEqual(emails, [])

    @patch("reNgine.osint.hunter_lookup.requests.get")
    def test_401_returns_empty_no_exception(self, mock_get):
        mock_get.return_value = _make_response(401, {})

        from reNgine.osint.hunter_lookup import _hunter_domain_search
        emails, pattern = _hunter_domain_search("bad-key", "example.org")

        self.assertEqual(emails, [])
        self.assertEqual(pattern, "")

    @patch("reNgine.osint.hunter_lookup.requests.get")
    def test_connection_error_returns_empty(self, mock_get):
        import requests as req
        mock_get.side_effect = req.exceptions.ConnectionError("timeout")

        from reNgine.osint.hunter_lookup import _hunter_domain_search
        emails, pattern = _hunter_domain_search("test-key", "example.org")

        self.assertEqual(emails, [])

    @patch("reNgine.osint.hunter_lookup.requests.get")
    def test_pagination_fetches_multiple_pages(self, mock_get):
        page1 = {
            "data": {
                "pattern": "{first}.{last}",
                "emails": [{"value": f"user{i}@example.org", "confidence": 80,
                             "type": "personal", "first_name": None, "last_name": None,
                             "position": None, "department": None, "linkedin": ""}
                            for i in range(100)],
            },
            "meta": {"total": 101},
        }
        page2 = {
            "data": {
                "pattern": "{first}.{last}",
                "emails": [{"value": "extra@example.org", "confidence": 80,
                             "type": "personal", "first_name": None, "last_name": None,
                             "position": None, "department": None, "linkedin": ""}],
            },
            "meta": {"total": 101},
        }
        mock_get.side_effect = [
            _make_response(200, page1),
            _make_response(200, page2),
        ]

        from reNgine.osint.hunter_lookup import _hunter_domain_search
        emails, _ = _hunter_domain_search("test-key", "example.org")

        self.assertEqual(len(emails), 101)
        self.assertEqual(mock_get.call_count, 2)


class TestHunterEmailFinder(unittest.TestCase):

    @patch("reNgine.osint.hunter_lookup.requests.get")
    def test_found_returns_email_dict(self, mock_get):
        mock_get.return_value = _make_response(200, {
            "data": {
                "email": "jane.doe@example.org",
                "score": 88,
                "type": "personal",
                "position": "Engineer",
                "department": "Engineering",
            },
            "errors": [],
        })

        from reNgine.osint.hunter_lookup import _hunter_email_finder
        result = _hunter_email_finder("test-key", "example.org", "Jane", "Doe")

        self.assertIsNotNone(result)
        self.assertEqual(result["email"], "jane.doe@example.org")

    @patch("reNgine.osint.hunter_lookup.requests.get")
    def test_404_returns_none(self, mock_get):
        mock_get.return_value = _make_response(404, {})

        from reNgine.osint.hunter_lookup import _hunter_email_finder
        result = _hunter_email_finder("test-key", "example.org", "Ghost", "Person")

        self.assertIsNone(result)

    @patch("reNgine.osint.hunter_lookup.requests.get")
    def test_429_raises_quota_exhausted(self, mock_get):
        mock_get.return_value = _make_response(429, {})

        from reNgine.osint.hunter_lookup import _hunter_email_finder, HunterQuotaExhausted
        with self.assertRaises(HunterQuotaExhausted):
            _hunter_email_finder("test-key", "example.org", "Jane", "Doe")

    @patch("reNgine.osint.hunter_lookup.requests.get")
    def test_usage_limit_error_in_body_raises_quota_exhausted(self, mock_get):
        mock_get.return_value = _make_response(200, {
            "data": {},
            "errors": [{"code": "usage_limit", "details": "You have exceeded your usage limit."}],
        })

        from reNgine.osint.hunter_lookup import _hunter_email_finder, HunterQuotaExhausted
        with self.assertRaises(HunterQuotaExhausted):
            _hunter_email_finder("test-key", "example.org", "Jane", "Doe")

    @patch("reNgine.osint.hunter_lookup.requests.get")
    def test_connection_error_returns_none(self, mock_get):
        import requests as req
        mock_get.side_effect = req.exceptions.ConnectionError("timeout")

        from reNgine.osint.hunter_lookup import _hunter_email_finder
        result = _hunter_email_finder("test-key", "example.org", "Jane", "Doe")

        self.assertIsNone(result)


from django.test import TestCase as DjangoTestCase
from django.utils import timezone
from targetApp.models import Domain
from startScan.models import ScanHistory, Email, Employee
from scanEngine.models import EngineType


class TestRunHunterLookup(DjangoTestCase):

    def setUp(self):
        self.domain = Domain.objects.create(name="example.org")
        self.engine = EngineType.objects.create(
            engine_name="test-engine",
            yaml_configuration="{}",
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
            scan_status=1,
            results_dir="/tmp/hunter-test",
        )

    @patch("reNgine.utils.task.threading.Thread")
    def test_no_api_key_returns_skipped(self, _mock_thread):
        from reNgine.osint.hunter_lookup import run_hunter_lookup
        result = run_hunter_lookup("example.org", self.scan.id, "")

        self.assertTrue(result["skipped"])
        self.assertEqual(result["emails"], 0)
        self.assertEqual(self.scan.emails.count(), 0)

    @patch("reNgine.utils.task.threading.Thread")
    @patch("reNgine.osint.hunter_lookup.requests.get")
    def test_domain_search_saves_emails_and_employees(self, mock_get, _mock_thread):
        mock_get.return_value = _make_response(200, {
            "data": {
                "pattern": "{first}.{last}",
                "emails": [
                    {
                        "value": "alice.smith@example.org",
                        "confidence": 91,
                        "type": "personal",
                        "first_name": "Alice",
                        "last_name": "Smith",
                        "position": "CTO",
                        "department": "Executive",
                        "linkedin": "",
                    },
                ],
            },
            "meta": {"total": 1},
        })

        from reNgine.osint.hunter_lookup import run_hunter_lookup
        result = run_hunter_lookup("example.org", self.scan.id, "test-key")

        self.assertFalse(result["skipped"])
        self.assertEqual(result["emails"], 1)
        self.assertEqual(result["employees"], 1)

        email = Email.objects.get(address="alice.smith@example.org")
        self.assertEqual(email.metadata["hunter"]["source"], "domain_search")
        self.assertEqual(email.metadata["hunter"]["confidence"], 91)

        employee = Employee.objects.get(name="Alice Smith")
        self.assertEqual(employee.designation, "CTO")

    @patch("reNgine.utils.task.threading.Thread")
    @patch("reNgine.osint.hunter_lookup._hunter_email_finder")
    @patch("reNgine.osint.hunter_lookup.requests.get")
    def test_email_finder_called_for_employee_without_email(
        self, mock_get, mock_finder, _mock_thread
    ):
        mock_get.return_value = _make_response(200, {
            "data": {"pattern": "", "emails": []},
            "meta": {"total": 0},
        })
        emp = Employee.objects.create(name="Bob Jones", designation="Dev")
        self.scan.employees.add(emp)

        mock_finder.return_value = {
            "email": "bob.jones@example.org",
            "score": 85,
            "type": "personal",
            "position": "Dev",
            "department": "Engineering",
        }

        from reNgine.osint.hunter_lookup import run_hunter_lookup
        run_hunter_lookup("example.org", self.scan.id, "test-key")

        mock_finder.assert_called_once_with("test-key", "example.org", "Bob", "Jones")
        self.assertTrue(Email.objects.filter(address="bob.jones@example.org").exists())
        email = Email.objects.get(address="bob.jones@example.org")
        self.assertEqual(email.metadata["hunter"]["source"], "email_finder")

    @patch("reNgine.utils.task.threading.Thread")
    @patch("reNgine.osint.hunter_lookup._hunter_email_finder")
    @patch("reNgine.osint.hunter_lookup.requests.get")
    def test_quota_exhausted_stops_email_finder_keeps_domain_search_results(
        self, mock_get, mock_finder, _mock_thread
    ):
        mock_get.return_value = _make_response(200, {
            "data": {
                "pattern": "{first}.{last}",
                "emails": [
                    {"value": "info@example.org", "confidence": 70, "type": "generic",
                     "first_name": None, "last_name": None, "position": None,
                     "department": None, "linkedin": ""},
                ],
            },
            "meta": {"total": 1},
        })
        from reNgine.osint.hunter_lookup import HunterQuotaExhausted
        mock_finder.side_effect = HunterQuotaExhausted("quota")

        emp1 = Employee.objects.create(name="Alice Smith", designation="")
        emp2 = Employee.objects.create(name="Bob Jones", designation="")
        self.scan.employees.add(emp1, emp2)

        from reNgine.osint.hunter_lookup import run_hunter_lookup
        result = run_hunter_lookup("example.org", self.scan.id, "test-key")

        self.assertTrue(Email.objects.filter(address="info@example.org").exists())
        self.assertEqual(mock_finder.call_count, 1)
        self.assertFalse(result["skipped"])
