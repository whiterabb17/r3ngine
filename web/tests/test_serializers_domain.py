"""Tests for DomainSerializer fields that depend on ScanHistory."""
from django.test import TestCase
from unittest.mock import patch, MagicMock


class DomainSerializerGetRecentScanTest(TestCase):
    """_get_recent_scan must find scans even when Domain.start_scan_date is None."""

    def _make_domain(self, start_scan_date=None):
        domain = MagicMock()
        domain.id = 1
        domain.start_scan_date = start_scan_date
        return domain

    def _make_scan(self, scan_id=42, scan_status=1):
        scan = MagicMock()
        scan.id = scan_id
        scan.scan_status = scan_status
        scan.get_progress.return_value = 50
        return scan

    def test_returns_scan_when_start_scan_date_is_none(self):
        """Domain.start_scan_date=None must NOT suppress an existing ScanHistory row."""
        from api.serializers import DomainSerializer
        domain = self._make_domain(start_scan_date=None)
        mock_scan = self._make_scan()

        serializer = DomainSerializer()
        with patch('api.serializers.apps') as mock_apps:
            mock_qs = MagicMock()
            mock_qs.filter.return_value.order_by.return_value.first.return_value = mock_scan
            mock_apps.get_model.return_value.objects = mock_qs
            result = serializer._get_recent_scan(domain)

        self.assertEqual(result, mock_scan)

    def test_returns_none_when_no_scan_history(self):
        """Returns None when no ScanHistory rows exist for the domain."""
        from api.serializers import DomainSerializer
        domain = self._make_domain(start_scan_date=None)

        serializer = DomainSerializer()
        with patch('api.serializers.apps') as mock_apps:
            mock_qs = MagicMock()
            mock_qs.filter.return_value.order_by.return_value.first.return_value = None
            mock_apps.get_model.return_value.objects = mock_qs
            result = serializer._get_recent_scan(domain)

        self.assertIsNone(result)

    def test_get_most_recent_scan_status_returns_never_scanned_when_no_rows(self):
        """get_most_recent_scan_status must return NEVER_SCANNED with no ScanHistory."""
        from api.serializers import DomainSerializer
        domain = self._make_domain()

        serializer = DomainSerializer()
        with patch.object(serializer, '_get_recent_scan', return_value=None):
            result = serializer.get_most_recent_scan_status(domain)

        self.assertEqual(result, 'NEVER_SCANNED')

    def test_get_most_recent_scan_returns_none_when_no_rows(self):
        """get_most_recent_scan must return None with no ScanHistory."""
        from api.serializers import DomainSerializer
        domain = self._make_domain()

        serializer = DomainSerializer()
        with patch.object(serializer, '_get_recent_scan', return_value=None):
            result = serializer.get_most_recent_scan(domain)

        self.assertIsNone(result)

    def test_get_most_recent_scan_progress_returns_zero_when_no_rows(self):
        """get_most_recent_scan_progress must return 0 with no ScanHistory."""
        from api.serializers import DomainSerializer
        domain = self._make_domain()

        serializer = DomainSerializer()
        with patch.object(serializer, '_get_recent_scan', return_value=None):
            result = serializer.get_most_recent_scan_progress(domain)

        self.assertEqual(result, 0)


class DomainSerializerSortOrderTest(TestCase):
    """_get_recent_scan must return the scan with the highest PK, not highest start_scan_date."""

    def test_orders_by_pk_descending(self):
        """
        Ordering by -id matches the original get_recent_scan_id() contract and is
        safe against backdated re-scans or fixture data with explicit timestamps.
        """
        from api.serializers import DomainSerializer

        domain = MagicMock()
        domain.id = 1
        domain.start_scan_date = None

        expected_scan = MagicMock()
        expected_scan.id = 99

        serializer = DomainSerializer()
        with patch('api.serializers.apps') as mock_apps:
            mock_qs = MagicMock()
            mock_qs.filter.return_value.order_by.return_value.first.return_value = expected_scan
            mock_apps.get_model.return_value.objects = mock_qs

            result = serializer._get_recent_scan(domain)

        mock_qs.filter.return_value.order_by.assert_called_once_with('-id')
        self.assertEqual(result.id, 99)
