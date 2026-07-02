import signal
import subprocess
import unittest
from unittest.mock import MagicMock, patch, call

from reNgine.utils.process_cleanup import kill_process_tree, safe_chrome_cleanup


class TestKillProcessTree(unittest.TestCase):

    @patch('reNgine.utils.process_cleanup.psutil.Process')
    def test_kills_children_then_parent(self, mock_process_cls):
        child = MagicMock()
        parent = MagicMock()
        parent.children.return_value = [child]
        mock_process_cls.return_value = parent

        # Simulate no survivors after wait
        import psutil as _psutil
        with patch('reNgine.utils.process_cleanup.psutil.wait_procs', return_value=([], [])):
            kill_process_tree(1234)

        child.send_signal.assert_called_once_with(signal.SIGTERM)
        parent.send_signal.assert_called_once_with(signal.SIGTERM)

    @patch('reNgine.utils.process_cleanup.psutil.Process')
    def test_sigkills_survivors(self, mock_process_cls):
        child = MagicMock()
        parent = MagicMock()
        parent.children.return_value = [child]
        mock_process_cls.return_value = parent

        # Both survive the wait
        with patch('reNgine.utils.process_cleanup.psutil.wait_procs', return_value=([], [child, parent])):
            kill_process_tree(1234)

        child.kill.assert_called_once()
        parent.kill.assert_called_once()

    @patch('reNgine.utils.process_cleanup.psutil.Process')
    def test_no_such_process_is_silent(self, mock_process_cls):
        import psutil as _psutil
        mock_process_cls.side_effect = _psutil.NoSuchProcess(9999)
        # Must not raise
        kill_process_tree(9999)

    @patch('reNgine.utils.process_cleanup.psutil.Process')
    def test_access_denied_on_child_is_silent(self, mock_process_cls):
        import psutil as _psutil
        child = MagicMock()
        child.send_signal.side_effect = _psutil.AccessDenied(1111)
        parent = MagicMock()
        parent.children.return_value = [child]
        mock_process_cls.return_value = parent

        with patch('reNgine.utils.process_cleanup.psutil.wait_procs', return_value=([], [])):
            kill_process_tree(1234)  # must not raise


class TestSafeChromeCleanup(unittest.TestCase):

    @patch('reNgine.utils.process_cleanup.kill_process_tree')
    def test_calls_driver_quit_and_kills_browser_pid(self, mock_kill):
        driver = MagicMock()
        driver.browser_pid = 5555
        driver.service.process.pid = 6666

        display = MagicMock()
        display.pid = 7777

        safe_chrome_cleanup(driver, display)

        driver.quit.assert_called_once()
        display.stop.assert_called_once()
        mock_kill.assert_any_call(5555)
        mock_kill.assert_any_call(6666)
        mock_kill.assert_any_call(7777)

    @patch('reNgine.utils.process_cleanup.kill_process_tree')
    def test_display_stop_runs_even_if_driver_quit_raises(self, mock_kill):
        driver = MagicMock()
        driver.browser_pid = 5555
        driver.service.process.pid = 6666
        driver.quit.side_effect = Exception("chrome crashed")

        display = MagicMock()
        display.pid = 7777

        # Must not raise, and display.stop must still be called
        safe_chrome_cleanup(driver, display)
        display.stop.assert_called_once()

    @patch('reNgine.utils.process_cleanup.kill_process_tree')
    def test_none_driver_is_safe(self, mock_kill):
        display = MagicMock()
        display.pid = 7777

        safe_chrome_cleanup(driver=None, display=display)

        display.stop.assert_called_once()
        mock_kill.assert_called_once_with(7777)

    @patch('reNgine.utils.process_cleanup.kill_process_tree')
    def test_none_display_is_safe(self, mock_kill):
        driver = MagicMock()
        driver.browser_pid = 5555
        driver.service.process.pid = 6666

        safe_chrome_cleanup(driver=driver, display=None)

        driver.quit.assert_called_once()

    @patch('reNgine.utils.process_cleanup.kill_process_tree')
    def test_missing_browser_pid_skips_kill(self, mock_kill):
        driver = MagicMock(spec=[])  # no browser_pid attribute
        driver.quit = MagicMock()

        display = MagicMock()
        display.pid = 7777

        safe_chrome_cleanup(driver=driver, display=display)
        # Only display pid killed
        mock_kill.assert_called_once_with(7777)


class TestHibpScraperCleanup(unittest.TestCase):
    """Verify hibp_scraper always cleans up Chrome and display regardless of errors."""

    @patch('reNgine.osint.hibp_scraper.safe_chrome_cleanup')
    @patch('reNgine.osint.hibp_scraper.uc.Chrome')
    @patch('reNgine.osint.hibp_scraper.Display')
    def test_cleanup_called_when_chrome_raises(self, mock_display_cls, mock_chrome_cls, mock_cleanup):
        mock_display_cls.return_value.start.return_value = None
        mock_chrome_cls.side_effect = Exception("chromedriver not found")

        from reNgine.osint.hibp_scraper import check_email_on_hibp_uc
        result = check_email_on_hibp_uc("test@example.com")

        mock_cleanup.assert_called_once_with(None, mock_display_cls.return_value)
        self.assertFalse(result["success"])

    @patch('reNgine.osint.hibp_scraper.safe_chrome_cleanup')
    @patch('reNgine.osint.hibp_scraper.uc.Chrome')
    @patch('reNgine.osint.hibp_scraper.Display')
    def test_cleanup_called_on_success_path(self, mock_display_cls, mock_chrome_cls, mock_cleanup):
        mock_display = MagicMock()
        mock_display_cls.return_value = mock_display

        mock_driver = MagicMock()
        mock_chrome_cls.return_value = mock_driver

        # Simulate WebDriverWait raising so we get to finally quickly
        with patch('reNgine.osint.hibp_scraper.WebDriverWait', side_effect=Exception("timeout")):
            from reNgine.osint.hibp_scraper import check_email_on_hibp_uc
            check_email_on_hibp_uc("test@example.com")

        mock_cleanup.assert_called_once_with(mock_driver, mock_display)
