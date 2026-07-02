import logging
import signal

import psutil

logger = logging.getLogger(__name__)


def kill_process_tree(pid: int, timeout: float = 3.0) -> None:
    """Send SIGTERM to an entire process subtree, then SIGKILL any survivors."""
    try:
        parent = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return

    children = parent.children(recursive=True)

    for proc in children:
        try:
            proc.send_signal(signal.SIGTERM)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    try:
        parent.send_signal(signal.SIGTERM)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    all_procs = children + [parent]
    _, alive = psutil.wait_procs(all_procs, timeout=timeout)
    for proc in alive:
        try:
            proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


def safe_chrome_cleanup(driver=None, display=None) -> None:
    """Gracefully stop a Chrome driver and Xvfb display, then forcibly kill any
    remaining processes in their trees.

    Each step runs in its own try/except so a failure in one never skips the rest.
    """
    if driver is not None:
        try:
            driver.quit()
        except Exception as exc:
            logger.warning("driver.quit() raised during cleanup: %s", exc)

        browser_pid = getattr(driver, 'browser_pid', None)
        if browser_pid:
            logger.debug("Killing Chrome process tree rooted at pid %s", browser_pid)
            kill_process_tree(browser_pid)

        service_pid = None
        try:
            service_pid = driver.service.process.pid
        except AttributeError:
            pass
        if service_pid:
            logger.debug("Killing chromedriver service process tree at pid %s", service_pid)
            kill_process_tree(service_pid)

    if display is not None:
        try:
            display.stop()
        except Exception as exc:
            logger.warning("display.stop() raised during cleanup: %s", exc)

        xvfb_pid = getattr(display, 'pid', None)
        if xvfb_pid:
            logger.debug("Killing Xvfb process tree rooted at pid %s", xvfb_pid)
            kill_process_tree(xvfb_pid)
