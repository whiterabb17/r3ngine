import logging
import os
import queue
import threading
import time
import atexit
from playwright.sync_api import sync_playwright

logger = logging.getLogger(__name__)

class PlaywrightThread(threading.Thread):
    def __init__(self, idle_timeout=60):
        super().__init__()
        self.daemon = True
        self.idle_timeout = idle_timeout
        self.queue = queue.Queue()
        self.running = True
        self.playwright = None
        self.browser = None
        self.last_activity = time.time()
        self.lock = threading.Lock()

    def run(self):
        logger.info("PlaywrightThread started.")
        while self.running:
            try:
                # If a browser exists, wake up every 1s to check idle timeout.
                # Otherwise, wait indefinitely.
                has_browser = self.browser is not None
                timeout = 1.0 if has_browser else None
                
                try:
                    task = self.queue.get(timeout=timeout)
                except queue.Empty:
                    # Check for idle timeout
                    if self.browser and (time.time() - self.last_activity) >= self.idle_timeout:
                        logger.info("Shutting down browser after %ss of inactivity.", self.idle_timeout)
                        self._shutdown_resources()
                    continue

                func, args, kwargs, reply_queue = task
                self.last_activity = time.time()

                # Lazy init of Playwright and Browser inside the thread
                if not self.browser:
                    try:
                        logger.info("Initializing Playwright (Sync) inside PlaywrightThread...")
                        self.playwright = sync_playwright().start()
                        logger.info("Launching Chromium browser (headless) inside PlaywrightThread...")
                        self.browser = self.playwright.chromium.launch(
                            headless=True,
                            args=[
                                "--disable-dev-shm-usage",
                                "--no-sandbox",
                                "--disable-setuid-sandbox",
                                "--disable-gpu",
                                "--disable-background-networking",
                                "--disable-sync",
                                "--metrics-recording-only",
                                "--disable-default-apps"
                            ]
                        )
                    except Exception as e:
                        logger.error("Failed to launch browser inside PlaywrightThread: %s", e)
                        reply_queue.put((None, e))
                        self.queue.task_done()
                        continue

                # Execute task on PlaywrightThread
                try:
                    res = func(self.browser, *args, **kwargs)
                    reply_queue.put((res, None))
                except Exception as e:
                    logger.error("Error executing screenshot task: %s", e)
                    reply_queue.put((None, e))
                finally:
                    self.queue.task_done()
                    self.last_activity = time.time()

            except Exception as e:
                logger.error("Error in PlaywrightThread event loop: %s", e)
                time.sleep(1)

        # Cleanup on stop
        self._shutdown_resources()
        logger.info("PlaywrightThread exited.")

    def _shutdown_resources(self):
        if self.browser:
            try:
                self.browser.close()
            except Exception as e:
                logger.error("Error closing browser: %s", e)
            self.browser = None
        if self.playwright:
            try:
                self.playwright.stop()
            except Exception as e:
                logger.error("Error stopping playwright: %s", e)
            self.playwright = None


class BrowserManager:
    _instance = None
    _lock = threading.Lock()
    _thread = None
    _idle_timeout = int(os.getenv("SCREENSHOT_IDLE_TIMEOUT", 60))

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(BrowserManager, cls).__new__(cls)
        return cls._instance

    def _ensure_thread_active(self):
        """Ensures that the PlaywrightThread is alive and active."""
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                logger.info("Starting a new PlaywrightThread...")
                self._thread = PlaywrightThread(idle_timeout=self._idle_timeout)
                self._thread.start()

    def execute(self, func, *args, **kwargs):
        """Executes a function on the dedicated PlaywrightThread and returns the result."""
        self._ensure_thread_active()
        
        reply_queue = queue.Queue()
        self._thread.queue.put((func, args, kwargs, reply_queue))
        
        res, err = reply_queue.get()
        if err:
            raise err
        return res

    def shutdown(self):
        """Clean shutdown of the browser thread (e.g. at app termination)."""
        try:
            with self._lock:
                if self._thread and self._thread.is_alive():
                    logger.info("Shutting down PlaywrightThread...")
                    self._thread.running = False
                    # Send a dummy task to wake up the loop if it's waiting
                    def dummy(browser):
                        pass
                    reply_queue = queue.Queue()
                    self._thread.queue.put((dummy, (), {}, reply_queue))
                    try:
                        self._thread.join(timeout=5)
                    except Exception as e:
                        logger.error("Error joining PlaywrightThread: %s", e)
                    self._thread = None
        except Exception:
            # Runs from atexit: log and let interpreter shutdown continue.
            logger.warning("PlaywrightThread shutdown failed", exc_info=True)

browser_manager = BrowserManager()
atexit.register(browser_manager.shutdown)
