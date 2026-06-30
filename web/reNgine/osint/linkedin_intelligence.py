import json
import logging
import os
import random
import re
import time
import urllib.parse
from typing import Optional

from django.conf import settings
from django.utils import timezone
from playwright.sync_api import BrowserContext, sync_playwright
from playwright_stealth import stealth_sync

import requests as req

from reNgine.osint.hunter_lookup import _hunter_domain_search

logger = logging.getLogger(__name__)

LINKEDIN_FEED_URL = "https://www.linkedin.com/feed/"
STATE_DIR = os.path.join(settings.RENGINE_RESULTS, "context", "linkedin")
STATE_FILE_NAME = "storage_state.json"


def _validate_state_path(path: str) -> str:
    """Ensure the state file path is within STATE_DIR (Rule 1.1)."""
    resolved = os.path.realpath(path)
    base = os.path.realpath(STATE_DIR)
    if not resolved.startswith(base + os.sep) and resolved != base:
        raise ValueError("state_file_path is outside the allowed directory: %s" % path)
    return resolved


class LinkedInScraper:
    def __init__(self, session, hunter_key: str):
        self.session = session
        self.hunter_key = hunter_key
        self.notes: list = []
        self._playwright = None
        self._browser = None
        self._context: Optional[BrowserContext] = None
        self._page = None
        os.makedirs(STATE_DIR, exist_ok=True)
        if not self.session.state_file_path:
            self.session.state_file_path = os.path.join(STATE_DIR, STATE_FILE_NAME)

    def __enter__(self):
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-dev-shm-usage",
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-gpu",
            ],
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for resource in (self._context, self._browser, self._playwright):
            if resource:
                try:
                    resource.close() if hasattr(resource, "close") else resource.stop()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> bool:
        if self._try_storage_state():
            return True
        if self._try_cookie_injection():
            return True
        self.session.is_valid = False
        self.session.save(update_fields=["is_valid"])
        self.notes.append(
            "[OSINT][LinkedIn] Session invalid and cookie injection failed — "
            "LinkedIn intelligence skipped. Re-authenticate via Settings → API Keys."
        )
        return False

    def _try_storage_state(self) -> bool:
        state_path = self.session.state_file_path
        if not state_path or not os.path.isfile(state_path):
            return False
        try:
            safe_path = _validate_state_path(state_path)
        except ValueError as exc:
            logger.warning("LinkedIn state_file_path rejected: %s", exc)
            return False
        try:
            self._context = self._browser.new_context(storage_state=safe_path)
            self._page = self._context.new_page()
            stealth_sync(self._page)
            if self._validate_session():
                self.session.is_valid = True
                self.session.last_validated_at = timezone.now()
                self.session.save(update_fields=["is_valid", "last_validated_at"])
                return True
            self._close_context()
            return False
        except Exception as exc:
            logger.warning("LinkedIn storage_state load failed: %s", exc)
            self._close_context()
            return False

    def _try_cookie_injection(self) -> bool:
        if not self.session.cookies_json:
            return False
        try:
            cookies = json.loads(self.session.cookies_json)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("LinkedIn cookies_json parse failed: %s", exc)
            return False
        try:
            self._context = self._browser.new_context()
            self._context.add_cookies(cookies)
            self._page = self._context.new_page()
            stealth_sync(self._page)
            if self._validate_session():
                self._save_state()
                return True
            self._close_context()
            return False
        except Exception as exc:
            logger.warning("LinkedIn cookie injection failed: %s", exc)
            self._close_context()
            return False

    def _validate_session(self) -> bool:
        try:
            self._page.goto(LINKEDIN_FEED_URL, wait_until="networkidle", timeout=30000)
            if "login" in self._page.url:
                return False
            if self._page.query_selector('button:has-text("Sign in")'):
                return False
            return True
        except Exception as exc:
            logger.warning("LinkedIn session validation error: %s", exc)
            return False

    def _save_state(self):
        try:
            safe_path = _validate_state_path(self.session.state_file_path)
            os.makedirs(os.path.dirname(safe_path), exist_ok=True)
            self._context.storage_state(path=safe_path)
            self.session.is_valid = True
            self.session.last_validated_at = timezone.now()
            self.session.save(update_fields=["state_file_path", "is_valid", "last_validated_at"])
        except Exception as exc:
            logger.warning("LinkedIn state save failed: %s", exc)

    def _close_context(self):
        if self._context:
            try:
                self._context.close()
            except Exception:
                pass
            self._context = None
        self._page = None

    # ------------------------------------------------------------------
    # Scraping helpers
    # ------------------------------------------------------------------

    def random_sleep(self, min_s: float = 2, max_s: float = 5):
        time.sleep(random.uniform(min_s, max_s))

    def human_scroll(self):
        for _ in range(random.randint(3, 6)):
            self._page.evaluate(f"window.scrollBy(0, {random.randint(300, 700)})")
            self.random_sleep(1, 3)

    def get_hunter_pattern(self, domain: str) -> str:
        try:
            _emails, pattern = _hunter_domain_search(self.hunter_key, domain, max_results=1)
            if pattern:
                return pattern
        except Exception as exc:
            logger.warning("Failed to fetch Hunter.io pattern: %s", exc)
        return "{first}.{last}"

    def format_email(self, name: str, pattern: str, domain: str) -> str:
        parts = name.split()
        first = parts[0] if parts else ""
        last = parts[-1] if len(parts) > 1 else ""
        email = pattern.replace("{first}", first.lower())
        email = email.replace("{last}", last.lower())
        email = email.replace("{f}", first[0].lower() if first else "")
        email = email.replace("{l}", last[0].lower() if last else "")
        if "@" not in email:
            email = f"{email}@{domain}"
        return email

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def discover_employees(self, company_name: str, domain: str, scan_history) -> list:
        if not self.authenticate():
            return []

        pattern = self.get_hunter_pattern(domain)
        employees_data: list = []

        try:
            search_query = urllib.parse.quote_plus(company_name)
            self._page.goto(
                f"https://www.linkedin.com/search/results/all/?keywords={search_query}",
                wait_until="networkidle",
            )
            self.random_sleep()

            company_link = self._page.query_selector('a[href*="/company/"]')
            if company_link:
                company_url = company_link.get_attribute("href").split("?")[0]
                self._page.goto(f"{company_url}people/", wait_until="networkidle")
                self.random_sleep()
                self.human_scroll()
                for card in self._page.query_selector_all(".org-people-profile-card__profile-info"):
                    name_elem = card.query_selector(".lt-line-clamp--single-line")
                    title_elem = card.query_selector(".lt-line-clamp--multi-line")
                    if name_elem:
                        name = name_elem.inner_text().strip()
                        title = title_elem.inner_text().strip() if title_elem else "Employee"
                        employees_data.append({
                            "name": name,
                            "designation": title,
                            "email": self.format_email(name, pattern, domain),
                        })

            if not employees_data:
                self._page.goto(
                    f"https://www.linkedin.com/search/results/people/?keywords={search_query}",
                    wait_until="networkidle",
                )
                self.random_sleep()
                self.human_scroll()
                for card in self._page.query_selector_all(".entity-result__item"):
                    name_elem = card.query_selector(
                        '.entity-result__title-text a span[aria-hidden="true"]'
                    )
                    title_elem = card.query_selector(".entity-result__primary-subtitle")
                    if name_elem:
                        name = name_elem.inner_text().strip()
                        title = title_elem.inner_text().strip() if title_elem else "Employee"
                        employees_data.append({
                            "name": name,
                            "designation": title,
                            "email": self.format_email(name, pattern, domain),
                        })

        except Exception as exc:
            logger.error("Error during LinkedIn employee discovery: %s", exc)
            self.notes.append("[OSINT][LinkedIn] Discovery error: %s" % type(exc).__name__)

        try:
            safe_name = re.sub(r"[^a-zA-Z0-9]", "_", company_name).lower()
            timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
            screenshot_path = os.path.join(
                scan_history.results_dir, "osint",
                f"linkedin_{safe_name}_{timestamp}.png",
            )
            resolved = os.path.realpath(screenshot_path)
            base = os.path.realpath(settings.RENGINE_RESULTS)
            if not resolved.startswith(base + os.sep):
                raise ValueError("Screenshot path is outside RENGINE_RESULTS")
            os.makedirs(os.path.dirname(resolved), exist_ok=True)
            self._page.screenshot(path=resolved)
        except Exception as exc:
            logger.warning("LinkedIn screenshot failed: %s", exc)

        return employees_data
