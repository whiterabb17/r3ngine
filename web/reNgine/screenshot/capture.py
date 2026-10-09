import hashlib
import os
import logging
from django.conf import settings
from playwright.sync_api import Error as PlaywrightError
from .browser_manager import browser_manager

logger = logging.getLogger(__name__)

def block_resources(route):
    """Performance optimization: block heavy resources."""
    if route.request.resource_type in ["media", "font", "websocket"]:
        route.abort()
        return

    # Block trackers
    trackers = ["google-analytics.com", "googletagmanager.com", "facebook.net", "doubleclick.net"]
    if any(tracker in route.request.url for tracker in trackers):
        route.abort()
        return

    route.continue_()

def capture_url(browser, url, scan_id, results_dir=None):
    """
    Core capture engine (Synchronous).
    """
    if not results_dir:
        results_dir = settings.RENGINE_RESULTS
    
    # Create unique context for this capture
    context = browser.new_context(
        viewport={'width': 1280, 'height': 800},
        ignore_https_errors=True,
        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    )

    # Prepare paths
    url_hash = hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()
    
    screenshot_rel_dir = f"screenshots/{scan_id}"
    html_rel_dir = f"html/{scan_id}"
    
    screenshot_full_dir = os.path.join(results_dir, screenshot_rel_dir)
    html_full_dir = os.path.join(results_dir, html_rel_dir)
    
    os.makedirs(screenshot_full_dir, exist_ok=True)
    os.makedirs(html_full_dir, exist_ok=True)
    
    screenshot_filename = f"{url_hash}.png"
    html_filename = f"{url_hash}.html"
    
    screenshot_full_path = os.path.join(screenshot_full_dir, screenshot_filename)
    html_full_path = os.path.join(html_full_dir, html_filename)
    
    screenshot_rel_path = f"{screenshot_rel_dir}/{screenshot_filename}"
    html_rel_path = f"{html_rel_dir}/{html_filename}"

    result = {
        "url": url,
        "success": False,
        "title": None,
        "status_code": None,
        "screenshot_path": None,
        "html_path": None,
        "response_headers": {},
        "tags": [],
    }

    page = context.new_page()
    page.route("**/*", block_resources)

    try:
        logger.info("Navigating to %s...", url)
        response = page.goto(url, wait_until="networkidle", timeout=30000)
        
        if response:
            result["success"] = True
            result["status_code"] = response.status
            result["title"] = page.title()
            result["response_headers"] = dict(response.headers)
            
            # Detect Login Panel
            if page.query_selector('input[type="password"]'):
                result["tags"].append("login_panel")
            
            # Save Screenshot
            page.screenshot(path=screenshot_full_path, full_page=True)
            result["screenshot_path"] = screenshot_rel_path
            
            # Save HTML
            content = page.content()
            with open(html_full_path, "w", encoding="utf-8") as f:
                f.write(content)
            result["html_path"] = html_rel_path
            
    except Exception as e:
        logger.error("Capture failed for %s: %s", url, str(e))
        # Try a partial/lazy screenshot if we reached the page but failed networkidle
        try:
            page.screenshot(path=screenshot_full_path)
            result["screenshot_path"] = screenshot_rel_path
        except PlaywrightError:
            pass  # the capture failure above is already logged
    finally:
        page.close()
        context.close()

    return result

def run_capture(url, scan_id, results_dir=None):
    """Wrapper for Celery tasks (already sync now)."""
    if not results_dir:
        results_dir = settings.RENGINE_RESULTS
    return browser_manager.execute(capture_url, url, scan_id, results_dir=results_dir)
