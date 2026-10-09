import logging
import os
from urllib.parse import urlparse
from startScan.models import Screenshot, Subdomain, ScanHistory, EndPoint, Command
from django.utils import timezone
from django.conf import settings
from .capture import run_capture

# Playwright's sync API uses an event loop under the hood, 
# so we need to allow Django ORM to run in this "pseudo-async" context.
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"

logger = logging.getLogger(__name__)

def take_screenshot_and_save(subdomain_id, scan_id, results_dir=None, activity_id=None, url_override=None):
    """
    Orchestrates the capture and database persistence of screenshots for a subdomain.

    When url_override is provided (recommended), that exact URL is captured without
    any path stripping — mirrors the rengine-ng pattern of passing full endpoint URLs.

    When url_override is None, falls back to the legacy behaviour: queries all
    endpoints for the subdomain, collapses them to base URLs (scheme://netloc),
    and caps at MAX_SCREENSHOTS_PER_SUBDOMAIN.

    Args:
        subdomain_id (int): ID of the Subdomain object.
        scan_id (int): ID of the ScanHistory object.
        results_dir (str, optional): Directory for results. Defaults to settings.RENGINE_RESULTS.
        activity_id (int, optional): ID of the ScanActivity executing this task.
        url_override (str, optional): Full URL to capture. Skips endpoint querying when set.

    Returns:
        bool: True if at least one screenshot was successfully captured and saved.
    """
    if not results_dir:
        results_dir = settings.RENGINE_RESULTS
    try:
        subdomain = Subdomain.objects.get(id=subdomain_id)
        scan = ScanHistory.objects.get(id=scan_id)

        if url_override is not None:
            parsed_override = urlparse(url_override)
            if parsed_override.scheme not in ('http', 'https'):
                logger.error(
                    "url_override rejected — invalid scheme: %s",
                    parsed_override.scheme or '(empty)'
                )
                return False
            # Use the caller-provided URL directly — no path stripping.
            target_urls = [url_override]
        else:
            # Legacy: gather all endpoints for this subdomain and collapse to base URLs.
            endpoints = EndPoint.objects.filter(subdomain=subdomain, scan_history=scan)

            # 2. Extract unique base URLs (scheme://netloc)
            urls_to_capture = set()
            for ep in endpoints:
                if ep.http_url:
                    try:
                        parsed = urlparse(ep.http_url)
                        if parsed.scheme and parsed.netloc:
                            base_url = f"{parsed.scheme}://{parsed.netloc}"
                            urls_to_capture.add(base_url)
                    except Exception as parse_err:
                        logger.debug("Failed to parse endpoint URL %s: %s", ep.http_url, parse_err)

            # 3. Add subdomain's main http_url if present
            if subdomain.http_url:
                try:
                    parsed = urlparse(subdomain.http_url)
                    if parsed.scheme and parsed.netloc:
                        urls_to_capture.add(f"{parsed.scheme}://{parsed.netloc}")
                    else:
                        urls_to_capture.add(subdomain.http_url)
                except Exception:
                    urls_to_capture.add(subdomain.http_url)

            # 4. Fallback to guessing if no URLs discovered
            if not urls_to_capture:
                urls_to_capture.add(f"http://{subdomain.name}")
                urls_to_capture.add(f"https://{subdomain.name}")

            # 5. Cap to a maximum of 10 unique base URLs to prevent resource thrashing
            max_screenshots = int(os.getenv("MAX_SCREENSHOTS_PER_SUBDOMAIN", 10))
            target_urls = sorted(list(urls_to_capture))[:max_screenshots]

        logger.info(
            "Processing %s screenshot(s) for subdomain %s (ID: %s)", len(target_urls), subdomain.name, subdomain_id
        )
        
        success_count = 0
        first_successful_path = None

        for url in target_urls:
            try:
                logger.info("Capturing screenshot for %s (Subdomain ID: %s)", url, subdomain_id)
                # Record command for timeline
                Command.objects.create(
                    command=f"Playwright: screenshot {url}",
                    time=timezone.now(),
                    scan_history_id=scan_id,
                    activity_id=activity_id
                )

                capture_result = run_capture(url, scan_id, results_dir)
                
                # Save to database if we got at least a screenshot
                if capture_result["screenshot_path"]:
                    Screenshot.objects.create(
                        subdomain=subdomain,
                        scan_history=scan,
                        url=url,
                        title=capture_result["title"],
                        status_code=capture_result["status_code"],
                        screenshot_path=capture_result["screenshot_path"],
                        html_path=capture_result["html_path"],
                        response_headers=capture_result.get("response_headers", {}),
                        tags=capture_result.get("tags", [])
                    )
                    success_count += 1
                    if not first_successful_path:
                        first_successful_path = capture_result["screenshot_path"]
                    logger.info("Successfully saved screenshot for %s", url)
                else:
                    logger.warning("No screenshot captured for %s", url)
            except Exception as capture_err:
                logger.error("Error capturing screenshot for %s: %s", url, str(capture_err))

        if first_successful_path:
            # Update the subdomain's legacy path field with the first success
            subdomain.screenshot_path = first_successful_path
            subdomain.save(update_fields=['screenshot_path'])
            return True
            
    except Subdomain.DoesNotExist:
        logger.error("Subdomain with ID %s does not exist.", subdomain_id)
    except ScanHistory.DoesNotExist:
        logger.error("ScanHistory with ID %s does not exist.", scan_id)
    except Exception as e:
        logger.error("Error in take_screenshot_and_save: %s", str(e))
        
    return False
