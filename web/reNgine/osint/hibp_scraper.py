import logging
import os
import re
import time
import random
from reNgine.common_func import get_random_proxy
from reNgine.utils.process_cleanup import safe_chrome_cleanup
from startScan.models import ScanHistory, Email, EmailBreach

logger = logging.getLogger(__name__)

import undetected_chromedriver as uc
from pyvirtualdisplay import Display
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def check_email_on_hibp_uc(email_address: str, proxy_string: str = None, results_dir: str | None = None) -> dict:
    """Core haveibeenpwned scraping logic using undetected-chromedriver and Xvfb.

    Args:
        email_address (str): Email address to search.
        proxy_string (str, optional): Proxy server configuration.
        results_dir (str, optional): Directory to save the raw HTML output.

    Returns:
        dict: Dict containing success, pwned status, and breach list.
    """
    result = {
        "success": False,
        "pwned": False,
        "breaches": [],
        "error": None
    }

    display = Display(visible=0, size=(1280, 800))
    options = uc.ChromeOptions()
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')

    if proxy_string:
        options.add_argument(f'--proxy-server={proxy_string}')
        logger.info("[HIBP Scraper] Using proxy: %s", proxy_string)

    driver = None
    try:
        display.start()
        driver = uc.Chrome(version_main=123, options=options)
        logger.info("[HIBP Scraper] Navigating to haveibeenpwned.com for %s...", email_address)
        driver.get("https://haveibeenpwned.com/")

        email_input = WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.ID, "emailInput"))
        )
        email_input.send_keys(email_address)

        driver.find_element(By.ID, "checkButton").click()

        # Wait for results
        for _ in range(25):
            try:
                good = driver.find_element(By.ID, "email-result-good").get_attribute("class")
                bad = driver.find_element(By.ID, "email-result-bad").get_attribute("class")
                if "d-none" not in good or "d-none" not in bad:
                    break
            except Exception:
                pass
            time.sleep(1)

        bad_result = driver.find_element(By.ID, "email-result-bad")
        good_result = driver.find_element(By.ID, "email-result-good")

        if "d-none" not in good_result.get_attribute("class"):
            logger.info("[HIBP Scraper] Good news! %s is clean.", email_address)
            result["success"] = True
            result["pwned"] = False
            return result

        if "d-none" not in bad_result.get_attribute("class"):
            logger.info("[HIBP Scraper] Oh no! %s is pwned.", email_address)
            result["success"] = True
            result["pwned"] = True

            time.sleep(2)  # Let DOM settle

            safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', email_address)
            html_dir = results_dir or '/usr/src/app'
            os.makedirs(html_dir, exist_ok=True)
            html_path = os.path.join(html_dir, f'hibp_{safe_name}.html')
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(driver.page_source)

            breach_elements = driver.find_elements(
                By.CSS_SELECTOR,
                "#timelineItems .timeline-item, .breach, .timeline-panel"
            )
            logger.info("[HIBP Scraper] Found %d breach elements in DOM.", len(breach_elements))

            for breach_el in breach_elements:
                try:
                    name_els = breach_el.find_elements(By.CSS_SELECTOR, "h5, h3.pwnedCompany, h3, h4")
                    if not name_els:
                        continue
                    name = name_els[0].text.strip()

                    date_els = breach_el.find_elements(
                        By.CSS_SELECTOR,
                        ".timeline-date-text, .dateCircle, .timeline-badge, .timeline-date"
                    )
                    if (
                        len(date_els) >= 2
                        and "timeline-date-text" in date_els[0].get_attribute("class")
                    ):
                        date_text = date_els[0].text.strip() + " " + date_els[1].text.strip()
                    else:
                        date_text = (
                            date_els[0].text.strip().replace("\n", " ") if date_els else "Unknown"
                        )

                    paragraphs = breach_el.find_elements(By.TAG_NAME, "p")
                    desc_texts = []
                    compromised_data = []

                    for p in paragraphs:
                        text = p.text.strip()
                        if not text:
                            continue
                        if "compromised data" in text.lower() or "compromised fields" in text.lower():
                            li_elements = p.find_elements(By.TAG_NAME, "li")
                            if li_elements:
                                compromised_data = [li.text.strip() for li in li_elements]
                        elif not text.startswith("Compromised data") and not text.startswith("View details"):
                            desc_texts.append(text)

                    if not compromised_data:
                        li_elements = breach_el.find_elements(
                            By.CSS_SELECTOR, "ul.timeline-details-list li, ul li, li"
                        )
                        compromised_data = [
                            li.text.strip()
                            for li in li_elements
                            if li.text.strip() and "view details" not in li.text.lower()
                        ]

                    result["breaches"].append({
                        "name": name,
                        "date": date_text,
                        "description": "\n".join(desc_texts),
                        "compromised_data": compromised_data,
                    })
                except Exception as parse_err:
                    logger.error(
                        "[HIBP Scraper] Error parsing single breach entry: %s", parse_err
                    )

            return result

        result["error"] = "Result state could not be determined"
    except Exception as exc:
        logger.error("[HIBP Scraper] Execution failed for %s: %s", email_address, exc)
        result["error"] = str(exc)
    finally:
        safe_chrome_cleanup(driver, display)

    return result

def scrape_email_breaches_with_retries(email_address: str, results_dir: str | None = None) -> dict:
    """Helper to run the HIBP scraping with proxy retries and sequential delays.

    Returns:
        dict: Scraped results containing breaches.
    """
    delay = random.uniform(2.0, 5.0)
    logger.info("[HIBP Scraper] Sleeping for %.2f seconds before checking %s...", delay, email_address)
    time.sleep(delay)

    max_proxy_attempts = 3
    for attempt in range(max_proxy_attempts):
        proxy = get_random_proxy()
        if not proxy:
            logger.info("[HIBP Scraper] No proxy configured. Proceeding to direct scan.")
            break

        logger.info("[HIBP Scraper] Proxy attempt %d/%d using proxy %s", attempt + 1, max_proxy_attempts, proxy)
        try:
            res = check_email_on_hibp_uc(email_address, proxy, results_dir=results_dir)
            if res.get("success"):
                return res
            logger.warning("[HIBP Scraper] Proxy request failed: %s", res.get('error'))
        except Exception as e:
            logger.warning("[HIBP Scraper] Exception during proxy execution: %s", e)

    logger.info("[HIBP Scraper] Final attempt: checking %s directly without proxy...", email_address)
    try:
        return check_email_on_hibp_uc(email_address, None, results_dir=results_dir)
    except Exception as e:
        logger.error("[HIBP Scraper] Direct request failed: %s", e)
        return {"success": False, "pwned": False, "breaches": [], "error": str(e)}


def check_hibp_for_email_task(email_address: str, scan_history_id: int, email_id: int = None) -> int:
    """Main execution wrapper to check HIBP for an email, save findings to EmailBreach.

    Args:
        email_address (str): Email to check.
        scan_history_id (int): ScanHistory ID.
        email_id (int, optional): Email model ID.

    Returns:
        int: Number of breaches found and saved.
    """
    logger.info("[HIBP Scraper] Starting breach check for %s", email_address)
    try:
        scan_history = ScanHistory.objects.get(id=scan_history_id)
        email_obj = Email.objects.get(id=email_id) if email_id else Email.objects.filter(address=email_address).first()
    except Exception as e:
        logger.error("[HIBP Scraper] Pre-execution database check failed: %s", e)
        return 0

    # Build per-scan HIBP output directory so HTML files land in scan results, not /usr/src/app
    hibp_dir = os.path.join(scan_history.results_dir, 'hibp') if scan_history.results_dir else None
    if hibp_dir:
        os.makedirs(hibp_dir, exist_ok=True)

    # Execute scrape
    res = scrape_email_breaches_with_retries(email_address, results_dir=hibp_dir)

    if not res.get("success"):
        logger.warning("[HIBP Scraper] Scraping failed for %s. No breaches saved.", email_address)
        return 0

    # Clear existing breaches for this email in this scan
    EmailBreach.objects.filter(scan_history=scan_history, email_address=email_address).delete()

    breach_count = 0
    if res.get("pwned") and res.get("breaches"):
        for b in res["breaches"]:
            EmailBreach.objects.create(
                scan_history=scan_history,
                email=email_obj,
                email_address=email_address,
                breach_name=b["name"],
                breach_date=b["date"],
                description=b["description"],
                compromised_data=b["compromised_data"]
            )
            breach_count += 1

    logger.info("[HIBP Scraper] Successfully checked %s. Saved %d breaches.", email_address, breach_count)
    return breach_count
