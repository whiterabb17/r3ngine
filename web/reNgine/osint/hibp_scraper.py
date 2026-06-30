import logging
import time
import random
import re
from playwright.sync_api import Browser
from reNgine.screenshot.browser_manager import browser_manager
from reNgine.common_func import get_random_proxy
from startScan.models import ScanHistory, Email, EmailBreach

logger = logging.getLogger(__name__)

import undetected_chromedriver as uc
from pyvirtualdisplay import Display
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def check_email_on_hibp_uc(email_address: str, proxy_string: str = None) -> dict:
    """Core haveibeenpwned scraping logic using undetected-chromedriver and Xvfb.

    Args:
        email_address (str): Email address to search.
        proxy_string (str, optional): Proxy server configuration.

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
    display.start()

    options = uc.ChromeOptions()
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    
    if proxy_string:
        options.add_argument(f'--proxy-server={proxy_string}')
        logger.info(f"[HIBP Scraper] Using proxy: {proxy_string}")

    driver = None
    try:
        driver = uc.Chrome(version_main=123, options=options)
        logger.info(f"[HIBP Scraper] Navigating to haveibeenpwned.com for {email_address}...")
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
            logger.info(f"[HIBP Scraper] Good news! {email_address} is clean.")
            result["success"] = True
            result["pwned"] = False
            return result

        if "d-none" not in bad_result.get_attribute("class"):
            logger.info(f"[HIBP Scraper] Oh no! {email_address} is pwned.")
            result["success"] = True
            result["pwned"] = True

            time.sleep(2) # Let DOM settle
            
            with open("/usr/src/app/hibp_results.html", "w", encoding="utf-8") as f:
                f.write(driver.page_source)
                
            breach_elements = driver.find_elements(By.CSS_SELECTOR, "#timelineItems .timeline-item, .breach, .timeline-panel")
            logger.info(f"[HIBP Scraper] Found {len(breach_elements)} breach elements in DOM.")

            for breach_el in breach_elements:
                try:
                    name_els = breach_el.find_elements(By.CSS_SELECTOR, "h5, h3.pwnedCompany, h3, h4")
                    if not name_els:
                        continue
                    name = name_els[0].text.strip()

                    date_els = breach_el.find_elements(By.CSS_SELECTOR, ".timeline-date-text, .dateCircle, .timeline-badge, .timeline-date")
                    if len(date_els) >= 2 and "timeline-date-text" in date_els[0].get_attribute("class"):
                        date_text = date_els[0].text.strip() + " " + date_els[1].text.strip()
                    else:
                        date_text = date_els[0].text.strip().replace("\n", " ") if date_els else "Unknown"

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
                        li_elements = breach_el.find_elements(By.CSS_SELECTOR, "ul.timeline-details-list li, ul li, li")
                        compromised_data = [li.text.strip() for li in li_elements if li.text.strip() and "view details" not in li.text.lower()]

                    description = "\n".join(desc_texts)

                    result["breaches"].append({
                        "name": name,
                        "date": date_text,
                        "description": description,
                        "compromised_data": compromised_data
                    })
                except Exception as parse_err:
                    logger.error(f"[HIBP Scraper] Error parsing single breach entry: {parse_err}")

            return result

        result["error"] = "Result state could not be determined"
    except Exception as e:
        logger.error(f"[HIBP Scraper] Execution failed for {email_address}: {e}")
        result["error"] = str(e)
    finally:
        if driver:
            driver.quit()
        display.stop()

    return result

def scrape_email_breaches_with_retries(email_address: str) -> dict:
    """Helper to run the HIBP scraping with proxy retries and sequential delays.

    Returns:
        dict: Scraped results containing breaches.
    """
    delay = random.uniform(2.0, 5.0)
    logger.info(f"[HIBP Scraper] Sleeping for {delay:.2f} seconds before checking {email_address}...")
    time.sleep(delay)

    max_proxy_attempts = 3
    for attempt in range(max_proxy_attempts):
        proxy = get_random_proxy()
        if not proxy:
            logger.info("[HIBP Scraper] No proxy configured. Proceeding to direct scan.")
            break

        logger.info(f"[HIBP Scraper] Proxy attempt {attempt + 1}/{max_proxy_attempts} using proxy '{proxy}'")
        try:
            res = check_email_on_hibp_uc(email_address, proxy)
            if res.get("success"):
                return res
            logger.warning(f"[HIBP Scraper] Proxy request failed: {res.get('error')}")
        except Exception as e:
            logger.warning(f"[HIBP Scraper] Exception during proxy execution: {e}")

    logger.info(f"[HIBP Scraper] Final attempt: checking {email_address} directly without proxy...")
    try:
        return check_email_on_hibp_uc(email_address, None)
    except Exception as e:
        logger.error(f"[HIBP Scraper] Direct request failed: {e}")
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
    logger.info(f"[HIBP Scraper] Starting breach check for {email_address}")
    try:
        scan_history = ScanHistory.objects.get(id=scan_history_id)
        email_obj = Email.objects.get(id=email_id) if email_id else Email.objects.filter(address=email_address).first()
    except Exception as e:
        logger.error(f"[HIBP Scraper] Pre-execution database check failed: {e}")
        return 0

    # Execute scrape
    res = scrape_email_breaches_with_retries(email_address)

    if not res.get("success"):
        logger.warning(f"[HIBP Scraper] Scraping failed for {email_address}. No breaches saved.")
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

    logger.info(f"[HIBP Scraper] Successfully checked {email_address}. Saved {breach_count} breaches.")
    return breach_count
