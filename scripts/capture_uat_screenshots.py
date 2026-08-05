"""
Capture UAT Screenshots via Selenium — AI‑IDS Streamlit App
===========================================================
Takes full-page screenshots of 4 key UAT scenarios:
  1. Live Capture page
  2. PCAP Analysis (Detection tab)
  3. Alerts page
  4. Dashboard page

Usage: python scripts/capture_uat_screenshots.py
"""
import sys, os, time, logging
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
os.chdir(str(_PROJECT_ROOT))

sys.stdout = open(1, 'w', encoding='utf-8', closefd=False)

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service

# ── Config ──
APP_URL = "http://localhost:8501"
USERNAME = "admin"
PASSWORD = "admin"
SCREENSHOTS_DIR = _PROJECT_ROOT / "screenshots"
LOG_FILE = SCREENSHOTS_DIR / "capture_log.txt"
TIMEOUT = 15

logging.basicConfig(
    filename=str(LOG_FILE), level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s", encoding="utf-8",
)
log = logging.getLogger("screenshot")
results = []


def log_result(name, ok, detail):
    results.append((name, ok, detail))
    if ok:
        log.info("PASS %s -> %s", name, detail)
    else:
        log.error("FAIL %s -> %s", name, detail)


def wait_for(driver, by, value, timeout=TIMEOUT):
    return WebDriverWait(driver, timeout).until(EC.presence_of_element_located((by, value)))


def sidebar_click(driver, href_contains):
    """Click a sidebar navigation link by href content."""
    link = wait_for(driver, By.CSS_SELECTOR,
                    f'a[data-testid="stSidebarNavLink"][href*="{href_contains}"]')
    link.click()
    time.sleep(4)


# ═══════════════════════════════════════════
script_start = time.time()
driver = None
try:
    log.info("=" * 60)
    log.info("Starting UAT screenshot capture")

    service = Service(ChromeDriverManager().install())
    opts = webdriver.ChromeOptions()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    driver = webdriver.Chrome(service=service, options=opts)
    driver.set_page_load_timeout(30)

    # ── LOGIN ──
    log.info("Logging in...")
    driver.get(APP_URL)
    wait_for(driver, By.CSS_SELECTOR, 'input[aria-label="Username"]')
    driver.find_element(By.CSS_SELECTOR, 'input[aria-label="Username"]').send_keys(USERNAME)
    driver.find_element(By.CSS_SELECTOR, 'input[aria-label="Password"]').send_keys(PASSWORD)
    driver.find_element(By.CSS_SELECTOR, 'button[kind="secondaryFormSubmit"]').click()
    time.sleep(5)
    log.info("Login successful")

    # ═══════════════════════════════════════
    # SCREENSHOT 1: Dashboard
    # ═══════════════════════════════════════
    log.info("\n[1/4] Dashboard")
    try:
        sidebar_click(driver, "/")
        wait_for(driver, By.XPATH,
                 "//*[contains(text(), 'Flows Analyzed') or contains(text(), 'Dashboard')]",
                 timeout=8)
        time.sleep(2)
        path = SCREENSHOTS_DIR / "scenario_4_dashboard.png"
        driver.save_screenshot(str(path))
        log_result("Dashboard", True, str(path))
    except Exception as e:
        log_result("Dashboard", False, str(e))

    # ═══════════════════════════════════════
    # SCREENSHOT 2: Live Capture
    # ═══════════════════════════════════════
    log.info("\n[2/4] Live Capture")
    try:
        sidebar_click(driver, "live_capture")
        time.sleep(3)

        # Try to click Start if available
        try:
            start_btn = driver.find_element(By.XPATH,
                "//button[contains(text(), 'Start Live Sniffing')]")
            start_btn.click()
            log.info("Start clicked, waiting for capture...")
            time.sleep(5)
        except NoSuchElementException:
            log.warning("Start button not found")

        path = SCREENSHOTS_DIR / "scenario_1_live_capture.png"
        driver.save_screenshot(str(path))
        log_result("Live Capture", True, str(path))

        # Stop capture gracefully
        try:
            stop_btn = driver.find_element(By.XPATH,
                "//button[contains(text(), 'Stop')]")
            stop_btn.click()
            time.sleep(1)
        except NoSuchElementException:
            pass
    except Exception as e:
        log_result("Live Capture", False, str(e))

    # ═══════════════════════════════════════
    # SCREENSHOT 3: PCAP Analysis
    # ═══════════════════════════════════════
    log.info("\n[3/4] PCAP Analysis")
    try:
        sidebar_click(driver, "detection")

        # Click the "Log (PCAP)" tab
        try:
            tab = wait_for(driver, By.XPATH,
                           "//button[@role='tab' and contains(text(), 'PCAP')]",
                           timeout=8)
        except TimeoutException:
            # Fallback: try role="tab" elements and pick the second one
            tabs = driver.find_elements(By.CSS_SELECTOR, '[role="tab"]')
            tab = tabs[1] if len(tabs) > 1 else tabs[0]
        tab.click()
        time.sleep(2)
        log.info("PCAP tab clicked")

        # Upload the test PCAP file
        try:
            file_input = wait_for(driver, By.CSS_SELECTOR,
                                  'input[type="file"]', timeout=8)
            pcap_path = str(SCREENSHOTS_DIR / "test_attack.pcap")
            file_input.send_keys(pcap_path)
            log.info("PCAP file uploaded")
            time.sleep(3)
        except (TimeoutException, NoSuchElementException) as e:
            log.warning("File upload not available: %s", e)

        # Click Analyze button
        try:
            analyze = driver.find_element(By.XPATH,
                "//button[contains(text(), 'Analyze')]")
            analyze.click()
            log.info("Analyze clicked")
            time.sleep(8)  # Wait for analysis
        except NoSuchElementException:
            log.warning("Analyze button not found")

        path = SCREENSHOTS_DIR / "scenario_2_pcap.png"
        driver.save_screenshot(str(path))
        log_result("PCAP Analysis", True, str(path))
    except Exception as e:
        log_result("PCAP Analysis", False, str(e))

    # ═══════════════════════════════════════
    # SCREENSHOT 4: Alerts
    # ═══════════════════════════════════════
    log.info("\n[4/4] Alerts")
    try:
        sidebar_click(driver, "alerts")
        time.sleep(4)
        path = SCREENSHOTS_DIR / "scenario_3_alerts.png"
        driver.save_screenshot(str(path))
        log_result("Alerts", True, str(path))
    except Exception as e:
        log_result("Alerts", False, str(e))

except Exception as global_e:
    log.error("Fatal: %s", global_e)
finally:
    if driver:
        try:
            driver.quit()
        except Exception:
            pass

    elapsed = time.time() - script_start
    log.info("Total time: %.1fs", elapsed)

    # ── Summary ──
    print(f"\n{'='*60}")
    print("SCREENSHOT CAPTURE SUMMARY")
    print(f"{'='*60}")
    ok_count = 0
    for name, ok, detail in results:
        icon = "PASS" if ok else "FAIL"
        print(f"  [{icon}] {name}")
        print(f"         {detail}")
        if ok:
            ok_count += 1
    print(f"\n{ok_count}/{len(results)} screenshots captured ({elapsed:.0f}s)")
    print(f"Log: {LOG_FILE}")
