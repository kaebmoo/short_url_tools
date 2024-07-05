import csv
import os
import time
from pathlib import Path
from urllib.parse import urlparse

from RPA.Browser.Selenium import Selenium
from RPA.FileSystem import FileSystem

# สร้างออบเจ็กต์ Selenium และ FileSystem
browser = Selenium()
file_system = FileSystem()

OUTPUT_DIR = Path(os.environ.get("ROBOT_ARTIFACTS", "scraper/output"))
DEVDATA = Path("scraper")

ACCEPT_COOKIES_SELECTOR = "accept_cookies_selector"
DATA_CONSENT_SELECTOR = "data_consent_selector"


def take_website_screenshots():
    """Take screenshots of all websites found in websites.csv file."""
    with open(str(DEVDATA / "websites.csv")) as csv_file:
        csv_reader = csv.DictReader(csv_file)
        websites = list(csv_reader)

    browser.open_available_browser()
    
    try:
        for website in websites:
            browser.go_to(website["url"])

            accept_cookies_and_consents(website)

            # Some websites have animations on cookies and consents so wait for that to disappear.
            time.sleep(1)

            domain = urlparse(website["url"]).netloc.replace(".", "_")
            screenshot_path = str(OUTPUT_DIR / f"{domain}.png")
            browser.capture_page_screenshot(screenshot_path)
            print(f"Screenshot saved to {screenshot_path}")
    finally:
        browser.close_browser()


def accept_cookies_and_consents(website: dict):
    """
    Accept cookies and data consents on every page before taking a screenshot.

    Args:
        website (dict): A dictionary with website related info, including the locators to find the consent elements with.
    """
    cookie_selector = website.get(ACCEPT_COOKIES_SELECTOR)
    if cookie_selector:
        try:
            browser.click_element_when_visible(cookie_selector)
        except Exception as exc:
            print(f"An error occurred during the cookies accept: {exc}")

    data_consent_selector = website.get(DATA_CONSENT_SELECTOR)
    if data_consent_selector:
        try:
            browser.click_element_when_visible(data_consent_selector)
        except Exception as exc:
            print(f"An error occurred during the data consent: {exc}")


take_website_screenshots()
