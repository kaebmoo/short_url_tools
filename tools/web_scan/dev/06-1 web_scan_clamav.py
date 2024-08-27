import requests
import subprocess
import tempfile
import os
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError, Error as PlaywrightError

def get_mime_type(url):
    try:
        response = requests.head(url, timeout=10, allow_redirects=True)
        mime_type = response.headers.get('Content-Type', '').lower()
        return mime_type
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while trying to get MIME type: {e}")
        return None

def is_direct_file(url):
    parsed_url = urlparse(url)
    if os.path.splitext(parsed_url.path)[1] != '':
        return True
    mime_type = get_mime_type(url)
    if mime_type and ('application/octet-stream' in mime_type or 'application' in mime_type or 'binary' in mime_type):
        return True
    return False

def download_file_with_requests(url):
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()

        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            for chunk in response.iter_content(chunk_size=8192):
                tmp_file.write(chunk)
            return tmp_file.name
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while trying to download the file: {e}")
        return None

def download_page_with_playwright(url):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(ignore_https_errors=True)
            page.set_default_navigation_timeout(30000)  # 30 seconds timeout
            
            try:
                page.goto(url)
                with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
                    tmp_file.write(page.content().encode('utf-8'))
                    return tmp_file.name
            except PlaywrightTimeoutError:
                print(f"Timeout error: The page took too long to load: {url}")
                return None
            except PlaywrightError as e:
                print(f"An error occurred while trying to load the page: {e}")
                return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def get_file_type(file_path):
    try:
        result = subprocess.run(['file', '--mime-type', '-b', file_path], stdout=subprocess.PIPE)
        return result.stdout.decode('utf-8').strip()
    except Exception as e:
        print(f"An error occurred while determining the file type: {e}")
        return None

def scan_file_with_clamav(file_path):
    try:
        result = subprocess.run(['clamdscan', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8')
        print("ClamAV Scan Result:\n", output)
        if "Infected files: 0" in output:
            print("No threats found.")
        else:
            print("Threat detected!")
    except Exception as e:
        print(f"An error occurred while scanning the file: {e}")

def main():
    url = "http://185.215.113.19/inc/cookie250.exe"  # เปลี่ยน URL ตามต้องการ
    url = "https://urlhaus.abuse.ch/browse/page/2/"

    if is_direct_file(url):
        print("Detected direct file download.")
        file_path = download_file_with_requests(url)
    else:
        print("Detected web page.")
        file_path = download_page_with_playwright(url)

    if file_path:
        file_type = get_file_type(file_path)
        print(f"File type detected: {file_type}")
        scan_file_with_clamav(file_path)
        os.remove(file_path)  # ลบไฟล์ชั่วคราวหลังจากสแกนเสร็จสิ้น

if __name__ == "__main__":
    main()
