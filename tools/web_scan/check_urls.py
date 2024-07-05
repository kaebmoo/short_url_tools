#tools/web_scan/check_urls.py
import os
from dotenv import load_dotenv

# โหลดค่าจาก .env
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), 'config.env'))

# อ่านค่าจาก config.env
INTERVAL_HOURS = int(os.getenv("INTERVAL_HOURS", 2))  # ค่า default 1 ถ้าไม่มีในไฟล์
SLEEP_SECONDS = int(os.getenv("SLEEP_SECONDS", 2))
DATABASE_PATH = os.getenv("DATABASE_PATH")
URLHAUS_API = os.getenv("URLHAUS_API")
PHISHTANK_CSV = os.getenv("PHISHTANK_CSV")
VIRUSTOTAL_ANALYSIS_URL = os.getenv("VIRUSTOTAL_ANALYSIS_URL")
VIRUSTOTAL_URLS_URL = os.getenv("VIRUSTOTAL_URLS_URL")

# ตรวจสอบว่าอ่านค่าได้ถูกต้อง
print(f"Database Path: {DATABASE_PATH}")

import asyncio
import sqlite3
from aiohttp import ClientSession
import time  # Import time for sleep functionality

# Google Web Risk
import json
from google.api_core.exceptions import PermissionDenied
from google.cloud import webrisk_v1
from google.cloud.webrisk_v1 import ThreatType

# Path to the credentials file
# ไฟล์ JSON Credential จาก Google Cloud
credentials_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api-project-744419703652-f520f5308dff.json")

# Set the environment variable for authentication
if os.path.exists(credentials_path):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = credentials_path
else:
    print("Google Credential file not found.")

# Create the client
webrisk_client = webrisk_v1.WebRiskServiceClient()

# VirusTotal
import vt

# กำหนด API Key ของ VirusTotal
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


# เน้นไปที่ phishing: phishtank
import pandas as pd

# เน้นไปที่ malware: urlhaus
import sys
import requests
import aiohttp  # Import aiohttp for asynchronous requests

# Database Trigger Function
def create_database_trigger():
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS check_new_url AFTER INSERT ON urls
            BEGIN
                INSERT INTO urls_to_check (url) VALUES (NEW.target_url); -- เพิ่ม URL ใหม่เข้าคิว
            END;
        """)
        conn.commit()
        print("create_database_trigger(), Database trigger created successfully.")
    except sqlite3.Error as e:
        print(f"create_database_trigger(), Error creating database trigger: {e}")
    finally:
        if conn:
            conn.close()

# Asynchronous Function for Periodic Full Checks
async def periodic_full_check(interval_hours=1):
    while True:
        urls_to_check = get_new_urls_from_database()  # Change function to get new URLs
        if urls_to_check:
            await main(urls_to_check)
        await asyncio.sleep(interval_hours * 3600)  # Sleep for the specified interval


# ฟังก์ชันจาก google_web_risk.py
async def check_google_web_risk(url):
    # print("Google Web Risk: ", end="")
    try:
        # The URL to be checked
        uri = url
        threat_types = ["MALWARE", "SOCIAL_ENGINEERING"]

        # Search the URI
        response = webrisk_client.search_uris(uri=uri, threat_types=threat_types)

        # Check the response
        if response.threat:
            #print(f"The URL {url} is not safe.")
            for threat in response.threat.threat_types:
                #print(f"Threat type: {threat} {ThreatType(threat).name}")
                pass
            return True
        else:
            # print(f"The URL {url} is safe.")
            return False

    except PermissionDenied as exc:
        print("check_google_web_risk(), Permission denied: ", exc)
        print("check_google_web_risk(), Please ensure the service account has the correct permissions and the Web Risk API is enabled.")
    
    return None

async def check_virustotal(url, session):  # Pass the aiohttp session
    # print("VirusTotal: ", end="")
    try:
        # Use the session for the VirusTotal request
        payload = { "url": url }
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY,
            "content-type": "application/x-www-form-urlencoded"
}
        async with session.post(
            VIRUSTOTAL_URLS_URL,
            data = payload,
            headers = headers
        ) as response:
            result = await response.json()
            scan_id = result["data"]["id"]

        # Poll for results (replace 10 with the desired number of retries)
        for _ in range(10):
            async with session.get(
                f"{VIRUSTOTAL_ANALYSIS_URL}{scan_id}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
            ) as response:
                analysis = await response.json()
                if analysis["data"]["attributes"]["status"] == "completed":
                    break
            await asyncio.sleep(5)  # Wait before retrying

        # Check analysis results
        if analysis["data"]["attributes"]["status"] == "completed":
            stats = analysis["data"]["attributes"]["stats"]
            if stats["malicious"] > 0:
                return True  # Malicious
            else:
                return False  # Not malicious
        else:
            return None  # Inconclusive

    except vt.error.APIError as e:
        print(f"VirusTotal Error: {e}")
        return None
    except Exception as e:  # Catch more general exceptions
        print(f"VirusTotal Unexpected error: {e}")
        return None


# ฟังก์ชันจาก check_url_with_phishtank.py
# file จาก phishtank
csv_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), str(PHISHTANK_CSV))
# อ่านไฟล์ CSV
data_phishtank = pd.read_csv(csv_file)

async def check_phishtank(url):
    # print("PhishTank: ", end="")
    try:
        # ตรวจสอบว่ามี URL ในไฟล์ CSV หรือไม่
        if url in data_phishtank['url'].values:
            # ค้นหาข้อมูลของ URL ที่ตรงกัน
            phish_info = data_phishtank[data_phishtank['url'] == url].iloc[0]
            '''
            print(f"The URL {url} is a phishing site.")
            print(f"Phish ID: {phish_info['phish_id']}")
            print(f"Phish detail URL: {phish_info['phish_detail_url']}")
            print(f"Submission time: {phish_info['submission_time']}")
            print(f"Verification time: {phish_info['verification_time']}")
            print(f"Target: {phish_info['target']}")
            '''
            return True
        else:
            # print(f"The URL {url} is not in the PhishTank CSV database.")
            return False
    except FileNotFoundError:
        print(f"PhishTank Error: The file {csv_file} was not found.")
        
    except pd.errors.EmptyDataError:
        print(f"PhishTank Error: The file {csv_file} is empty.")
        
    except Exception as e:
        print(f"PhishTank An unexpected error occurred: {e}")
        

    return None

# ฟังก์ชันจาก urlhaus_lookup_url.py
async def check_urlhaus(url, session):
    # print("URLHaus: ", end="")
    # ตัวอย่างโค้ดที่ใช้ตรวจสอบ URL จาก URLhaus
    try:
        # Construct the HTTP request
        data_urlhaus = {'url' : url}
        # Use aiohttp.ClientSession for asynchronous POST request
        async with session.post(URLHAUS_API, data=data_urlhaus) as response:
        # response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data_urlhaus)
            # Parse the response from the API
            json_response = await response.json()
            if json_response['query_status'] == 'ok':
                # print(json.dumps(json_response, indent=4, sort_keys=False))
                return True
            elif json_response['query_status'] == 'no_results':
                # print("No results")
                return False
            else:
                print("URLHAUS Something went wrong")
                return None
    except (
        aiohttp.ClientError,
        aiohttp.ClientResponseError,
        json.JSONDecodeError,
        KeyError,
    ) as e:
        print(f"Error checking URLhaus: {e}")
        return None
    

# ฟังก์ชันในการอัพเดตฐานข้อมูล
def update_database(url, is_active):
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE urls SET is_active = ? WHERE target_url = ?", (is_active, url))
        conn.commit()
    except sqlite3.Error as e:
        print(f"UPDATE Database error: {e}")
    except Exception as e:
        print(f"update_database(), Unexpected error: {e}")
    finally:
        if conn:
            conn.close()

# ฟังก์ชันในการอ่านข้อมูลจากฐานข้อมูล อ่านเฉพาะที่ยังไม่เคย scan
def get_new_urls_from_database():
    urls = []
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT target_url FROM urls WHERE is_checked IS NULL OR is_checked = 0 ")
        urls = [row[0] for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"get_new_urls_from_database(), Database error: {e}")
    except Exception as e:
        print(f"get_new_urls_from_database(), Unexpected error: {e}")
    finally:
        if conn:
            conn.close()
    return urls

# ฟังก์ชันในการอ่านข้อมูลจาก urls_to_check table ซึ่งข้อมูลจะเพิ่มเข้ามาเมื่อมีการทำ shorten url ใหม่ 
def get_urls_from_database():
    urls = []
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM urls_to_check GROUP BY url")  # อ่าน URL จาก urls_to_check
        urls = [row[0] for row in cursor.fetchall()]

        # ลบ URL ที่อ่านแล้วออกจากคิว
        cursor.execute("DELETE FROM urls_to_check")
        conn.commit()
    except sqlite3.Error as e:
        print(f"get_urls_from_database(), Database error: {e}")
    finally:
        if conn:
            conn.close()
    return urls

def mark_urls_as_checked(urls):
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.executemany("UPDATE urls SET is_checked = 1 WHERE target_url = ?", [(url,) for url in urls])
        conn.commit()
    except sqlite3.Error as e:
        print(f"mark_urls_as_checked(), Database error: {e}")
    except Exception as e:
        print(f"mark_urls_as_checked(), Unexpected error: {e}")
    finally:
        if conn:
            conn.close()

# ฟังก์ชันหลักในการตรวจสอบ URL
async def check_url(url, session):
    '''
    tasks = [
        check_google_web_risk(url),
        check_virustotal(url, session),
        check_phishtank(url),
        check_urlhaus(url, session)
    ]
    results = await asyncio.gather(*tasks)
    '''
    tasks = {
        "Google Web Risk": check_google_web_risk(url),
        "VirusTotal": check_virustotal(url, session),
        "Phishtank": check_phishtank(url),
        "URLhaus": check_urlhaus(url, session)
    }  # Use a dictionary to map functions to their names
    results = await asyncio.gather(*tasks.values())  # Gather results
    is_dangerous = False  # Flag to track if the URL is marked dangerous

    for function_name, result in zip(tasks.keys(), results):
        if any(result is True for result in results):
            if result is True:
                print(f"The URL {url} is dangerous according to {function_name}.")
            elif result is False:
                print(f"No conclusive information for the URL {url} in {function_name}.")
            is_dangerous = True
            
        elif all(result is False for result in results if result is not None):
            print(f"The URL {url} is safe according to {function_name}.")
            # update_database(url, 1)
        else:
            print(f"No conclusive information for the URL {url} in {function_name}.")
        
    # Update database only once after checking all agents
    if is_dangerous:
        update_database(url, -1)

# ฟังก์ชันหลักในการรับ URL และตรวจสอบ
async def main(urls, batch_size=10):
    if isinstance(urls, str):  # Check if urls is a string
        urls = [urls]  # Convert the single string to a list
    async with aiohttp.ClientSession() as session:  # Create session here
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i + batch_size]  # Get a batch of URLs
            tasks = [check_url(url, session) for url in batch]
            await asyncio.gather(*tasks)

            # Delay after each batch
            await asyncio.sleep(SLEEP_SECONDS)  # Adjust delay time as needed
        mark_urls_as_checked(urls)

# ฟังก์ชันหลักในการเรียกใช้ main
def run_main(urls):
    asyncio.run(main(urls)) # Changed to asyncio.run()

# ตัวอย่างการเรียกใช้งาน
if __name__ == "__main__":
    # อ่าน URL จากฐานข้อมูล ทั้งหมด
    # urls_to_check = get_urls_from_database()

    # อ่านเฉพาะ record ที่ยังไม่ได้ scan
    # urls_to_check = get_new_urls_from_database()
    # run_main(urls_to_check)

    # เริ่มการตรวจสอบ URL ใหม่และตรวจสอบเป็นระยะ
    # สร้าง Trigger ใน Database สำหรับตรวจสอบ URL ใหม่
    create_database_trigger()

    async def main_task():
        # เริ่มการตรวจสอบ URL ใหม่และตรวจสอบเป็นระยะ
        async def check_urls_task():
            while True:
                urls_to_check = get_urls_from_database()
                if urls_to_check:
                    await main(urls_to_check)
                await asyncio.sleep(SLEEP_SECONDS)  # รอ 2 วินาทีก่อนตรวจสอบรอบถัดไป (ปรับได้ตามต้องการ)

        loop = asyncio.get_event_loop()
        loop.create_task(periodic_full_check(interval_hours=INTERVAL_HOURS))  # สร้าง task ตรวจสอบทุก 2 ชั่วโมง
        loop.create_task(check_urls_task())  # เริ่ม Task ตรวจสอบ URL ใหม่
        await asyncio.Event().wait()  # รอ event loop ทำงาน

    asyncio.run(main_task())  # เริ่ม event loop และรัน main_task



    
