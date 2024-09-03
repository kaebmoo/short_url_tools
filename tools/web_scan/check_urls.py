#tools/web_scan/check_urls.py
import os
from dotenv import load_dotenv

import asyncio
import sqlite3
from aiohttp import ClientSession
import time  # Import time for sleep functionality

# Google Web Risk
import json
from google.api_core.exceptions import PermissionDenied
from google.cloud import webrisk_v1
from google.cloud.webrisk_v1 import ThreatType

from sqlalchemy import create_engine, Boolean, Column, Integer, String, DateTime, func, Enum, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import declarative_base

# VirusTotal
import vt

# เน้นไปที่ phishing: phishtank
import pandas as pd

# เน้นไปที่ malware: urlhaus
import sys
import requests
import aiohttp  # Import aiohttp for asynchronous requests

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

Base = declarative_base() 

# กำหนด class scan_records ภายในโปรแกรม
class scan_records(Base):
    __tablename__ = "scan_records"  # เก็บข้อมูลการ scan 
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())  
    url = Column(String)
    status = Column(
        Enum(
            '0', 
            'Dangerous', 
            'Safe', 
            'In queue for scanning', 
            '-1', 
            '1', 
            'No conclusive information', 
            'No classification', 
            name='status_enum'  # กำหนดชื่อให้กับ ENUM type
        ),
        default='0'
    )
    scan_type = Column(String)
    result = Column(String)
    submission_type = Column(String)
    scan_id = Column(String)
    sha256 = Column(String)

class URL(Base):
    __tablename__ = "urls"  # ชื่อ table ใน sqlite

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)                  # primary key
    key = Column(String, unique=True, index=True)           # shorten 
    secret_key = Column(String, unique=True, index=True)    # a secret key to the user to manage their shortened URL and see statistics.
    target_url = Column(String, index=True)                 # to store the URL strings for which your app provides shortened URLs.
    is_active = Column(Boolean, default=True)               # false is delete
    clicks = Column(Integer, default=0)     # this field will increase the integer each time someone clicks the shortened link.
    api_key = Column(String, index=True)  # เพิ่มฟิลด์นี้เพื่อเก็บ API key
    created_at = Column(DateTime(timezone=True), server_default=func.now())  # เพิ่มฟิลด์วันที่และเวลาในการสร้าง
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())       # เพิ่มฟิลด์วันที่และเวลาในการอัปเดต
    is_checked = Column(Boolean, default=False, nullable=True)
    status = Column(String) # เก็บสถานะว่าเป็น url อันตรายหรือไม่ เช่น safe, danger, no info
    title = Column(String(255)) # title page
    favicon_url = Column(String(255)) # favicon url

# กำหนด class URLsToCheck สำหรับ urls_to_check table
class URLsToCheck(Base):
    __tablename__ = 'urls_to_check'
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)    
    url = Column(String)

# Database setup
engine = create_engine(DATABASE_PATH, echo=False) 
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

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

# กำหนด API Key ของ VirusTotal
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


# Database Trigger Function
def create_database_trigger(db_type):
    if db_type == "sqlite":
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS check_new_url AFTER INSERT ON urls
                BEGIN
                    INSERT INTO urls_to_check (url) VALUES (NEW.target_url);
                END;
            """)
            conn.commit()
            print("create_database_trigger(), Database trigger created successfully for SQLite.")
        except sqlite3.Error as e:
            print(f"create_database_trigger(), Error creating database trigger: {e}")
        finally:
            if conn:
                conn.close()

    elif db_type == "postgresql":
        try:
            with engine.connect() as conn:
                # ลบ Trigger เดิมถ้ามีอยู่แล้ว
                conn.execute(text("DROP TRIGGER IF EXISTS check_new_url ON urls;"))
                conn.execute(text("DROP FUNCTION IF EXISTS insert_url_to_check();"))

                # สร้างฟังก์ชันใหม่
                conn.execute(text("""
                    CREATE OR REPLACE FUNCTION insert_url_to_check()
                    RETURNS TRIGGER AS $$
                    BEGIN
                        INSERT INTO urls_to_check (url) VALUES (NEW.target_url);
                        RETURN NEW;
                    END;
                    $$ LANGUAGE plpgsql;
                """))

                # สร้าง Trigger ใหม่
                conn.execute(text("""
                    CREATE TRIGGER check_new_url
                    AFTER INSERT ON urls
                    FOR EACH ROW
                    EXECUTE FUNCTION insert_url_to_check();
                """))
            print("Trigger and function created successfully in PostgreSQL.")
        except Exception as e:
            print(f"create_database_trigger(), Error creating database trigger for PostgreSQL: {e}")



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
    """Asynchronously checks the reputation of a URL using the VirusTotal API.

    Args:
        url: The URL to check.
        session: An aiohttp ClientSession for making asynchronous requests.

    Returns:
        True if the URL is considered malicious, False if safe, or None if the analysis is inconclusive.
    """
    try:
        # Use the session for the VirusTotal request
        payload = { "url": url }
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY,
            "content-type": "application/x-www-form-urlencoded"
}
        async with session.post(VIRUSTOTAL_URLS_URL, data = payload, headers = headers) as response:
            result = await response.json()  # Get the JSON response
            scan_id = result["data"]["id"]  # Extract the scan ID

        # Poll for results (replace 10 with the desired number of retries)
        for _ in range(10):
            async with session.get(f"{VIRUSTOTAL_ANALYSIS_URL}{scan_id}", headers={"x-apikey": VIRUSTOTAL_API_KEY}) as response:
                analysis = await response.json()
                if analysis["data"]["attributes"]["status"] == "completed":
                    break   # Stop polling if analysis is complete
            await asyncio.sleep(5)  # Wait for 5 seconds before retrying

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
def update_database(url, status):
    session = Session()
    try:
        session.query(URL).filter(URL.target_url == url).update({URL.status: status})
        session.commit()
    except Exception as e:
        session.rollback()
        print(f"update_database(), Unexpected error: {e}")
    finally:
        session.close()

# ฟังก์ชันในการอ่านข้อมูลจากฐานข้อมูล อ่านเฉพาะที่ยังไม่เคย scan
def get_new_urls_from_database():
    session = Session()
    try:
        urls = session.query(URL.target_url).filter(
            (URL.is_checked == None) | (URL.is_checked == False)
        ).all()
        return [url[0] for url in urls]
    except Exception as e:
        print(f"get_new_urls_from_database(), Unexpected error: {e}")
    finally:
        session.close()

# ฟังก์ชันในการอ่านข้อมูลจาก urls_to_check table ซึ่งข้อมูลจะเพิ่มเข้ามาเมื่อมีการทำ shorten url ใหม่ 
def get_urls_from_database():
    session = Session()
    urls = []
    try:
        # อ่าน URL จาก urls_to_check โดยการใช้ SQLAlchemy query
        urls = session.query(URLsToCheck.url).distinct().all()
        urls = [url[0] for url in urls]

        # ลบ URL ที่อ่านแล้วออกจากคิว
        session.query(URLsToCheck).delete()
        session.commit()
    except Exception as e:
        session.rollback()
        print(f"get_urls_from_database(), Database error: {e}")
    finally:
        session.close()
    return urls

def mark_urls_as_checked(urls):
    session = Session()
    try:
        session.query(URL).filter(URL.target_url.in_(urls)).update({URL.is_checked: True}, synchronize_session=False)
        session.commit()
    except Exception as e:
        session.rollback()
        print(f"mark_urls_as_checked(), Database error: {e}")
    finally:
        session.close()

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

    db_session = Session()  # Create a database session

    for function_name, result in zip(tasks.keys(), results):
        # Determine the result string
        if result is True:
            result_str = "DANGER"
            is_dangerous = True
            print(f"The URL {url} is dangerous according to {function_name}.")
        elif result is False:
            result_str = "SAFE"
            print(f"The URL {url} is safe according to {function_name}.")
        else:
            result_str = "INCONCLUSIVE"
            print(f"No conclusive information for the URL {url} in {function_name}.")

        # ตรวจสอบว่ามี record ของ URL นี้และ scan_type นี้อยู่แล้วหรือไม่
        existing_record = db_session.query(scan_records).filter_by(url=url, scan_type=function_name).first()

        # ถ้ามี record อยู่แล้ว ให้อัพเดตเฉพาะ timestamp และ result
        if existing_record:
            existing_record.timestamp = func.now()
            existing_record.result = result_str 
        else:  # ถ้ายังไม่มี record ให้สร้างใหม่
            # Create a new scan record
            new_record = scan_records(
                url=url,
                scan_type=function_name,
                result=result_str  # You can add more details here if needed
            )
            db_session.add(new_record)

    db_session.commit()  # Commit the changes to the database
    db_session.close()

    # Update the main 'urls' table only once
    if is_dangerous:
        update_database(url, "DANGER")
    else:  # Update to SAFE only if all results are False or None
        if all(result is False or result is None for result in results):
            update_database(url, "SAFE")

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
    if DATABASE_PATH.startswith("sqlite"):
        create_database_trigger("sqlite")
    elif DATABASE_PATH.startswith("postgresql"):
        create_database_trigger("postgresql")

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



    
