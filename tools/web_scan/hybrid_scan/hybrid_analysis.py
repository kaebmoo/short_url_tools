import os
import aiohttp
import asyncio
from dotenv import load_dotenv
from datetime import datetime, timezone
from sqlalchemy import text
from models import create_db_session, ScanRecord
from sqlalchemy.exc import SQLAlchemyError

# Load values from .env
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), 'config.env'))

HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")
HYBRID_ANALYSIS_URL = os.getenv("HYBRID_ANALYSIS_URL")
DATABASE_PATH = os.getenv("DATABASE_PATH")
SCAN_RECORDS_DATABASE_PATH = os.getenv("SCAN_RECORDS_DATABASE_PATH")
SLEEP_SECONDS = int(os.getenv("SLEEP_SECONDS", 2))

# Create database sessions
urls_session, _ = create_db_session(DATABASE_PATH)
scan_records_session, _ = create_db_session(SCAN_RECORDS_DATABASE_PATH)

async def check_hybrid_analysis_url(api_key, url_to_check):
    url = HYBRID_ANALYSIS_URL
    headers = {
        'User-Agent': 'Falcon Sandbox',
        'api-key': api_key
    }
    data = {
        'scan_type': 'all',
        'url': url_to_check
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=data) as response:
            if response.status == 200:
                data = await response.json()
                return parse_hybrid_analysis_response(data)
            else:
                print(f"Error: {response.status}, {await response.text()}")
                return None

def parse_hybrid_analysis_response(data):
    results = {
        'submission_type': data.get('submission_type', 'N/A'),
        'id': data.get('id', 'N/A'),
        'url': data.get('url', 'N/A'),
        'sha256': data.get('sha256', 'N/A'),
        'scanners': []
    }

    scanners = data.get('scanners', [])
    for scanner in scanners:
        results['scanners'].append({
            'scanner': scanner.get('name', 'N/A'),
            'status': scanner.get('status', 'N/A'),
            'progress': scanner.get('progress', 'N/A'),
            'percent': scanner.get('percent', 'N/A')
        })

    scanners_v2 = data.get('scanners_v2', {})
    for key, value in scanners_v2.items():
        if value:
            results['scanners'].append({
                'scanner': value.get('name', 'N/A'),
                'status': value.get('status', 'N/A'),
                'progress': value.get('progress', 'N/A'),
                'percent': value.get('percent', 'N/A')
            })

    return results

def get_new_urls_from_database():
    try:
        urls = urls_session.execute(text("SELECT target_url FROM urls WHERE is_checked IS NULL OR is_checked = 0")).fetchall()
        return [url[0] for url in urls]
    except Exception as e:
        print(f"get_new_urls_from_database(), Unexpected error: {e}")
        return []

def update_database(url, is_active):
    try:
        urls_session.execute(text("UPDATE urls SET is_active = :is_active WHERE target_url = :url"), {'is_active': is_active, 'url': url})
        urls_session.commit()
    except Exception as e:
        urls_session.rollback()
        print(f"update_database(), Unexpected error: {e}")

def save_scan_results_to_database(results, url, scan_type, status):
    try:
        existing_record = scan_records_session.query(ScanRecord).filter(ScanRecord.url == url).first()
        if existing_record:
            existing_record.timestamp = datetime.now(timezone.utc)
            existing_record.status = status
            existing_record.scan_type = scan_type
            existing_record.submission_type = results['submission_type']
            existing_record.scan_id = results['id']
            existing_record.sha256 = results['sha256'] 
        else:
            new_scan_record = ScanRecord(
                timestamp=datetime.now(timezone.utc),
                url=url,
                status=status,
                scan_type=scan_type,
                submission_type=results['submission_type'],
                scan_id=results['id'],
                sha256=results['sha256']
            )
            scan_records_session.add(new_scan_record)
            
        scan_records_session.commit()
        print(f"Record for URL {url} {'updated' if existing_record else 'added'} successfully.")
        
    except SQLAlchemyError as e:
        scan_records_session.rollback()
        print(f"Database error in save_scan_results_to_database(): {str(e)}")
    except Exception as e:
        scan_records_session.rollback()
        print(f"Unexpected error in save_scan_results_to_database(): {str(e)}")

def reload_config():
    global HYBRID_ANALYSIS_API_KEY, HYBRID_ANALYSIS_URL, DATABASE_PATH, SLEEP_SECONDS, SCAN_RECORDS_DATABASE_PATH
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), 'config.env'), override=True)
    HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")
    HYBRID_ANALYSIS_URL = os.getenv("HYBRID_ANALYSIS_URL")
    DATABASE_PATH = os.getenv("DATABASE_PATH")
    SCAN_RECORDS_DATABASE_PATH = os.getenv("SCAN_RECORDS_DATABASE_PATH")
    SLEEP_SECONDS = int(os.getenv("SLEEP_SECONDS", 2))

    # Update the sessions if the database paths have changed
    global urls_session, scan_records_session
    urls_session, _ = create_db_session(DATABASE_PATH)
    scan_records_session, _ = create_db_session(SCAN_RECORDS_DATABASE_PATH)
