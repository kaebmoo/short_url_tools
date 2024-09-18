import asyncio
import os
from datetime import datetime, timezone

import aiohttp
from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from models import ScanRecord, create_db_session

# Load values from .env
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), 'config.env'))

HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")
HYBRID_ANALYSIS_URL = os.getenv("HYBRID_ANALYSIS_URL")
DATABASE_PATH = os.getenv("DATABASE_PATH")
SCAN_RECORDS_DATABASE_PATH = os.getenv("SCAN_RECORDS_DATABASE_PATH")
SLEEP_SECONDS = int(os.getenv("SLEEP_SECONDS", "2"))

# Create database sessions
urls_session, _ = create_db_session(DATABASE_PATH)
scan_records_session, _ = create_db_session(SCAN_RECORDS_DATABASE_PATH)

async def check_hybrid_analysis_url(api_key, url_to_check):
    """
    Submits a URL to the Hybrid Analysis API for scanning.

    Args:
        api_key (str): The API key for Hybrid Analysis.
        url_to_check (str): The URL to be submitted for scanning.

    Returns:
        dict: The parsed response data containing scan results or an error message.
    """
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
        try:
            async with session.post(url, headers=headers, data=data) as response:
                if response.status == 200:
                    data = await response.json()
                    # Extract the scan_id and sha256
                    scan_id = data.get('id')
                    sha256 = data.get('sha256')
                    if scan_id and sha256:
                        # Save the scan to the database with the status "In queue for scanning"
                        save_scan_results_to_database(data, url_to_check, 'hybrid-analysis', "In queue for scanning")
                        print(f"Submitted URL {url_to_check} for scanning, Scan ID: {scan_id}")
                    else:
                        print(f"Error: Scan ID or SHA256 missing in response for URL {url_to_check}")
                    return data
                elif response.status == 400:
                    # Handle the specific 400 error case
                    error_message = await response.json()
                    if error_message.get('message') == 'Not allowed URL submitted':
                        return {'error': 'Not allowed URL submitted'}
                    else:
                        return {'error': f"Error 400: {error_message.get('message')}"}
                else:
                    print(f"Error: {response.status}, {await response.text()}")
                    return None
        except aiohttp.ClientError as e:
            print(f"Network error during check_hybrid_analysis_url: {str(e)}")
            return None

async def handle_in_queue_scan(scan_id, sha256, url):
    """
    Handles the case where the scan is still in the queue by periodically checking the scan status.

    Args:
        scan_id (str): The scan ID to check.
        sha256 (str): The SHA256 hash of the URL.
        url (str): The URL being scanned.

    Returns:
        str: The final status of the scan.
    """
    max_attempts = 10
    attempt = 0
    while attempt < max_attempts:
        attempt += 1
        await asyncio.sleep(10)  # Wait for 10 seconds before re-checking
        scan_status = await check_quick_scan_status(scan_id)
        if scan_status and scan_status.get('finished'):
            # Fetch the final results using the overview endpoint
            final_results = await get_hybrid_analysis_summary(HYBRID_ANALYSIS_API_KEY, sha256)
            if final_results:
                return final_results.get('verdict', 'No conclusive information')
            break
        else:
            print(f"Scan for {url} still in progress, checking again...")

    return "Scan did not complete within expected time"

async def check_quick_scan_status(scan_id):
    """
    Checks the status of a quick scan using its scan ID.

    Args:
        scan_id (str): The scan ID to check.

    Returns:
        dict: The scan status information if available.
    """
    url = f"https://www.hybrid-analysis.com/api/v2/quick-scan/{scan_id}"
    headers = {
        'User-Agent': 'Falcon Sandbox',
        'api-key': HYBRID_ANALYSIS_API_KEY
    }
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    print(f"Error checking quick scan status: {response.status}, {await response.text()}")
                    return None
        except aiohttp.ClientError as e:
            print(f"Network error during check_quick_scan_status: {str(e)}")
            return None

def check_and_update_pending_scan(url):
    """
    Checks the database for any scans that are still "In queue for scanning" and updates their status if completed.

    Args:
        url (str): The URL to be checked in the database.

    Returns:
        str: The status of the scan if found and updated, otherwise None.
    """
    try:
        # Query for existing scan records with "In queue for scanning" status
        existing_record = scan_records_session.query(ScanRecord).filter(
            ScanRecord.url == url,
            ScanRecord.status == 'In queue for scanning'
        ).first()
        
        if existing_record:
            # Check the scan status using the stored scan_id
            scan_id = existing_record.scan_id
            sha256 = existing_record.sha256
            if scan_id:
                scan_status = asyncio.run(check_quick_scan_status(scan_id))
                if scan_status and scan_status.get('finished'):
                    # Fetch the final results using the overview endpoint
                    final_results = asyncio.run(get_hybrid_analysis_summary(HYBRID_ANALYSIS_API_KEY, sha256))
                    if final_results:
                        verdict = final_results.get('verdict', 'No conclusive information')
                        existing_record.status = verdict
                        existing_record.timestamp = datetime.now(timezone.utc)
                        existing_record.threat_score = final_results.get('threat_score')
                        existing_record.verdict = final_results.get('verdict')
                        scan_records_session.commit()
                        print(f"Updated existing record for {url} with new scan results.")
                        return verdict
            return "In queue for scanning"  # If still in queue
        else:
            return None
    except Exception as e:
        scan_records_session.rollback()
        print(f"Unexpected error in check_and_update_pending_scan(): {str(e)}")
        return None

async def check_scan_state(api_key, sha256):
    """
    Checks the scan state of a URL using its SHA256 hash.

    Args:
        api_key (str): The API key for Hybrid Analysis.
        sha256 (str): The SHA256 hash of the scanned URL.

    Returns:
        dict: The scan state information if available.
    """
    url = f"https://www.hybrid-analysis.com/api/v2/report/{sha256}/state"
    headers = {
        'User-Agent': 'Falcon Sandbox',
        'api-key': api_key
    }
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    print(f"Error fetching scan state: {response.status}, {await response.text()}")
                    return None
        except aiohttp.ClientError as e:
            print(f"Network error during check_scan_state: {str(e)}")
            return None

async def get_hybrid_analysis_summary(api_key, sha256):
    """
    Retrieves the detailed summary of a scan using the SHA256 hash.

    Args:
        api_key (str): The API key for Hybrid Analysis.
        sha256 (str): The SHA256 hash of the scanned URL.

    Returns:
        dict: The detailed summary of the scan if available.
    """
    url = f"https://www.hybrid-analysis.com/api/v2/overview/{sha256}/summary"
    headers = {
        'User-Agent': 'Falcon Sandbox',
        'api-key': api_key
    }
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    print(f"Error fetching summary: {response.status}, {await response.text()}")
                    return None
        except aiohttp.ClientError as e:
            print(f"Network error during get_hybrid_analysis_summary: {str(e)}")
            return None

def parse_hybrid_analysis_response(data, summary=None):
    """
    Parses the response from Hybrid Analysis API into a structured format.

    Args:
        data (dict): The initial scan response data.
        summary (dict, optional): The detailed summary of the scan.

    Returns:
        dict: A dictionary containing the parsed scan results.
    """
    results = {
        'submission_type': data.get('submission_type', 'N/A'),
        'id': data.get('id', 'N/A'),
        'url': data.get('url', 'N/A'),
        'sha256': data.get('sha256', 'N/A'),
        'scanners': [],
        'threat_score': summary.get('threat_score') if summary else 'N/A',
        'verdict': summary.get('verdict') if summary else 'N/A'
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
    """
    Retrieves URLs from the database that have not been checked yet.

    Returns:
        list: A list of URLs that need to be scanned.
    """
    try:
        urls = urls_session.execute(text("SELECT target_url FROM urls WHERE is_checked IS NULL OR is_checked = 0")).fetchall()
        return [url[0] for url in urls]
    except Exception as e:
        print(f"get_new_urls_from_database(), Unexpected error: {e}")
        return []

def update_database(url, is_active):
    """
    Updates the database with the scan status of a URL.

    Args:
        url (str): The URL to update in the database.
        is_active (int): The status indicating if the URL is active (-1 for dangerous, 1 for safe).
    """
    try:
        urls_session.execute(text("UPDATE urls SET is_active = :is_active WHERE target_url = :url"), {'is_active': is_active, 'url': url})
        urls_session.commit()
    except Exception as e:
        urls_session.rollback()
        print(f"update_database(), Unexpected error: {e}")

def save_scan_results_to_database(results, url, scan_type, status):
    """
    Saves or updates scan results in the database.

    Args:
        results (dict): The scan results to be saved.
        url (str): The URL that was scanned.
        scan_type (str): The type of scan conducted.
        status (str): The status of the scan result.
    """
    try:
        # Check if results is None before accessing its elements
        if results is None:
            print(f"No data returned for URL: {url}")
            return

        # Convert timestamp to a proper datetime object
        timestamp = datetime.now(timezone.utc)

        existing_record = scan_records_session.query(ScanRecord).filter(ScanRecord.url == url).first()
        if existing_record:
            existing_record.timestamp = timestamp
            existing_record.status = status
            existing_record.scan_type = scan_type
            existing_record.submission_type = results.get('submission_type', 'N/A')
            existing_record.scan_id = results.get('id', 'N/A')
            existing_record.sha256 = results.get('sha256', 'N/A')
            existing_record.threat_score = results.get('threat_score')
            existing_record.verdict = results.get('verdict')
        else:
            new_scan_record = ScanRecord(
                timestamp=timestamp,  # Use the correct datetime object
                url=url,
                status=status,
                scan_type=scan_type,
                submission_type=results.get('submission_type', 'N/A'),
                scan_id=results.get('id', 'N/A'),
                sha256=results.get('sha256', 'N/A'),
                threat_score=results.get('threat_score'),
                verdict=results.get('verdict')
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

async def check_pending_scans():
    """
    Periodically checks the status of all scans that are in the queue and updates the database if completed.
    """
    while True:
        try:
            # Get all pending scans from the database
            pending_scans = scan_records_session.query(ScanRecord).filter(
                ScanRecord.status == 'In queue for scanning'
            ).all()

            for scan in pending_scans:
                scan_id = scan.scan_id
                sha256 = scan.sha256

                # Check the current status of the scan
                scan_status = await check_quick_scan_status(scan_id)
                if scan_status and scan_status.get('finished'):
                    # Fetch the final results using the overview endpoint
                    final_results = await get_hybrid_analysis_summary(HYBRID_ANALYSIS_API_KEY, sha256)
                    if final_results:
                        verdict = final_results.get('verdict', 'No conclusive information')
                        scan.status = verdict
                        scan.timestamp = datetime.now(timezone.utc)
                        scan.threat_score = final_results.get('threat_score')
                        scan.verdict = final_results.get('verdict')
                        scan_records_session.commit()
                        print(f"Updated scan record for {scan.url} with new results.")
                    else:
                        print(f"No detailed results available yet for {scan.url}")
                else:
                    print(f"Scan for {scan.url} still in progress or not found.")
        
        except Exception as e:
            scan_records_session.rollback()
            print(f"Error while checking pending scans: {e}")
        
        # Sleep for a specified interval before checking again
        await asyncio.sleep(300)  # Check every 5 minutes

def reload_config():
    """
    Reloads configuration values from the .env file and updates database sessions.
    """
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
