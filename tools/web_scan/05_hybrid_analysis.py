# tools/web_scan/05_hybrid_analysis.py
# read data from database
import os
import sqlite3
import aiohttp
import asyncio
import json
import pandas as pd
from dotenv import load_dotenv

# โหลดค่าจาก .env
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), 'config.env'))
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")
HYBRID_ANALYSIS_URL = os.getenv("HYBRID_ANALYSIS_URL")
DATABASE_PATH = os.getenv("DATABASE_PATH")
SLEEP_SECONDS = int(os.getenv("SLEEP_SECONDS", 2))

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
    urls = []
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT target_url FROM urls WHERE is_checked IS NULL OR is_checked = 0")
        urls = [row[0] for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"get_new_urls_from_database(), Database error: {e}")
    except Exception as e:
        print(f"get_new_urls_from_database(), Unexpected error: {e}")
    finally:
        if conn:
            conn.close()
    return urls

def update_database(url, is_active):
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE urls SET is_active = ? WHERE target_url = ?", (is_active, url))
        conn.commit()
    except sqlite3.Error as e:
        print(f"update_database(), Database error: {e}")
    except Exception as e:
        print(f"update_database(), Unexpected error: {e}")
    finally:
        if conn:
            conn.close()

async def check_url(url):
    response = await check_hybrid_analysis_url(HYBRID_ANALYSIS_API_KEY, url)
    if response is not None:
        in_queue = any(scanner['status'] == 'in-queue' for scanner in response['scanners'])
        no_classification = any(scanner['status'] == 'no-classification' for scanner in response['scanners'])
        
        if in_queue:
            print(f"URL: {url} is still in queue for scanning.")
        elif no_classification:
            print(f"URL: {url} is no classification.")
        else:
            is_dangerous = any(scanner['status'] == 'malicious' for scanner in response['scanners'])
            update_database(url, -1 if is_dangerous else 1)
            print(f"URL: {url} is {'dangerous' if is_dangerous else 'safe'}")
    else:
        print(f"No conclusive information for URL: {url}")

async def main():
    urls = get_new_urls_from_database()
    if urls:
        tasks = [check_url(url) for url in urls]
        await asyncio.gather(*tasks)
        await asyncio.sleep(SLEEP_SECONDS)

if __name__ == '__main__':
    asyncio.run(main())
