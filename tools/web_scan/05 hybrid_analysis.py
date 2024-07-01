import requests
import json
import os
from dotenv import load_dotenv
import aiohttp
import asyncio

# โหลดค่าจาก .env
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), 'config.env'))
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")
HYBRID_ANALYSIS_URL = os.getenv("HYBRID_ANALYSIS_URL")

# API Key ที่ได้จากการสมัครสมาชิกใน Hybrid Analysis
api_key = HYBRID_ANALYSIS_API_KEY

# URL ของ API Endpoint
url = HYBRID_ANALYSIS_URL

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
                # print(data)
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

    # รวมผลจาก scanners
    scanners = data.get('scanners', [])
    for scanner in scanners:
        results['scanners'].append({
            'scanner': scanner.get('name', 'N/A'),
            'status': scanner.get('status', 'N/A'),
            'progress': scanner.get('progress', 'N/A'),
            'percent': scanner.get('percent', 'N/A')
        })

    # รวมผลจาก scanners_v2
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

async def main():
    api_key = HYBRID_ANALYSIS_API_KEY
    url_to_check = 'http://web-whatsapp-kf.top/'  # ระบุ URL ที่ต้องการตรวจสอบ
    # url_to_check = 'https://tinyurl.com/'
    response = await check_hybrid_analysis_url(api_key, url_to_check)
    
    if response is not None:
        results = parse_hybrid_analysis_response(response)
        print(f"Submission Type: {results['submission_type']}")
        print(f"ID: {results['id']}")
        print(f"URL: {url_to_check}")
        print(f"SHA256: {results['sha256']}")
        print("Scanners data:", results['scanners'])  # พิมพ์ข้อมูล scanners เพื่อตรวจสอบ
        print("Scan Results:")
        '''for result in results['scanners']:
            if result['percent'] == 'N/A' or result['percent'] is None:
                print(f"Scanner: {result['scanner']}, Status: {result['status']}, Progress: {result['progress']}%, Percent: {result['percent']}")
            else:
                print(f"Scanner: {result['scanner']}, Status: {result['status']}, Progress: {result['progress']}%, Percent: {result['percent']}%")
'''
        for result in results['scanners']:
            percent = f"{result['percent']}%" if result['percent'] != 'N/A' and result['percent'] is not None else "N/A"
            print(f"Scanner: {result['scanner']}, Status: {result['status']}, Progress: {result['progress']}%, Percent: {percent}")

if __name__ == '__main__':
    asyncio.run(main())

