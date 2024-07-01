import vt
import os
import configparser

config = configparser.ConfigParser(interpolation=None)
config.read("/Users/seal/Documents/GitHub/short_url_tools/tools/web_scan/config.ini")

# กำหนด API Key ของ VirusTotal
API_KEY = config["CONFIG"]["API_KEY"]


def check_url_with_virustotal(url):
    # สร้าง client สำหรับ VirusTotal API
    client = vt.Client(API_KEY)

    try:
        # สแกน URL ด้วย VirusTotal API
        analysis = client.scan_url(url)
        print(f"Scan ID: {analysis.id}")

        # รอการสแกนให้เสร็จสมบูรณ์
        analysis = client.get_object("/analyses/{}", analysis.id)

        # ตรวจสอบผลการสแกน
        if analysis.status == "completed":
            # แสดงผลลัพธ์การสแกน
            url_report = client.get_object("/urls/{}", vt.url_id(url))
            print(f"URL: {url}")
            print(f"Harmless: {url_report.last_analysis_stats['harmless']}")
            print(f"Malicious: {url_report.last_analysis_stats['malicious']}")
            print(f"Suspicious: {url_report.last_analysis_stats['suspicious']}")
            print(f"Undetected: {url_report.last_analysis_stats['undetected']}")
            malicious_count = url_report.last_analysis_stats['malicious']
            if malicious_count > 0:
                return True
            else:
                return False
            
        else:
            print("Analysis is still in progress. Please check back later.")
            return None
        

    except vt.error.APIError as e:
        print(f"Error: {e}")
        return None
    finally:
        # ปิด client เมื่อเสร็จสิ้นการใช้งาน
        client.close()

url_to_check = "http://web-whatsapp-kf.top/"
check_url_with_virustotal("https://www.onlinegantt.com/")