# เน้นไปที่ phishing 
import pandas as pd

def check_url_from_csv(url, csv_file='tools/web_scan/verified_online.csv'):
    try:
        # อ่านไฟล์ CSV
        data = pd.read_csv(csv_file)
        
        # ตรวจสอบว่ามี URL ในไฟล์ CSV หรือไม่
        if url in data['url'].values:
            # ค้นหาข้อมูลของ URL ที่ตรงกัน
            phish_info = data[data['url'] == url].iloc[0]
            print(f"The URL {url} is a phishing site.")
            print(f"Phish ID: {phish_info['phish_id']}")
            print(f"Phish detail URL: {phish_info['phish_detail_url']}")
            print(f"Submission time: {phish_info['submission_time']}")
            print(f"Verification time: {phish_info['verification_time']}")
            print(f"Target: {phish_info['target']}")
            return True
        else:
            print(f"The URL {url} is not in the PhishTank CSV database.")
            return False
    except FileNotFoundError:
        print(f"Error: The file {csv_file} was not found.")
        
    except pd.errors.EmptyDataError:
        print(f"Error: The file {csv_file} is empty.")
        
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        

    return None

url_to_check = "https://tinyurl.com"
check_url_from_csv(url_to_check)
# check_url_from_csv("http://ustert.net/Alphine/")