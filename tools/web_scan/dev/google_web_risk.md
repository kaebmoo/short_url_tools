### `google_web_risk.py`

```python
import os
import json

# หาตำแหน่งของ directory ที่โปรแกรมกำลังรันอยู่
current_dir = os.path.dirname(os.path.abspath(__file__))

# ตั้งค่าเส้นทางไปยังไฟล์ JSON Credentials ใน directory เดียวกัน
credentials_path = os.path.join(current_dir, "credential-file.json")

# ตรวจสอบว่าไฟล์ Credentials มีอยู่หรือไม่
if os.path.exists(credentials_path):
    # ตั้งค่าตัวแปรสภาพแวดล้อม
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = credentials_path

    # อ่านไฟล์ JSON เพื่อให้แน่ใจว่าอ่านได้ถูกต้อง
    with open(credentials_path, 'r') as file:
        credentials_data = json.load(file)
        print("Credentials loaded successfully.")

    # ฟังก์ชันสำหรับตรวจสอบ URL
    from google.cloud import webrisk_v1

    def check_url_safety(url):
        client = webrisk_v1.WebRiskServiceClient()
        uri = url
        threat_types = ["MALWARE", "SOCIAL_ENGINEERING"]
        response = client.search_uris(uri=uri, threat_types=threat_types)
        if response.threat:
            print(f"The URL {url} is not safe.")
            for threat in response.threat.threat_types:
                print(f"Threat type: {threat}")
        else:
            print(f"The URL {url} is safe.")

    # ตัวอย่างการใช้งาน
    url_to_check = "http://example.com"
    check_url_safety(url_to_check)
else:
    print("Credential file not found.")
```

### อธิบายโค้ดที่อัปเดต:
1. **นำเข้าไลบรารีที่จำเป็น**: นำเข้าโมดูล `os` และ `json` สำหรับการจัดการกับไฟล์ JSON และตัวแปรสภาพแวดล้อม
2. **หา directory ของโปรแกรม**: ใช้ `os.path.dirname` และ `os.path.abspath(__file__)` เพื่อหา directory ที่ไฟล์โปรแกรมกำลังรันอยู่
3. **ตั้งค่า `credentials_path`**: ใช้ `os.path.join` เพื่อสร้างเส้นทางไปยังไฟล์ JSON Credentials ที่อยู่ใน directory เดียวกับโปรแกรม
4. **ตรวจสอบและตั้งค่าตัวแปรสภาพแวดล้อม**: ตรวจสอบว่าไฟล์ JSON Credentials มีอยู่หรือไม่ และตั้งค่าตัวแปรสภาพแวดล้อม `GOOGLE_APPLICATION_CREDENTIALS` ให้ชี้ไปยังไฟล์ JSON นั้น
5. **อ่านไฟล์ JSON**: เปิดและโหลดไฟล์ JSON เพื่อให้แน่ใจว่าอ่านได้ถูกต้อง
6. **ฟังก์ชัน `check_url_safety`**: ฟังก์ชันสำหรับตรวจสอบ URL โดยใช้ Google Web Risk API โดยระบุประเภทภัยคุกคามเป็น `MALWARE` และ `SOCIAL_ENGINEERING`
7. **ทดสอบการใช้งาน**: ตรวจสอบ URL ตัวอย่างโดยเรียกใช้ฟังก์ชัน `check_url_safety`

