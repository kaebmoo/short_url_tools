นี่คือโค้ดที่มีการจัดการ Exception เพิ่มเติมเพื่อให้โปรแกรมมีความเสถียรมากขึ้น:

```python
#!/usr/bin/python3
import sys
import requests
import json

def query_urlhaus(url):
    try:
        # Construct the HTTP request
        data = {'url': url}
        response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data)

        # Handle potential HTTP errors
        response.raise_for_status()  # Raise an exception for 4xx or 5xx errors

        # Parse the response from the API
        json_response = response.json()
        if json_response['query_status'] == 'ok':
            print(json.dumps(json_response, indent=4, sort_keys=False))
            return True
        elif json_response['query_status'] == 'no_results':
            print("No results")
            return None
        else:
            print("Something went wrong")
            return False

    except requests.exceptions.RequestException as e:
        print(f"Error communicating with URLhaus API: {e}")
        return False
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON response: {e}")
        return False
    except KeyError as e:
        print(f"Unexpected response format from URLhaus API: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        query_urlhaus(sys.argv[1])
    else:
        print("Looking up a URL on the URLhaus bulk API")
        print("Usage: python3 lookup_url.py <URL>")
```

**การปรับปรุง:**

1. **Try-Except Blocks:**  มีการเพิ่ม `try-except` blocks เพื่อดักจับข้อผิดพลาดที่อาจเกิดขึ้นได้หลายอย่าง:
   * `requests.exceptions.RequestException`: เกิดขึ้นเมื่อมีปัญหาในการสื่อสารกับ API (เช่น ไม่มีการเชื่อมต่ออินเทอร์เน็ต)
   * `json.JSONDecodeError`: เกิดขึ้นเมื่อไม่สามารถแปลงข้อมูลที่ได้รับจาก API เป็นรูปแบบ JSON ได้
   * `KeyError`: เกิดขึ้นเมื่อข้อมูลที่ได้รับจาก API ไม่มี key ที่คาดไว้ (เช่น `query_status`)

2. **Error Handling:**  ภายใน `except` blocks จะมีการพิมพ์ข้อความแจ้งข้อผิดพลาดที่เกิดขึ้น และฟังก์ชันจะคืนค่า `False` เพื่อระบุว่าการค้นหาไม่สำเร็จ
3. **raise_for_status() Method:** Added to the `response` object to check for HTTP errors directly. If there is a client error (4xx) or server error (5xx), this method will raise a `requests.exceptions.HTTPError`. This allows us to handle specific HTTP errors like 404 Not Found or 503 Service Unavailable if needed.

4. **Main Guard:** The script will now only run the `query_urlhaus` function when executed as a script, rather than when it is imported as a module.


**การใช้งาน:**

* **เรียกใช้จาก terminal:**
   ```bash
   python3 lookup_url.py http://livetrack.in/EmployeeMasterImages/qace.jpg
   ```
   หรือ
   ```bash
   python3 lookup_url.py https://www.ntplc.co.th
   ```


ด้วยการปรับปรุงเหล่านี้ โปรแกรมของคุณจะสามารถรับมือกับข้อผิดพลาดต่างๆ ได้ดีขึ้น และยังคงทำงานได้อย่างถูกต้องแม้ว่าจะเกิดปัญหาบางอย่างขึ้นก็ตาม