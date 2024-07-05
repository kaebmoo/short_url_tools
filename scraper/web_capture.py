from RPA.Browser.Selenium import Selenium
from RPA.FileSystem import FileSystem

# สร้างออบเจ็กต์ Selenium และ FileSystem
browser = Selenium()
file_system = FileSystem()

# กำหนด URL ของเว็บเพจและ path ของไฟล์ที่จะเก็บภาพที่ capture
url = "https://bit.ly/3MnWMV7"
output_path = "scraper/output/screenshot_shorturl.png"

try:
    # เปิดเว็บเบราว์เซอร์และเข้าเว็บเพจตาม URL ที่กำหนด
    browser.open_available_browser(url)
    
    # จับภาพหน้าจอของเว็บเพจและบันทึกเป็นไฟล์ใน path ที่กำหนด
    browser.capture_page_screenshot(output_path)
    
    print(f"Screenshot saved to {output_path}")
finally:
    # ปิดเว็บเบราว์เซอร์หลังจากทำการ capture เสร็จ
    browser.close_browser()
