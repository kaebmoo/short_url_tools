
### อธิบายโค้ด:

1. **ติดตั้งไลบรารี `vt`**:
ไลบรารี `vt-py` ถูกใช้เพื่อเชื่อมต่อและใช้งาน VirusTotal API

2. **การตั้งค่า API Key**:
กำหนด API Key จาก VirusTotal เพื่อให้สามารถใช้งาน API ได้

3. **ฟังก์ชัน `check_url_with_virustotal`**:
- สร้าง client สำหรับ VirusTotal API โดยใช้ API Key
- ใช้เมธอด `scan_url` เพื่อสแกน URL ที่ต้องการตรวจสอบ
- ใช้เมธอด `get_object` เพื่อตรวจสอบสถานะการสแกน และรับผลลัพธ์การสแกน URL
- แสดงผลลัพธ์การสแกน URL ว่าเป็น `harmless`, `malicious`, `suspicious` หรือ `undetected`
- จัดการข้อยกเว้น `APIError` หากเกิดข้อผิดพลาดจาก API
- ปิด client เมื่อเสร็จสิ้นการใช้งาน

4. **ทดสอบการใช้งาน**:
- ระบุ URL ที่ต้องการตรวจสอบ และเรียกใช้ฟังก์ชัน `check_url_with_virustotal`

ด้วยโค้ดนี้ คุณจะสามารถตรวจสอบ URL ว่าเป็นอันตรายหรือไม่โดยใช้ VirusTotal API ได้อย่างง่ายดาย
