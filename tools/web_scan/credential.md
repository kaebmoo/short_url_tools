การสร้างไฟล์ JSON ที่มีข้อมูล Credential ของ Google Cloud สามารถทำได้ตามขั้นตอนดังนี้:

### ขั้นตอนการสร้างไฟล์ JSON Credential จาก Google Cloud Console:

1. **เข้าสู่ Google Cloud Console**:
   ไปที่ [Google Cloud Console](https://console.cloud.google.com/) และลงชื่อเข้าใช้ด้วยบัญชี Google ของคุณ

2. **สร้างโปรเจคใหม่หรือเลือกโปรเจคที่มีอยู่**:
   - หากคุณยังไม่มีโปรเจค ให้สร้างโปรเจคใหม่โดยคลิกที่ "Select a project" แล้วคลิก "New Project"
   - ตั้งชื่อโปรเจคและคลิก "Create"

3. **เปิดใช้งาน API**:
   - ไปที่ "APIs & Services" > "Library"
   - ค้นหา "Web Risk API" แล้วคลิก "Enable" เพื่อเปิดใช้งาน API นี้

4. **สร้าง Credentials**:
   - ไปที่ "APIs & Services" > "Credentials"
   - คลิกที่ "Create Credentials" แล้วเลือก "Service account"
   - ตั้งชื่อสำหรับ Service account และคลิก "Create"
   - ในส่วน "Service account permissions" ให้เลือก "Owner" หรือบทบาทที่ต้องการ แล้วคลิก "Continue"
   - ในส่วน "Grant users access to this service account" สามารถข้ามขั้นตอนนี้ได้โดยคลิก "Done"

5. **ดาวน์โหลดไฟล์ JSON Credentials**:
   - เมื่อสร้าง Service account เสร็จแล้ว จะกลับมาที่หน้า "Credentials"
   - ในรายการ Service accounts ให้คลิกที่ชื่อบัญชีที่คุณสร้างขึ้น
   - คลิกที่แท็บ "Keys" แล้วคลิก "Add Key" > "Create new key"
   - เลือก "JSON" และคลิก "Create"
   - ไฟล์ JSON ที่มีข้อมูล Credential จะถูกดาวน์โหลดลงในเครื่องของคุณ

6. **ตั้งค่า Environment Variable**:
   - ตั้งค่าตัวแปรสภาพแวดล้อม `GOOGLE_APPLICATION_CREDENTIALS` ให้ชี้ไปยังไฟล์ JSON ที่ดาวน์โหลดมา
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS="path/to/your/credential-file.json"
   ```

   ตัวอย่าง:
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS="/Users/username/Downloads/my-project-credentials.json"
   ```

### ตัวอย่างการใช้ Python กับ Credential JSON:

หลังจากที่ตั้งค่าตัวแปรสภาพแวดล้อมเรียบร้อยแล้ว คุณสามารถใช้โค้ด Python ที่ได้กล่าวไปก่อนหน้านี้เพื่อเชื่อมต่อกับ Google Web Risk API และตรวจสอบ URL ได้ทันที