from url_blacklist import URLBlacklist

# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    blacklist = URLBlacklist()
    
    # เพิ่ม URL
    blacklist.add_url("http://example.com", "ADVERTISING", "Test URL")
    
    # ตรวจสอบ URL
    print(blacklist.check_url("http://example.com"))  # True
    
    # ตั้งค่าสถานะ
    blacklist.set_status("http://example.com", False)
    
    # ลบ URL
    blacklist.remove_url("http://example.com")
    
    # โหลดข้อมูลใหม่ถ้ามีการเปลี่ยนแปลง
    if blacklist.reload_if_modified():
        print("ไฟล์มีการเปลี่ยนแปลง และได้ทำการโหลดข้อมูลใหม่แล้ว")
    else:
        print("ไฟล์ไม่มีการเปลี่ยนแปลง")