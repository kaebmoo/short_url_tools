# URL Blacklist Manager

URL Blacklist Manager เป็นแอปพลิเคชันเว็บที่ใช้ Flask สำหรับการจัดการ URL ที่ถูกบล็อก โดยผู้ใช้สามารถเพิ่ม ลบ และค้นหา URL ที่ถูกบล็อกได้ นอกจากนี้ยังสามารถนำเข้าและส่งออกข้อมูล URL ได้

## คุณสมบัติ

- เพิ่ม URL ที่ต้องการบล็อก
- ลบ URL ที่ถูกบล็อก
- ค้นหา URL ที่ถูกบล็อก
- ส่งออกข้อมูล URL เป็น CSV และ JSON
- นำเข้าข้อมูล URL จากไฟล์ CSV และ JSON
- แสดงสถานะการนำเข้าและส่งออกข้อมูลแบบเรียลไทม์

## การติดตั้ง

### ข้อกำหนดเบื้องต้น

- Python 3.x
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-WTF
- Flask-SocketIO

### การติดตั้งด้วยคำสั่ง

1. สร้าง Virtual Environment
    ```bash
    python3 -m venv venv
    ```

2. เริ่มใช้งาน Virtual Environment
    ```bash
    # บน macOS/Linux
    source venv/bin/activate
    # บน Windows
    venv\Scripts\activate
    ```

3. ติดตั้งแพ็คเกจที่จำเป็น
    ```bash
    pip install Flask Flask-SQLAlchemy Flask-Login Flask-WTF Flask-SocketIO
    ```

4. เริ่มใช้งานแอปพลิเคชัน
    ```bash
    python app.py
    ```

5. เปิดเว็บเบราว์เซอร์แล้วไปที่ URL [http://127.0.0.1:5001](http://127.0.0.1:5001)

## โครงสร้างโปรเจค

```
URL Blacklist Manager/
│
├── app.py               # ไฟล์หลักของแอปพลิเคชัน
├── blacklist.db         # ฐานข้อมูล SQLite
├── templates/           # โฟลเดอร์สำหรับ HTML Templates
│   ├── index.html
│   └── login.html
└── static/              # โฟลเดอร์สำหรับไฟล์ Static เช่น CSS และ JS
```

## การใช้งาน

### เพิ่ม URL

1. ไปที่หน้าแรก
2. กรอก URL ที่ต้องการบล็อก หมวดหมู่ และเหตุผล
3. คลิกปุ่ม "Add URL"

### ลบ URL

1. ไปที่หน้าแรก
2. คลิกปุ่ม "Remove" ที่อยู่ข้างๆ URL ที่ต้องการลบ

### ค้นหา URL

1. ไปที่หน้าแรก
2. กรอกข้อความที่ต้องการค้นหาในช่องค้นหา
3. กดปุ่ม "Search"

### ส่งออกข้อมูล

1. ไปที่หน้าแรก
2. คลิกปุ่ม "Export CSV" หรือ "Export JSON"

### นำเข้าข้อมูล

1. ไปที่หน้าแรก
2. เลือกไฟล์ CSV หรือ JSON ที่ต้องการนำเข้า
3. คลิกปุ่ม "Import"

## การแสดงสถานะ

- สถานะการนำเข้าและส่งออกข้อมูลจะแสดงในแถบด้านบนของหน้าเว็บแบบเรียลไทม์ โดยใช้ WebSocket

## การพัฒนาและการมีส่วนร่วม

หากต้องการมีส่วนร่วมในโปรเจคนี้ โปรด fork โปรเจคและส่ง pull request หรือเปิด issue เพื่อแจ้งปัญหาหรือข้อเสนอแนะ

## License


# URL Blacklist Manager

URL Blacklist Manager is a Flask-based web application for managing blocked URLs. Users can add, remove, and search for blocked URLs. Additionally, it supports importing and exporting URL data.

## Features

- Add URLs to be blocked
- Remove blocked URLs
- Search for blocked URLs
- Export URL data as CSV and JSON
- Import URL data from CSV and JSON files
- Real-time import/export status updates

## Installation

### Prerequisites

- Python 3.x
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-WTF
- Flask-SocketIO

### Installation Steps

1. Create a Virtual Environment
    ```bash
    python3 -m venv venv
    ```

2. Activate the Virtual Environment
    ```bash
    # On macOS/Linux
    source venv/bin/activate
    # On Windows
    venv\Scripts\activate
    ```

3. Install the required packages
    ```bash
    pip install Flask Flask-SQLAlchemy Flask-Login Flask-WTF Flask-SocketIO
    ```

4. Run the application
    ```bash
    python app.py
    ```

5. Open your web browser and navigate to [http://127.0.0.1:5001](http://127.0.0.1:5001)

## Project Structure

```
URL Blacklist Manager/
│
├── app.py               # Main application file
├── blacklist.db         # SQLite database
├── templates/           # Folder for HTML Templates
│   ├── index.html
│   └── login.html
└── static/              # Folder for static files like CSS and JS
```

## Usage

### Adding URLs

1. Navigate to the home page
2. Enter the URL to be blocked, category, and reason
3. Click the "Add URL" button

### Removing URLs

1. Navigate to the home page
2. Click the "Remove" button next to the URL you want to remove

### Searching URLs

1. Navigate to the home page
2. Enter the search term in the search box
3. Click the "Search" button

### Exporting Data

1. Navigate to the home page
2. Click the "Export CSV" or "Export JSON" button

### Importing Data

1. Navigate to the home page
2. Select the CSV or JSON file to import
3. Click the "Import" button

## Status Updates

- The import/export status is displayed at the top of the webpage in real-time using WebSocket.

## Development and Contributions

If you would like to contribute to this project, please fork the project and send a pull request or open an issue to report problems or suggestions.

## License



