import http.client
import json
import os

from urllib.parse import quote_plus  # สำหรับ URL encoding
import ssl

def send_otp(phone_number, otp):
    
    user = 'ntdigital'
    passw = 'xyGcN2'

    otp_code = otp

    # URL encode ข้อความ OTP ก่อนนำไปใส่ใน XML
    encoded_message = quote_plus(f"Your OTP code is {otp_code}")

    # Construct the XML payload
    payload = f"""<?xml version="1.0" encoding="UTF-8"?>
                <Envelope>
                <Header/>
                    <Body>
                        <sendSMS>
                            <user>{user}</user>
                            <pass>{passw}</pass>
                            <from>NTDigital</from>
                            <target>{phone_number}</target>
                            <mess>{encoded_message}</mess>
                            <lang>E</lang>
                        </sendSMS>
                    </Body>
                </Envelope>
                """
    headers = {
        'Content-Type': 'application/xml',
        'Accept': 'application/xml'
    }

    # context = ssl.create_default_context(cafile="/Users/seal/Documents/GitHub/short_url_tools/.venv/lib/python3.10/site-packages/certifi/cacert.pem")
    context = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection("smsgw.mybynt.com", context=context)
    
    conn.request("POST", "/service/SMSWebServiceEngine.php", payload, headers)
    res = conn.getresponse()
    data = res.read()
    print(data.decode("utf-8"))

send_otp('0813520625', 'ABCD')