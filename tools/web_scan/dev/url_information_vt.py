import vt
import requests
import base64
import configparser

config = configparser.ConfigParser(interpolation=None)
config.read("/Users/seal/Documents/GitHub/short_url_tools/tools/web_scan/config.ini")

api_key = ""
# https://docs.virustotal.com/reference/errors
error_code = {
    400 : "BadRequestError",
    400 : "InvalidArgumentError",
    400 : "NotAvailableYet",
    400 : "UnselectiveContentQueryError",
    400 : "UnsupportedContentQueryError",
    401 : "AuthenticationRequiredError",
    401 : "UserNotActiveError",
    401 : "WrongCredentialsError",
    403 : "ForbiddenError",
    404 : "NotFoundError",
    409 : "AlreadyExistsError",
    424 : "FailedDependencyError",
    429 : "QuotaExceededError",
    429 : "TooManyRequestsError",
    503 : "TransientError",
    504 : "DeadlineExceededError"
}

def main():
    print(config.sections())
    api_key = config["CONFIG"]["API_KEY"]
    url_api = config["CONFIG"]["URL_API"]

    # https://developers.virustotal.com/reference/url-info
    # สร้าง url id
    # http://42.235.69.142:38523/bin.sh
    url = "http://42.235.69.142:38523/bin.sh" # "https://www.cat.net.th"
    url_id = vt.url_id(url)
    print(url_id)

    # ใช้ lib ของ vt-py 
    # https://github.com/VirusTotal/vt-py/tree/master
    # ข้อดีคือ เรียกใช้ข้อมูลจาก object ได้เลย ไม่ต้องประมวลผลข้อมูลแบบ http response 
    # แต่ต้องจัดการกับ error 
    try:
        with vt.Client(api_key) as client:
            url = client.get_object("/urls/{}", url_id)
            print('Analysis Stats:')
            print(url.last_analysis_stats)
            print(url.last_analysis_date)
            results = url.last_analysis_stats
            
            if results['malicious'] == 0:
                print('malicious: ', results['malicious'])
                print("น่าจะปลอดภัย")
            else:
                print("ฉิบหายแน่ อย่าเข้าไป")
    except Exception as error:
        print(error.code)
        print(error.message)
        chunks = error.message.split(" ")
        print(chunks)
        if chunks[0] == "URL":
            url_base64 = chunks[1].replace('"', '')
            decodedBytes = base64.urlsafe_b64decode(url_base64 + '=' * (4 - len(url_base64) % 4))
            decodedStr = str(decodedBytes, "utf-8")
            print("URL : " + decodedStr + " not found")
        vt.APIError(error.code, error.message)

    # https://virustotal.github.io/vt-py/quickstart.html


    # scan an url
    # analysis = client.scan_url('https://dg.th/')
    # print(analysis)

    client.close()

if __name__ == "__main__":
    main()
