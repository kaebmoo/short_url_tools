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

    # Get a URL analysis report
    # แบบใช้ http get
    # url_api = https://www.virustotal.com/api/v3/urls/
    url = url_api + url_id
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    print(response.status_code)
    print(response.text)

if __name__ == "__main__":
    main()
