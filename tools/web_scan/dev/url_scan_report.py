import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode
import time
import configparser

config = configparser.ConfigParser(interpolation=None)
config.read("/Users/seal/Documents/GitHub/short_url_tools/tools/web_scan/config.ini")
api_key = config["CONFIG"]["API_KEY"]

# url = "https://www.royalrain.go.th/royalrain/ShowDetail.aspx?DetailId=11101"
url = "www.ntplc.co.th"
url = "https://www.cat.net.th"

with virustotal_python.Virustotal(api_key) as vtotal:
    try:
        resp = vtotal.request("urls", data={"url": url}, method="POST")
        # Safe encode URL in base64 format
        # https://developers.virustotal.com/reference/url
        url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
        report = vtotal.request(f"urls/{url_id}")
        # pprint(report.object_type)
        # pprint(report.data)
        print(report.data)

    except virustotal_python.VirustotalError as err:
        print(f"Failed to send URL: {url} for analysis and get the report: {err}")