# ส่ง url ไป scan
import vt
import requests
import calendar, time
import datetime;
import pytz
from datetime import timedelta
import configparser

config = configparser.ConfigParser(interpolation=None)
config.read("/Users/seal/Documents/GitHub/short_url_tools/tools/web_scan/config.ini")
api_key = config["CONFIG"]["API_KEY"]

url = "https://www.cat.net.th"
url = "http://42.235.69.142:38523/bin.sh"
url_id = vt.url_id(url)
with vt.Client(api_key) as client:
    url = client.get_object("/urls/{}", url_id)

    print(url_id)
    print(url.last_analysis_stats)
    print(url.last_analysis_date)
    last_analysis_date = str(url.last_analysis_date)
    print(calendar.timegm(time.strptime(last_analysis_date, '%Y-%m-%d %H:%M:%S'))) # '2000-01-01 12:34:00'
    local_time = int(calendar.timegm(time.strptime(last_analysis_date, '%Y-%m-%d %H:%M:%S'))) + 25200
    gmt_time = calendar.timegm(time.strptime(last_analysis_date, '%Y-%m-%d %H:%M:%S'))

    print(local_time)
    print("Last analysis date, Local time: ", time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(gmt_time))) # or time.gmtime
    print("GMT time: ", datetime.datetime.utcfromtimestamp(gmt_time).replace(tzinfo=datetime.timezone.utc))
    current_date = datetime.datetime.now(pytz.timezone('Asia/Bangkok'))
    print("Current date: ", current_date.strftime("%a, %d %b %Y %H:%M:%S GMT+7"))
    print(timedelta(seconds=(time.time() - gmt_time)))
    relative = timedelta(seconds=(time.time() - gmt_time))
    print("%d days" % relative.days)




# https://virustotal.github.io/vt-py/quickstart.html


# scan an url

# analysis = client.scan_url('https://dg.th/')
# print(analysis)

client.close()
