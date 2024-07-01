# เน้นไปที่ malware
#!/usr/bin/python3
import sys
import requests
import json

def query_urlhaus(url):
    try:
        # Construct the HTTP request
        data = {'url' : url}
        response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data)
        # Parse the response from the API
        json_response = response.json()
        if json_response['query_status'] == 'ok':
            print(json.dumps(json_response, indent=4, sort_keys=False))
            return True
        elif json_response['query_status'] == 'no_results':
            print("No results")
            return False
        else:
            print("Something went wrong")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error communicating with URLhaus API: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON response: {e}")
        return None
    except KeyError as e:
        print(f"Unexpected response format from URLhaus API: {e}")
        return None
    
'''
if len(sys.argv) > 1:
    query_urlhaus(sys.argv[1])
else:
    print("Looking up a URL on the URLhaus bulk API")
    print("Usage: python3 lookup_url.py <URL>")
'''
# query_urlhaus("http://livetrack.in/EmployeeMasterImages/qace.jpg")
# query_urlhaus("https://www.ntplc.co.th")
query_urlhaus("http://web-whatsapp-kf.top/")