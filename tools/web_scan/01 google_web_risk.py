import os
import json
from google.api_core.exceptions import PermissionDenied
from google.cloud import webrisk_v1
from google.cloud.webrisk_v1 import ThreatType

def check_url_safety(url):
    try:
        # Create the client
        client = webrisk_v1.WebRiskServiceClient()

        # The URL to be checked
        uri = url
        threat_types = ["MALWARE", "SOCIAL_ENGINEERING"]

        # Search the URI
        response = client.search_uris(uri=uri, threat_types=threat_types)

        # Check the response
        if response.threat:
            print(f"The URL {url} is not safe.")
            for threat in response.threat.threat_types:
                print(f"Threat type: {threat} {ThreatType(threat).name}")
            return True
        else:
            print(f"The URL {url} is safe.")
            return False

    except PermissionDenied as exc:
        print("Permission denied: ", exc)
        print("Please ensure the service account has the correct permissions and the Web Risk API is enabled.")
    
    return None

# Path to the credentials file
# ไฟล์ JSON Credential จาก Google Cloud
credentials_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api-project-744419703652-f520f5308dff.json")

# Set the environment variable for authentication
if os.path.exists(credentials_path):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = credentials_path

    # Example URL to check
    # https://coinbase-wallett.weebly.com
    # url_to_check = "https://coinbase-wallett.weebly.com"
    # check_url_safety(url_to_check)
    # check_url_safety("https://codinggun.com/security/jwt/")
    # check_url_safety("http://sms-carte-vitale.fr")
    # check_url_safety("http://livetrack.in/EmployeeMasterImages/qace.jpg")
    check_url_safety("http://web-whatsapp-kf.top/")

else:
    print("Credential file not found.")
