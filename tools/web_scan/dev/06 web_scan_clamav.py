import requests
import subprocess
import tempfile
import os

def download_file_from_url(url):
    response = requests.get(url)
    if response.status_code == 200:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(response.content)
            return tmp_file.name
    else:
        print("Failed to download the file.")
        return None

def scan_file_with_clamav(file_path):
    try:
        result = subprocess.run(['clamscan', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8')
        print("ClamAV Scan Result:\n", output)
        if "Infected files: 0" in output:
            print("No threats found.")
        else:
            print("Threat detected!")
    except Exception as e:
        print(f"An error occurred while scanning the file: {e}")

def main():
    url = "https://www.metabase.com/product/csv-uploads"
    url = "http://185.172.128.40/hv.exe"
    file_path = download_file_from_url(url)
    if file_path:
        scan_file_with_clamav(file_path)
        os.remove(file_path)  # Clean up temporary file

if __name__ == "__main__":
    main()
