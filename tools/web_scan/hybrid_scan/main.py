from flask import Flask, render_template, request, redirect, url_for, jsonify
import os
import asyncio
from hybrid_analysis import check_hybrid_analysis_url, get_new_urls_from_database, update_database, reload_config, save_scan_results_to_database
from dotenv import load_dotenv
from models import ScanRecord, urls_session, scan_records_session
from datetime import datetime

app = Flask(__name__)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), 'config.env'))

app.secret_key = os.urandom(24)

# Global variable to store scan status
scan_status = {}

@app.route("/")
def index():
    scans = scan_records_session.query(ScanRecord).all()
    return render_template("index.html", scans=scans)

@app.route("/scan_single_url", methods=["POST"])
def scan_single_url():
    global scan_status
    url = request.form.get('url')
    scan_status = {url: "Sending to scan"}
    asyncio.run(scan_single_url_async(url))
    return redirect(url_for('index'))

@app.route("/scan_urls", methods=["POST"])
def scan_urls():
    global scan_status
    urls = get_new_urls_from_database()
    scan_status = {url: "Sending to scan" for url in urls}
    print(f"Initial scan_status: {scan_status}")
    asyncio.run(scan_urls_async(urls))
    return redirect(url_for('index'))

@app.route("/scan_status")
def get_scan_status():
    global scan_status
    print(f"Current scan_status: {scan_status}")
    return jsonify(scan_status)

async def scan_single_url_async(url):
    global scan_status
    await check_url(url)

async def scan_urls_async(urls):
    global scan_status
    if urls:
        tasks = [check_url(url) for url in urls]
        await asyncio.gather(*tasks)
    else:
        scan_status = {"message": "No URLs to scan."}

async def check_url(url):
    global scan_status
    scan_status[url] = "Scanning"
    api_key = os.getenv("HYBRID_ANALYSIS_API_KEY")
    response = await check_hybrid_analysis_url(api_key, url)
    if response is not None:
        in_queue = any(scanner['status'] == 'in-queue' for scanner in response['scanners'])
        no_classification = any(scanner['status'] == 'no-classification' for scanner in response['scanners'])
        
        if in_queue:
            status = "In queue for scanning"
        elif no_classification:
            status = "No classification"
        else:
            is_dangerous = any(scanner['status'] == 'malicious' for scanner in response['scanners'])
            status = "Dangerous" if is_dangerous else "Safe"
            update_database(url, -1 if is_dangerous else 1)
            
    else:
        status = "No conclusive information"
    
    save_scan_results_to_database(response, url, 'hybrid-analysis', status)
    scan_status[url] = status
    print(f"Updated status for {url}: {status}")

@app.route("/config", methods=["GET", "POST"])
def config():
    if request.method == "POST":
        hybrid_analysis_api_key = request.form.get("hybrid_analysis_api_key")
        hybrid_analysis_url = request.form.get("hybrid_analysis_url")
        database_path = request.form.get("database_path")
        scan_records_database_path = request.form.get("scan_records_database_path")
        sleep_seconds = request.form.get("sleep_seconds")
        
        with open(os.path.join(os.path.dirname(__file__), 'config.env'), 'w') as configfile:
            configfile.write(f"HYBRID_ANALYSIS_API_KEY={hybrid_analysis_api_key}\n")
            configfile.write(f"HYBRID_ANALYSIS_URL={hybrid_analysis_url}\n")
            configfile.write(f"DATABASE_PATH={database_path}\n")
            configfile.write(f"SCAN_RECORDS_DATABASE_PATH={scan_records_database_path}\n")
            configfile.write(f"SLEEP_SECONDS={sleep_seconds}\n")
        
        load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), 'config.env'), override=True)
        reload_config()
        
        return redirect(url_for('index'))
    
    config_path = os.path.join(os.path.dirname(__file__), 'config.env')
    config_values = {}
    if os.path.exists(config_path):
        with open(config_path, 'r') as configfile:
            for line in configfile:
                key, value = line.strip().split('=', 1)
                config_values[key] = value
    
    return render_template("config.html", config=config_values)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8088, debug=True)
