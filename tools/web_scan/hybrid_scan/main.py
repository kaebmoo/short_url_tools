import asyncio
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import (Flask, Response, abort, jsonify, redirect, render_template,
                   request, stream_with_context, url_for)
from sqlalchemy.exc import SQLAlchemyError

from hybrid_analysis import (check_hybrid_analysis_url, check_pending_scans,
                             check_quick_scan_status,
                             get_hybrid_analysis_summary,
                             get_new_urls_from_database, reload_config,
                             save_scan_results_to_database, update_database)
from models import ScanRecord, scan_records_session, urls_session

app = Flask(__name__)

# Create a global executor
executor = ThreadPoolExecutor(max_workers=5)

# Load environment variables
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), 'config.env'))
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")

# Secret key for session management (ensure this is set securely in production)
app.secret_key = os.urandom(24)  # Change to a secure key in production

# Global variable to store scan status
scan_status = {}

# Global event loop
loop = None

def normalize_url(url: str, trailing_slash: bool = False) -> str:
    """
    Normalizes a URL by optionally adding or removing trailing slashes.

    Args:
        url (str): The URL to normalize.
        trailing_slash (bool): Whether to ensure a trailing slash (True) or remove it (False).

    Returns:
        str: The normalized URL.
    """
    # Strip leading and trailing whitespace from the URL
    url = url.strip()

    parsed_url = urlparse(url)
    path = parsed_url.path.rstrip("/")  # Remove all trailing slashes from the path

    if trailing_slash:
        path += "/"  # Add a single trailing slash if requested

    return parsed_url._replace(path=path).geturl()

@app.route("/")
def index():
    """
    Renders the index page with a list of all scan records.

    Returns:
        Response: The rendered HTML page showing all scan records.
    """
    scans = scan_records_session.query(ScanRecord).all()
    return render_template("index.html", scans=scans)

@app.route('/stream')
def stream():
    def event_stream():
        while True:
            # Get the latest scan statuses
            yield f"data: {json.dumps(scan_status)}\n\n"
            time.sleep(5)  # Adjust the interval as needed
    return Response(event_stream(), content_type='text/event-stream')

@app.route('/scan_status_sse')
def scan_status_sse():
    def generate():
        # Stream the scan status updates
        while True:
            for url, status in scan_status.items():
                # Find the scan record from the database
                scan_record = scan_records_session.query(ScanRecord).filter_by(url=url).first()
                if scan_record:
                    data = {
                        'url': scan_record.url,
                        'status': scan_record.status,
                        'scan_type': scan_record.scan_type,
                        'timestamp': scan_record.timestamp.strftime('%Y-%m-%d %H:%M:%S') if scan_record.timestamp else '',
                        'threat_score': scan_record.threat_score if scan_record.threat_score is not None else 'N/A',
                        'verdict': scan_record.verdict if scan_record.verdict is not None else 'N/A'
                    }
                    yield f'data: {json.dumps(data)}\n\n'
            time.sleep(5)

    return Response(stream_with_context(generate()), content_type='text/event-stream')


@app.route("/scan_single_url", methods=["POST"])
def scan_single_url():
    """
    Scans a single URL submitted through a form and updates the scan status.

    Returns:
        Response: Redirects to the index page after initiating the scan.
    """
    global scan_status
    url = request.form.get('url')
    if not url:
        abort(400, "URL is required.")

    scan_status = {url: "Sending to scan"}
    try:
        # Run the async function in a separate thread using run_in_executor
        loop.run_in_executor(executor, asyncio.run, scan_single_url_async(url))
    except Exception as e:
        print(f"Error scanning URL: {e}")
        scan_status[url] = "Error during scanning"
        abort(500, "An error occurred during the scan.")

    return redirect(url_for('index'))

@app.route("/scan_urls", methods=["POST"])
def scan_urls():
    """
    Initiates a scan for multiple URLs retrieved from the database and updates the scan status.

    Returns:
        Response: Redirects to the index page after initiating the scans.
    """
    global scan_status
    urls = get_new_urls_from_database()
    if not urls:
        return redirect(url_for('index'))  # No URLs to scan

    scan_status = {url: "Sending to scan" for url in urls}
    print(f"Initial scan_status: {scan_status}")

    try:
        # Run the async function in a thread-safe manner
        asyncio.run_coroutine_threadsafe(scan_urls_async(urls), loop)
    except Exception as e:
        print(f"Error scanning URLs: {e}")
        scan_status = {"message": "Error during scanning"}
        abort(500, "An error occurred during the batch scan.")

    return redirect(url_for('index'))

@app.route("/scan_status")
def get_scan_status():
    """
    Returns the current status of all URL scans as a JSON response.

    Returns:
        Response: A JSON object containing the scan statuses.
    """
    global scan_status
    print(f"Current scan_status: {scan_status}")
    return jsonify(scan_status)

async def scan_single_url_async(url):
    """
    Asynchronously scans a single URL or checks its existing status if it's already in the database.

    Args:
        url (str): The URL to scan.

    Raises:
        Exception: If an error occurs during scanning.
    """
    global scan_status
    try:
        await check_url(url)
    except Exception as e:
        print(f"Error in scan_single_url_async: {e}")
        scan_status[url] = "Error during scanning"

async def scan_urls_async(urls):
    """
    Asynchronously scans multiple URLs.

    Args:
        urls (list): A list of URLs to scan.

    Raises:
        Exception: If an error occurs during scanning.
    """
    global scan_status
    if urls:
        tasks = [check_url(url) for url in urls]
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            print(f"Error in scan_urls_async: {e}")
            scan_status = {"message": "Error during scanning"}
    else:
        scan_status = {"message": "No URLs to scan."}

def map_verdict_to_status(verdict):
    """
    Maps the verdict from Hybrid Analysis to a valid status for the database.

    Args:
        verdict (str): The verdict string to map.

    Returns:
        str: The mapped status value.
    """
    if verdict == 'malicious':
        return 'Dangerous'
    elif verdict == 'no specific threat':
        return 'Safe'
    # Add more mappings as needed
    else:
        return 'No conclusive information'
    
async def check_url(url):
    """
    Asynchronously checks a single URL with Hybrid Analysis and updates the database.

    Args:
        url (str): The URL to be checked.

    Updates:
        scan_status (dict): Updates the scan status for the URL.
    """
    global scan_status
    scan_status[url] = "Checking in database"
    url = normalize_url(url, trailing_slash=False)

    try:
        # Start a new session for this operation
        existing_scan = scan_records_session.query(ScanRecord).filter(ScanRecord.url == url).first()

        if existing_scan:
            scan_id = existing_scan.scan_id
            sha256 = existing_scan.sha256

            # Check the scan status using the stored scan_id
            scan_status[url] = "Checking existing scan status"
            scan_status_data = await check_quick_scan_status(scan_id)
            if scan_status_data and scan_status_data.get('finished'):
                # Fetch the final results using the overview endpoint
                final_results = await get_hybrid_analysis_summary(HYBRID_ANALYSIS_API_KEY, sha256)
                if final_results:
                    # Map the verdict to a valid status
                    verdict = final_results.get('verdict', 'No conclusive information')
                    status = map_verdict_to_status(verdict)
                    
                    # Update the database with the final results
                    existing_scan.status = status
                    existing_scan.timestamp = datetime.now(timezone.utc)
                    existing_scan.threat_score = final_results.get('threat_score')
                    existing_scan.verdict = verdict
                    
                    # Commit the changes to the database
                    scan_records_session.commit()
                    scan_status[url] = status
                    print(f"Updated scan record for {url} with new results.")
                    return
                else:
                    scan_status[url] = "No detailed results available yet"
            else:
                scan_status[url] = "In queue for scanning"
                print(f"Scan for {url} still in progress or not found.")
                return
        else:
            # If not found in the database, submit it for scanning
            scan_status[url] = "Submitting for scan"
            response = await check_hybrid_analysis_url(HYBRID_ANALYSIS_API_KEY, url)
            if response is not None:
                # Handle the case where the URL is not allowed
                if 'error' in response and response['error'] == 'Not allowed URL submitted':
                    status = "Not allowed URL submitted"
                    scan_status[url] = status
                    print(f"Updated status for {url}: {status}")
                    return

                scan_id = response.get('id')
                sha256 = response.get('sha256')

                # Store the scan_id and sha256 in the database with an initial status
                save_scan_results_to_database(response, url, 'hybrid-analysis', "In queue for scanning")
                scan_status[url] = "In queue for scanning"
                print(f"Submitted URL for scanning: {url}")
            else:
                status = "No conclusive information"
                scan_status[url] = status
    except SQLAlchemyError as e:
        scan_records_session.rollback()
        print(f"Database error in check_url(): {str(e)}")
    except Exception as e:
        scan_records_session.rollback()
        print(f"Unexpected error in check_url(): {str(e)}")

@app.route("/config", methods=["GET", "POST"])
def config():
    """
    Handles the configuration page to update environment settings.

    GET: Renders the configuration page.
    POST: Updates the .env file with new settings and reloads the configuration.

    Returns:
        Response: Redirects to the index page after saving the configuration or renders the config page.
    """
    # This route should be protected in a real application (e.g., require authentication)
    if request.method == "POST":
        hybrid_analysis_api_key = request.form.get("hybrid_analysis_api_key")
        hybrid_analysis_url = request.form.get("hybrid_analysis_url")
        database_path = request.form.get("database_path")
        scan_records_database_path = request.form.get(
            "scan_records_database_path")
        sleep_seconds = request.form.get("sleep_seconds")

        try:
            with open(os.path.join(os.path.dirname(__file__), 'config.env'),
                      'w') as configfile:
                configfile.write(
                    f"HYBRID_ANALYSIS_API_KEY={hybrid_analysis_api_key}\n")
                configfile.write(
                    f"HYBRID_ANALYSIS_URL={hybrid_analysis_url}\n")
                configfile.write(f"DATABASE_PATH={database_path}\n")
                configfile.write(
                    f"SCAN_RECORDS_DATABASE_PATH={scan_records_database_path}\n"
                )
                configfile.write(f"SLEEP_SECONDS={sleep_seconds}\n")

            load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__),
                                                 'config.env'),
                        override=True)
            reload_config()
        except Exception as e:
            print(f"Error saving configuration: {e}")
            abort(500, "Error saving configuration.")

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
    # Create an event loop and assign it to a global variable
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Schedule the background task
    loop.create_task(check_pending_scans())

    # Run the Flask app
    app.run(host="0.0.0.0", port=8088, debug=True)
