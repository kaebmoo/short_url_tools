# tools/web_scan/hybrid_scan/main_fastapi.py
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv
import os
import sqlite3
import asyncio

from web_scan.hybrid_scan.hybrid_analysis import check_hybrid_analysis_url, get_new_urls_from_database, update_database

# โหลดค่าจาก .env
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), 'config.env'))

app = FastAPI()
templates = Jinja2Templates(directory="web_scan/hybrid_scan/templates")

DATABASE_PATH = os.getenv("DATABASE_PATH")
SLEEP_SECONDS = int(os.getenv("SLEEP_SECONDS", 2))

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    urls = get_new_urls_from_database()
    return templates.TemplateResponse("index.html", {"request": request, "urls": urls})

@app.post("/scan")
async def scan_urls():
    urls = get_new_urls_from_database()
    if urls:
        tasks = [check_url(url) for url in urls]
        await asyncio.gather(*tasks)
        await asyncio.sleep(SLEEP_SECONDS)
    return RedirectResponse(url="/", status_code=303)

async def check_url(url):
    api_key = os.getenv("HYBRID_ANALYSIS_API_KEY")
    response = await check_hybrid_analysis_url(api_key, url)
    if response is not None:
        in_queue = any(scanner['status'] == 'in-queue' for scanner in response['scanners'])
        no_classification = any(scanner['status'] == 'no-classification' for scanner in response['scanners'])
        
        if in_queue:
            print(f"URL: {url} is still in queue for scanning.")
        elif no_classification:
            print(f"URL: {url} is no classification.")
        else:
            is_dangerous = any(scanner['status'] == 'malicious' for scanner in response['scanners'])
            update_database(url, -1 if is_dangerous else 1)
            print(f"URL: {url} is {'dangerous' if is_dangerous else 'safe'}")
    else:
        print(f"No conclusive information for URL: {url}")

@app.post("/config")
async def update_config(request: Request, hybrid_analysis_api_key: str = Form(...), hybrid_analysis_url: str = Form(...), database_path: str = Form(...), sleep_seconds: int = Form(...)):
    with open(os.path.join(os.path.dirname(__file__), 'config.env'), 'w') as configfile:
        configfile.write(f"HYBRID_ANALYSIS_API_KEY={hybrid_analysis_api_key}\n")
        configfile.write(f"HYBRID_ANALYSIS_URL={hybrid_analysis_url}\n")
        configfile.write(f"DATABASE_PATH={database_path}\n")
        configfile.write(f"SLEEP_SECONDS={sleep_seconds}\n")
    return RedirectResponse(url="/", status_code=303)
