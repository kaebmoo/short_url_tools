import asyncio
from urllib.parse import urlparse
from playwright.async_api import async_playwright, Playwright

async def capture_screenshot(playwright: Playwright, url: str):
    parsed_url = urlparse(url)
    # Extract the netloc and path part, and replace '/' with '_' to form the filename
    file_name = f"{parsed_url.netloc}{parsed_url.path.replace('/', '_')}.png"
    output_path = f"scraper/output/{file_name}"

    chromium = playwright.chromium  # or "firefox" or "webkit".
    browser = await chromium.launch(headless=True)
    page = await browser.new_page(viewport={'width': 1280, 'height': 720})  # กำหนดขนาดของ viewport
    await page.goto(url)
    await page.screenshot(path=output_path, full_page=False)  # ตั้งค่า full_page เป็น False เพื่อจับภาพแค่ viewport
    await browser.close()

    print(f"Screenshot saved to {output_path}")

async def main():
    async with async_playwright() as playwright:
        print("1")
        await capture_screenshot(playwright, 'https://bit.ly/3MnWMV7')
        print("2")
        await capture_screenshot(playwright, 'https://www.digitalocean.com/community/tutorials/how-to-add-authentication-to-your-app-with-flask-login')

url = 'https://bit.ly/3MnWMV7'
asyncio.run(main())
