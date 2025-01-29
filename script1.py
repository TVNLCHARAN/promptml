import asyncio
import requests
# from playwright.async_api import async_playwright

# async def fetch_page_content(url):
#     async with async_playwright() as p:
#         browser = await p.chromium.launch(headless=True)
#         page = await browser.new_page()
#         await page.goto(url)
#         content = await page.content()
#         print(content)
#         await browser.close()

url = "https://prompt.ml/0"
# asyncio.run(fetch_page_content(url))

response = requests.get(url)
print(response.content)
