from fastapi import FastAPI
from playwright.async_api import async_playwright
import base64
from bs4 import BeautifulSoup
import os
import httpx
import asyncio

app = FastAPI()

# Tor socks5 proxy inside docker
TOR_PROXY = os.environ.get("TOR_PROXY", "socks5://tor:9050")

def analyze_security(html_content: str) -> list[str]:
    warnings = []
    soup = BeautifulSoup(html_content, "html.parser")
    
    # Static Analysis of the HTML mapping potential exploit surfaces
    if "navigator.geolocation" in html_content:
         warnings.append("This site contains scripts attempting to access your Geolocation.")
         
    if "navigator.mediaDevices" in html_content or "getUserMedia" in html_content:
         warnings.append("This site contains scripts attempting to access your Camera or Microphone.")
         
    inputs = soup.find_all("input")
    for b in inputs:
         if b.get("capture") is not None:
              warnings.append("Form detected requesting direct Camera/Microphone media capture.")
         accept = b.get("accept", "")
         if "video/" in accept or "audio/" in accept:
              warnings.append("Form detected requesting media (Audio/Video) uploads.")

    # Deduplicate
    return list(set(warnings))

async def fetch_pgp_key(base_url: str) -> str:
    """Attempt to fetch PGP key from common paths via SOCKS5."""
    paths = ["/pgp.txt", "/key.asc", "/pgp_key.txt", "/public.asc"]
    
    async def try_path(path):
        try:
            async with httpx.AsyncClient(proxy=TOR_PROXY, timeout=10.0) as client:
                res = await client.get(base_url.rstrip("/") + path)
                if res.status_code == 200 and "BEGIN PGP PUBLIC KEY" in res.text:
                    return res.text
        except Exception:
            pass
        return None

    tasks = [try_path(p) for p in paths]
    results = await asyncio.gather(*tasks)
    
    for r in results:
        if r:
            return r
    return None

@app.get("/capture")
async def capture(url: str):
    if not url.startswith("http"):
        url = "http://" + url
        
    try:
        async with async_playwright() as p:
            # We enforce the SOCKS5 Tor Proxy to ensure anonymous crawling safely
            browser = await p.chromium.launch(
                proxy={"server": TOR_PROXY}
            )
            # For maximum safety during capture, we disable javascript logic execution 
            # while still capturing the static HTML for source code analysis.
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                javascript_enabled=False 
            )
            page = await context.new_page()
            
            # Wait until load, timeout after 25s
            response = await page.goto(url, wait_until="load", timeout=25000)
            
            if not response or not response.ok:
                await browser.close()
                return {"success": False, "error": f"Failed to reach the onion site (Status {response.status if response else 'Unknown'})."}
                
            headers = response.headers
            headers_intel = {}
            if 'server' in headers:
                headers_intel['Server'] = headers['server']
            if 'x-powered-by' in headers:
                headers_intel['X-Powered-By'] = headers['x-powered-by']

            screenshot_bytes = await page.screenshot(type="jpeg", quality=65)
            html_content = await page.content()
            
            await browser.close()
            
            warnings = analyze_security(html_content)
            screenshot_str = base64.b64encode(screenshot_bytes).decode('utf-8')
            
            # Fire PGP Extraction
            pgp_key = await fetch_pgp_key(url)
            if not pgp_key:
                # Fallback: check main HTML body for PGP string
                if "BEGIN PGP PUBLIC KEY BLOCK" in html_content:
                    import re
                    match = re.search(r"-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]+?-----END PGP PUBLIC KEY BLOCK-----", html_content)
                    if match:
                        pgp_key = match.group(0)
            
            return {
                "success": True,
                "screenshot": screenshot_str,
                "warnings": warnings,
                "headers_intel": headers_intel,
                "pgp_key": pgp_key
            }
            
    except Exception as e:
        # Log internally but don't expose details to client
        import logging
        logging.getLogger(__name__).error(f"Capture failed for {url}: {e}")
        return {"success": False, "error": "Capture failed. The target may be unreachable or incompatible."}
