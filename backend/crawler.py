"""
Onion Crawler for Singularity Directory.
Fetches new .onion links from Ahmia and other trusted sources via Tor,
filters them through the blacklist, and injects them into directory_links.
"""

import asyncio
import re
import logging
import httpx
from bs4 import BeautifulSoup
from backend.database import add_directory_link, get_directory_links

logger = logging.getLogger(__name__)

import os

TOR_PROXY = os.environ.get("TOR_PROXY", "socks5://127.0.0.1:9050")

# V3 onion address pattern (56 chars base32 + .onion)
ONION_REGEX = re.compile(r'[a-z2-7]{56}\.onion', re.IGNORECASE)

# Sources to crawl
AHMIA_ADDRESS_URL = "https://ahmia.fi/address/"
AHMIA_ONION_URL = "http://juhanurmihxlp77nkq76byazcjo22cgvdztsnssyevzi7a2nfozpxpad.onion/address/"

# Content blacklist — reject any onion whose URL or page title contains these
BLACKLIST_KEYWORDS = [
    "cp", "child", "drugs", "weapons", "hitman", "murder",
    "illegal", "escort", "market", "porn", "xxx", "sex",
    "cocaine", "heroin", "meth", "fentanyl"
]

# Maximum number of new links to add per crawl cycle (prevent DB flooding)
MAX_NEW_PER_CYCLE = 200


def _is_blacklisted(address: str, title: str = "") -> bool:
    """Check if an onion address or its title contains blacklisted keywords."""
    combined = (address + " " + title).lower()
    for kw in BLACKLIST_KEYWORDS:
        if re.search(r'\b' + re.escape(kw) + r'\b', combined):
            return True
    return False


def _extract_onions_from_html(html: str) -> list[dict]:
    """
    Parse Ahmia's /address/ page and extract onion addresses.
    Returns a list of dicts: [{"url": "xxx.onion", "name": "xxx.onion"}, ...]
    """
    results = []
    seen = set()

    soup = BeautifulSoup(html, "lxml")

    # Ahmia lists onions as <a> tags linking to http://xxx.onion/
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"].strip()
        match = ONION_REGEX.search(href)
        if match:
            onion = match.group(0).lower()
            if onion not in seen:
                seen.add(onion)
                # Use the link text as name if available, otherwise use the address
                name = a_tag.get_text(strip=True) or onion
                results.append({"url": onion, "name": name})

    # Also scan raw text for any onion addresses not in <a> tags
    for match in ONION_REGEX.finditer(html):
        onion = match.group(0).lower()
        if onion not in seen:
            seen.add(onion)
            results.append({"url": onion, "name": onion})

    return results


async def _fetch_page(url: str, use_tor: bool = True) -> str | None:
    """Fetch a page's HTML content, optionally through Tor."""
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        kwargs = {"timeout": 60.0, "headers": headers}
        if use_tor:
            kwargs["proxy"] = TOR_PROXY

        async with httpx.AsyncClient(**kwargs) as client:
            response = await client.get(url)
            if response.status_code < 400:
                return response.text
    except Exception as e:
        logger.warning(f"Crawler: Failed to fetch {url}: {e}")
    return None


async def fetch_new_onions() -> int:
    """
    Main crawl function. Fetches onion addresses from sources,
    filters them, and injects new ones into the database.
    Returns the number of newly added links.
    """
    # Get existing URLs to avoid duplicates
    existing_links = await get_directory_links()
    existing_urls = set()
    for link in existing_links:
        link = dict(link) if not isinstance(link, dict) else link
        existing_urls.add(link.get("url", "").lower().strip())

    all_discovered = []

    # --- Source 1: Ahmia clearnet (routed through Tor for IP privacy) ---
    logger.info("Crawler: Fetching from Ahmia (via Tor)...")
    html = await _fetch_page(AHMIA_ADDRESS_URL, use_tor=True)
    if html:
        onions = _extract_onions_from_html(html)
        all_discovered.extend(onions)
        logger.info(f"Crawler: Found {len(onions)} onions from Ahmia clearnet.")

    # --- Source 2: Ahmia .onion mirror (via Tor) ---
    logger.info("Crawler: Fetching from Ahmia (.onion mirror)...")
    html_onion = await _fetch_page(AHMIA_ONION_URL, use_tor=True)
    if html_onion:
        onions = _extract_onions_from_html(html_onion)
        all_discovered.extend(onions)
        logger.info(f"Crawler: Found {len(onions)} onions from Ahmia .onion.")

    # Deduplicate
    seen = set()
    unique = []
    for item in all_discovered:
        url_lower = item["url"].lower()
        if url_lower not in seen:
            seen.add(url_lower)
            unique.append(item)

    # Filter and inject
    added = 0
    for item in unique:
        if added >= MAX_NEW_PER_CYCLE:
            logger.info(f"Crawler: Hit max limit ({MAX_NEW_PER_CYCLE}), stopping injection.")
            break

        url = item["url"]
        name = item["name"]

        # Skip if already in DB
        if url.lower() in existing_urls:
            continue

        # Skip blacklisted
        if _is_blacklisted(url, name):
            continue

        # Inject into DB with "New/Unverified" category, is_online=0
        await add_directory_link(
            name=name,
            url=url,
            category="New/Unverified"
        )
        added += 1

    logger.info(f"Crawler: Cycle complete. Added {added} new onion links.")
    return added


async def crawler_loop():
    """
    Background loop that runs the crawler every 24 hours.
    Waits 60 seconds on startup before first crawl to let other services initialize.
    """
    # Initial delay to let Tor and DB fully initialize
    await asyncio.sleep(60)

    while True:
        try:
            new_count = await fetch_new_onions()
            logger.info(f"Crawler: Sleeping 24h. Last run added {new_count} links.")
        except Exception as e:
            logger.error(f"Crawler loop error: {e}")

        # Sleep 24 hours
        await asyncio.sleep(86400)
