import asyncio
import re
import httpx
import logging
from backend.database import get_directory_links, update_link_status, log_link_uptime

logger = logging.getLogger(__name__)

import os

TOR_PROXY = os.environ.get("TOR_PROXY", "socks5://127.0.0.1:9050")

BLACKLIST_KEYWORDS = [
    "cp", "child", "drugs", "weapons", "hitman", "murder", "illegal", "escort", "market"
]

# Lock to prevent overlapping scan cycles
_scan_lock = asyncio.Lock()


def is_suspicious(url: str, name: str = "") -> bool:
    content = (url + " " + name).lower()
    for kw in BLACKLIST_KEYWORDS:
        if re.search(r'\b' + re.escape(kw) + r'\b', content):
            return True
    return False


async def ping_onion(url: str) -> bool:
    """Ping a .onion or clearnet URL through the Tor SOCKS5 proxy."""
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"

    # Security Fix: Prevent SSRF by ensuring the URL is actually an onion service
    # Tor Proxy handles resolution, but we shouldn't ask it to ping internal/clearnet domains
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if not parsed.hostname or not parsed.hostname.endswith('.onion'):
        return False

    try:
        async with httpx.AsyncClient(proxy=TOR_PROXY, timeout=30.0) as client:
            response = await client.get(url)
            return response.status_code < 400
    except Exception:
        return False


async def _run_scan_cycle():
    """
    Runs a single scan cycle: fetches all links, pings them sequentially
    with a 3-second throttle between each, and updates status + timestamp.
    """
    links = await get_directory_links()
    total = len(links)
    logger.info(f"Fetcher: Starting scan cycle for {total} links.")

    for i, link in enumerate(links, 1):
        link = dict(link) if not isinstance(link, dict) else link
        url = link['url']
        link_id = link['id']
        name = link.get('name', '')

        # Blacklisted links are marked offline without pinging
        if is_suspicious(url, name):
            await update_link_status(link_id, False)
            await log_link_uptime(link_id, False)
            logger.debug(f"Fetcher: [{i}/{total}] Skipped (blacklisted): {url}")
        else:
            is_online = await ping_onion(url)
            await update_link_status(link_id, is_online)
            await log_link_uptime(link_id, is_online)
            status = "ONLINE" if is_online else "OFFLINE"
            logger.debug(f"Fetcher: [{i}/{total}] {status}: {url}")

        # 3-second throttle between each link
        if i < total:
            await asyncio.sleep(3)

    logger.info(f"Fetcher: Scan cycle complete. Checked {total} links.")


async def directory_ping_loop():
    """
    Background worker that pings all directory .onions every hour.
    Uses a lock to prevent overlapping scans if a cycle takes longer than expected.
    """
    # Initial delay to let Tor and DB initialize
    await asyncio.sleep(30)

    while True:
        if _scan_lock.locked():
            logger.warning("Fetcher: Previous scan still running, skipping this cycle.")
        else:
            async with _scan_lock:
                try:
                    await _run_scan_cycle()
                except Exception as e:
                    logger.error(f"Fetcher: Scan cycle error: {e}")

        # Sleep 40 minutes between cycles
        await asyncio.sleep(2400)
