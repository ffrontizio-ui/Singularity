import asyncio
import os
import uuid
import json
import time
import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from backend.crypto_engine import generate_mnemonic, derive_keys, sign_message, verify_signature
from backend.database import (
    init_db, create_post, get_posts, get_post, like_post, prune_old_posts, 
    is_banned, ban_user, get_directory_links, update_link_status, 
    vote_directory_link, get_directory_link_by_id, get_link_uptime_history, 
    get_online_mirror, check_vote_hash, record_vote_hash,
    get_or_create_user_btc_address
)
from backend.utils import verify_pow, strip_exif_and_save, check_banned_words, is_explicit_image
from backend.fetcher import directory_ping_loop, ping_onion, is_suspicious
from backend.crawler import crawler_loop

# === Security Constants ===
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5 MB
JPEG_MAGIC = b'\xff\xd8\xff'
PNG_MAGIC = b'\x89PNG\r\n\x1a\n'
WEBP_MAGIC = b'RIFF'

# Master BTC Public Key (BIP84) - Loaded from environment for privacy
BTC_ZPUB = os.environ.get("MASTER_BTC_ZPUB", "Zpub_Placeholder_Change_Me")
PROJECT_BTC_ADDRESS = os.environ.get("PROJECT_BTC_ADDRESS", "bc1q_placeholder_address")


# Daily rotating salt for vote hashing (rotates every 24h)
def _get_daily_salt() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")

# Background task for pruning old posts
async def run_pruner():
    while True:
        try:
            # Run every 24 hours
            await asyncio.sleep(86400)
            await prune_old_posts()
        except Exception:
            pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    tasks = [
        asyncio.create_task(run_pruner()),
        asyncio.create_task(directory_ping_loop()),
        asyncio.create_task(crawler_loop())
    ]
    yield
    # Shutdown
    for task in tasks:
        task.cancel()
    # Optional: wait for tasks to finish cancellation
    # await asyncio.gather(*tasks, return_exceptions=True)

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)

# Anonymity First: No IP logging / Override header stripping via middleware.
@app.middleware("http")
async def anonymity_middleware(request: Request, call_next):
    # Hide IP information from logs if we had custom logging, internally request.client.host is purely what it is.
    # In production with tor, it will be 127.0.0.1 anyway.
    response = await call_next(request)
    # Anonymity headers
    response.headers["Server"] = "Singularity/1.0"
    response.headers["X-Powered-By"] = "Unknown"
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    return response

# Mount statics
os.makedirs("static/uploads", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    posts = await get_posts()
    # Enrich posts with BTC addresses
    enriched_posts = []
    for post in posts:
        post_dict = dict(post)
        btc_addr = await get_or_create_user_btc_address(post_dict['public_key'], BTC_ZPUB)
        post_dict['btc_address'] = btc_addr
        enriched_posts.append(post_dict)
        
    return templates.TemplateResponse(
        request=request, 
        name="home.html", 
        context={"posts": enriched_posts, "project_address": PROJECT_BTC_ADDRESS}
    )

@app.get("/generate-seed", response_class=HTMLResponse)
async def seed_page(request: Request):
    seed = generate_mnemonic()
    return templates.TemplateResponse(
        request=request, 
        name="seed.html", 
        context={"seed": seed}
    )

@app.get("/help", response_class=HTMLResponse)
async def help_page(request: Request):
    return templates.TemplateResponse(
        request=request, 
        name="help.html", 
        context={}
    )

@app.get("/support", response_class=HTMLResponse)
async def support_page(request: Request, identity: str = None):
    address = None
    if identity:
        identity = identity.strip()
        # Check if it's a seed or a pubkey
        if len(identity.split()) >= 12:
            try:
                pub_key, _ = derive_keys(identity)
                address = await get_or_create_user_btc_address(pub_key, BTC_ZPUB)
            except Exception:
                pass
        else:
            address = await get_or_create_user_btc_address(identity, BTC_ZPUB)
            
    return templates.TemplateResponse(
        request=request, 
        name="support.html", 
        context={"identity": identity, "address": address, "project_address": PROJECT_BTC_ADDRESS}
    )

@app.get("/publish", response_class=HTMLResponse)
async def publish_page(request: Request):
    return templates.TemplateResponse(
        request=request, 
        name="publish.html", 
        context={}
    )

@app.post("/publish")
async def publish_post(
    request: Request,
    mnemonic: str = Form(...),
    content: str = Form(...),
    nonce: str = Form(...),
    location: str = Form(""),
    survival_time: str = Form("permanent"),
    image: UploadFile = File(None)
):
    content = content.replace("\r\n", "\n")
    
    # 1. Verify Proof of Work
    res = verify_pow(content, nonce)
        
    if not res:
        return templates.TemplateResponse(
            request=request, 
            name="error.html", 
            context={"error": "Invalid Proof of Work. Access Denied."}
        )
        
    # 2. Derive Identity from Mnemonic
    try:
        pub_b85, priv_b85 = derive_keys(mnemonic)
    except Exception:
        return templates.TemplateResponse(
            request=request, 
            name="error.html", 
            context={"error": "Invalid mnemonic seed provided."}
        )
        
    # Check if user is blacklisted
    if await is_banned(pub_b85):
        return templates.TemplateResponse(
            request=request, 
            name="error.html", 
            context={"error": "Your identity has been blacklisted from the grid."}
        )

    # 3. Handle Content Filters (Text)
    if check_banned_words(content):
        await ban_user(pub_b85, "Illegal content violation (Text)")
        return templates.TemplateResponse(
            request=request, 
            name="error.html", 
            context={"error": "Transmission rejected due to severe content policy violation. Your identity has been blacklisted."}
        )
    
    # 4. Handle Image Upload, Strip EXIF & Filter Explicit Content
    image_path = None
    if image and image.filename:
        # Check explicit extension block for non images if bypassed html accept
        if not image.filename.lower().endswith(('.jpg', '.jpeg', '.png', '.webp')):
             return templates.TemplateResponse(
                request=request, 
                name="error.html", 
                context={"error": "Videos and invalid files are strictly forbidden. Upload JPG, PNG, or WEBP only."}
            )

        ext = "jpg" # Enforce all to jpeg
        safe_name = f"{uuid.uuid4()}.{ext}"
        image_path = f"static/uploads/{safe_name}"
        file_bytes = await image.read()

        # VULN-01 FIX: Enforce file size limit
        if len(file_bytes) > MAX_UPLOAD_SIZE:
            return templates.TemplateResponse(
                request=request, 
                name="error.html", 
                context={"error": f"File too large. Maximum allowed: {MAX_UPLOAD_SIZE // (1024*1024)}MB."}
            )

        # VULN-11 FIX: Verify magic bytes (actual file content, not just extension)
        if not (file_bytes[:3] == JPEG_MAGIC or file_bytes[:8] == PNG_MAGIC or file_bytes[:4] == WEBP_MAGIC):
            return templates.TemplateResponse(
                request=request, 
                name="error.html", 
                context={"error": "Invalid image file. The file content does not match a valid JPEG, PNG, or WEBP image."}
            )
        try:
            strip_exif_and_save(file_bytes, image_path)
            # Run explicit content check
            if is_explicit_image(image_path):
                # Clean up offending file
                os.remove(image_path)
                await ban_user(pub_b85, "Illegal explicit content violation (Image)")
                return templates.TemplateResponse(
                    request=request, 
                    name="error.html", 
                    context={"error": "Transmission rejected. Explicit content detected. Your identity has been blacklisted."}
                )
        except Exception:
            return templates.TemplateResponse(
                request=request, 
                name="error.html", 
                context={"error": "Failed to process image. Ensure it's a valid format."}
            )

    # 5. Calculate Expiry Date
    expiry_date_str = None
    if survival_time == "1_hour":
        expiry_date_str = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    elif survival_time == "24_hours":
        expiry_date_str = (datetime.now(timezone.utc) + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    elif survival_time == "7_days":
        expiry_date_str = (datetime.now(timezone.utc) + timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")

    # 6. Sign Content
    # We sign the content to ensure it wasn't tampered with.
    try:
        signature = sign_message(priv_b85, content.encode('utf-8'))
    except Exception:
        return templates.TemplateResponse(
            request=request, 
            name="error.html", 
            context={"error": "Failed to digitally sign transmission."}
        )
        
    clean_loc = location.strip() if location else None
    
    # 7. Store securely
    try:
        await create_post(pub_b85, content, image_path, signature, clean_loc, expiry_date_str)
    except Exception:
        return templates.TemplateResponse(
            request=request, 
            name="error.html", 
            context={"error": "Internal Grid Error. Please try again later."}
        )
        
    return RedirectResponse(url="/", status_code=303)

@app.post("/like/{post_id}")
async def like_action(request: Request, response: Response, post_id: str):
    # Session tracking using Anonymous Cookies
    liked_cookie = request.cookies.get("session_likes", "{}")
    try:
        liked_posts = json.loads(liked_cookie)
    except Exception:
        liked_posts = {}
    
    now = datetime.now(timezone.utc).timestamp()
    if post_id in liked_posts:
        last_liked = liked_posts[post_id]
        if now - last_liked < 3600: # 1 hour cooldown limit
            return JSONResponse(content={"success": False, "error": "Anti-Spam Shield: Allowed once per hour."})

    # VULN-04 FIX: Check post exists BEFORE incrementing
    post = await get_post(post_id)
    if not post:
         return JSONResponse(content={"success": False, "error": "Post not found."})

    # Increments like in SQLite
    await like_post(post_id)
    liked_posts[post_id] = now
         
    new_likes = post['likes'] + 1
    
    resp = JSONResponse(content={"success": True, "likes": new_likes})
    # Store session safely without deanonymizing the user (No IPs)
    resp.set_cookie(key="session_likes", value=json.dumps(liked_posts), httponly=True, max_age=3600, samesite='strict')
    return resp

@app.get("/export", response_class=HTMLResponse)
async def export_page(request: Request):
    return templates.TemplateResponse("export.html", {"request": request})

@app.post("/export")
async def process_export(request: Request, mnemonic: str = Form(...)):
    try:
        pub_b85, priv_b85 = derive_keys(mnemonic)
    except Exception:
        return templates.TemplateResponse("export.html", {"request": request, "error": "Invalid Seed provided."})

    import aiosqlite
    from backend.database import DB_PATH
    
    user_posts = []
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT id, public_key, content, image_path, signature, created_at, likes, location, expiry_date FROM posts WHERE public_key = ? ORDER BY created_at DESC", (pub_b85,)) as cursor:
            rows = await cursor.fetchall()
            for row in rows:
                p = dict(row)
                user_posts.append(p)
                
    if not user_posts:
         return templates.TemplateResponse("export.html", {"request": request, "error": "No transmissions found for this Identity."})

    json_data = json.dumps(user_posts, indent=4)
    
    # Return as downloadable JSON file
    return Response(
        content=json_data, 
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=singularity_export_{pub_b85[:8]}.json"}
    )

@app.get("/tools", response_class=HTMLResponse)
async def tools_page(request: Request):
    return templates.TemplateResponse("tools.html", {"request": request})

async def get_categorized_links():
    FAMOUS_NAMES = ["ahmia", "torch", "duckduckgo", "new york times", "bbc", "propublica", "cia", "proton", "facebook", "hidden wiki"]
    links_raw = await get_directory_links()
    
    from collections import OrderedDict
    categorized = OrderedDict()
    
    for link in links_raw:
        l = dict(link)
        is_famous = any(f in l['name'].lower() for f in FAMOUS_NAMES)
        
        # Filtering Rules: Show if Online, OR if Offline but Famous
        if l['is_online'] or is_famous:
            cat = str(l.get('category') or 'Uncategorized').strip()
            if cat not in categorized:
                categorized[cat] = []
            
            # Default vote values if missing from old DB structure
            l['upvotes'] = l.get('upvotes', 0) or 0
            l['downvotes'] = l.get('downvotes', 0) or 0
            
            # Scam/High Risk detection logic
            total_votes = l['upvotes'] + l['downvotes']
            if l['downvotes'] >= 5 and total_votes > 0:
                if (l['downvotes'] / total_votes) > 0.6:
                    l['is_high_risk'] = True

            # Auto-tag user contributed links
            if cat in ["Unverified", "New/Unverified"]:
                l['is_unverified'] = True
                
            categorized[cat].append(l)
    return categorized

@app.get("/directory", response_class=HTMLResponse)
async def directory_page(request: Request):
    categorized = await get_categorized_links()
    return templates.TemplateResponse("directory.html", {
        "request": request, 
        "categorized": categorized
    })

@app.post("/directory/submit", response_class=HTMLResponse)
async def directory_submit(request: Request, name: str = Form(...), url: str = Form(...), nonce: str = Form("")):
    name = name.strip()
    url = url.strip()

    # VULN-03 FIX: Require Proof of Work to prevent spam
    if not nonce or not verify_pow(name + url, nonce, difficulty=3):
        categorized = await get_categorized_links()
        return templates.TemplateResponse("directory.html", {"request": request, "categorized": categorized, "error": "Invalid Proof of Work. Please wait for PoW calculation to complete."})
    
    # 1. Check uniqueness and status
    links_raw = await get_directory_links()
    link_obj = next((l for l in links_raw if l['url'].strip().lower() == url.lower()), None)
    
    if link_obj and link_obj['is_online']:
        categorized = await get_categorized_links()
        return templates.TemplateResponse("directory.html", {"request": request, "categorized": categorized, "error": "This link already exists and is currently online. Duplicate rejected."})

    # 2. Check blacklist
    if is_suspicious(url, name):
        categorized = await get_categorized_links()
        return templates.TemplateResponse("directory.html", {"request": request, "categorized": categorized, "error": "This link is prohibited by our community standards."})

    # 3. Verify via Tor
    is_working = await ping_onion(url)
    if not is_working:
        categorized = await get_categorized_links()
        return templates.TemplateResponse("directory.html", {"request": request, "categorized": categorized, "error": "Verification Failed: The link is currently unreachable. Only responding links can be added."})
         
    # 4. Insert or Update DB
    if link_obj:
        # If it was offline but we just proved it works
        await update_link_status(link_obj['id'], True)
    else:
        import aiosqlite
        from backend.database import DB_PATH
        async with aiosqlite.connect(DB_PATH) as conn:
            try:
                await conn.execute(
                    "INSERT INTO directory_links (name, url, category, is_online, last_checked) VALUES (?, ?, ?, 1, datetime('now', 'utc'))",
                    (name, url, "New/Unverified")
                )
                await conn.commit()
            except aiosqlite.IntegrityError:
                pass

    categorized = await get_categorized_links()
    return templates.TemplateResponse("directory.html", {"request": request, "categorized": categorized, "success": "Link verified and added successfully!"})
         
@app.post("/directory/vote/{link_id}")
async def vote_link(request: Request, response: Response, link_id: int, vote: int = Form(...), nonce: str = Form(...)):
    # 1. Verify PoW to prevent spam scripts (difficulty 3)
    if not verify_pow(str(link_id), nonce, difficulty=3):
        return JSONResponse(status_code=400, content={"error": "Invalid Proof of Work"})

    if vote not in [1, -1]:
        return JSONResponse(status_code=400, content={"error": "Invalid vote value"})

    # VULN-02 FIX: Server-side vote tracking using hashed fingerprint
    user_agent = request.headers.get("user-agent", "unknown")
    daily_salt = _get_daily_salt()
    vote_fingerprint = hashlib.sha256(f"{link_id}:{user_agent}:{daily_salt}".encode()).hexdigest()
    
    if await check_vote_hash(vote_fingerprint):
        return JSONResponse(status_code=400, content={"error": "You have already voted on this link today."})

    # Also check cookie as secondary layer
    voted_cookie = request.cookies.get("session_dir_votes", "{}")
    try:
        voted_links = json.loads(voted_cookie)
    except Exception:
        voted_links = {}

    str_id = str(link_id)
    if str_id in voted_links:
        return JSONResponse(status_code=400, content={"error": "You have already voted on this link"})

    # 3. Add vote to DB
    await vote_directory_link(link_id, vote)

    # 4. Record vote hash server-side
    await record_vote_hash(vote_fingerprint)

    # 5. Also mark in cookie as UX hint
    voted_links[str_id] = vote

    resp = JSONResponse(content={"success": True})
    resp.set_cookie(key="session_dir_votes", value=json.dumps(voted_links), httponly=True, max_age=86400 * 30, samesite='strict')
    return resp

@app.get("/preview/{link_id}", response_class=HTMLResponse)
async def link_preview(request: Request, link_id: int):
    link = await get_directory_link_by_id(link_id)
    if not link:
        return templates.TemplateResponse("error.html", {"request": request, "error": "Platform not found in directory."})

    mirror_activated = False
    
    # Mirror Auto-Switch Logic
    if not link['is_online']:
        mirror = await get_online_mirror(link['name'], link_id)
        if mirror:
            mirror_activated = True
            link = mirror
            link_id = link['id']
            
    uptime_history = await get_link_uptime_history(link_id)

    import httpx
    import aiofiles

    os.makedirs("static/previews", exist_ok=True)
    img_path = f"static/previews/{link_id}.jpg"
    data_path = f"static/previews/{link_id}.json"

    warnings = []
    headers_intel = {}
    pgp_key = None
    has_screenshot = False

    # Cache mechanism with 1-hour TTL
    CACHE_TTL = 3600  # 1 hour in seconds
    cache_is_fresh = False
    if os.path.exists(img_path) and os.path.exists(data_path):
        cache_age = time.time() - os.path.getmtime(data_path)
        if cache_age < CACHE_TTL:
            cache_is_fresh = True

    if cache_is_fresh:
        has_screenshot = True
        try:
            async with aiofiles.open(data_path, mode="r") as f:
                cache_data = json.loads(await f.read())
                if isinstance(cache_data, list):
                    warnings = cache_data
                else:
                    warnings = cache_data.get("warnings", [])
                    headers_intel = cache_data.get("headers_intel", {})
                    pgp_key = cache_data.get("pgp_key")
        except Exception:
            warnings = []
    else:
        # Fetch from previewer microservice inside docker network
        previewer_url = os.environ.get("PREVIEWER_URL", "http://previewer:8001")
        target_url = link['url']
        if not target_url.startswith("http"):
             target_url = "http://" + target_url

        try:
            async with httpx.AsyncClient(timeout=40.0) as client:
                res = await client.get(f"{previewer_url}/capture", params={"url": target_url})
                if res.status_code == 200:
                    data = res.json()
                    if data.get("success"):
                        import base64
                        img_bytes = base64.b64decode(data["screenshot"])
                        async with aiofiles.open(img_path, mode="wb") as f:
                            await f.write(img_bytes)
                            
                        warnings = data.get("warnings", [])
                        headers_intel = data.get("headers_intel", {})
                        pgp_key = data.get("pgp_key")
                        
                        cache_data = {
                            "warnings": warnings,
                            "headers_intel": headers_intel,
                            "pgp_key": pgp_key
                        }
                        
                        async with aiofiles.open(data_path, mode="w") as f:
                            await f.write(json.dumps(cache_data))
                        
                        has_screenshot = True
                    else:
                        warnings = [f"Cannot reach site: {data.get('error', 'Unknown Error')}"]
        except Exception:
            warnings = ["Preview service temporarily unavailable. Please try again later."]
            
    return templates.TemplateResponse("preview.html", {
        "request": request, 
        "link": link,
        "has_screenshot": has_screenshot,
        "warnings": warnings,
        "headers_intel": headers_intel,
        "pgp_key": pgp_key,
        "img_url": f"/static/previews/{link_id}.jpg" if has_screenshot else None,
        "mirror_activated": mirror_activated,
        "uptime_history": uptime_history
    })

