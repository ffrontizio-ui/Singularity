import asyncio
import aiosqlite
import uuid
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta

DB_PATH = "singularity.db"

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        # WAL mode allows concurrent reads during writes — prevents 'database is locked'
        await db.execute("PRAGMA journal_mode=WAL;")

        await db.execute("""
            CREATE TABLE IF NOT EXISTS posts (
                id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                content TEXT,
                image_path TEXT,
                signature TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                likes INTEGER DEFAULT 0,
                location TEXT,
                expiry_date TIMESTAMP
            )
        """)
        # Add columns for existing DBs safely
        try:
            await db.execute("ALTER TABLE posts ADD COLUMN location TEXT")
        except Exception:
            pass
        try:
            await db.execute("ALTER TABLE posts ADD COLUMN expiry_date TIMESTAMP")
        except Exception:
            pass
        await db.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                public_key TEXT PRIMARY KEY,
                reason TEXT,
                banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS directory_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL UNIQUE,
                category TEXT,
                is_online BOOLEAN DEFAULT 0,
                last_checked TIMESTAMP,
                upvotes INTEGER DEFAULT 0,
                downvotes INTEGER DEFAULT 0
            )
        """)
        # Schema migration for existing DB
        try:
            await db.execute("ALTER TABLE directory_links ADD COLUMN upvotes INTEGER DEFAULT 0")
            await db.execute("ALTER TABLE directory_links ADD COLUMN downvotes INTEGER DEFAULT 0")
        except Exception:
            pass

        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_key TEXT UNIQUE NOT NULL,
                btc_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        await db.execute("""
            CREATE TABLE IF NOT EXISTS link_uptime_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id INTEGER NOT NULL,
                is_online BOOLEAN NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS vote_hashes (
                hash TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Prune old vote hashes (older than 7 days) on startup
        await db.execute("DELETE FROM vote_hashes WHERE created_at < datetime('now', '-7 days')")
        
        await db.commit()
    await _seed_directory()

async def _seed_directory():
    """Auto-seed directory only when the table is empty (fresh DB)."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM directory_links") as cursor:
            count = (await cursor.fetchone())[0]
            if count > 0:
                return  # Already seeded, skip

    initial_links = [
        ("Ahmia", "https://ahmia.fi", "Search Engines"),
        ("Torch", "xmh57jrknzkhv6y3ls3ubupt22n3uzjntpztr4d7dxfwps4z2ddzxxqd.onion", "Search Engines"),
        ("DuckDuckGo", "duckduckgogg42xjoc72x3sjiqbzzdaxacnmy3k7ptclymtzclj4yd.onion", "Search Engines"),
        ("The New York Times", "nytimesn7cgmftshazwhfgzm37qxb44r64ytbb2dj3x62d2lljsciiyd.onion", "News & Media"),
        ("BBC News", "bbcnewsd73jkber2jm5yp2hyr7xqa5n532srb2ya2jtmlr7gv7hpqqd.onion", "News & Media"),
        ("ProPublica", "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion", "News & Media"),
        ("CIA", "ciadotgov4s3v6ui52y83ndlj3hffm6t6n4fhhthcnh3c4yq4c4h7qhqyd.onion", "Official Services"),
        ("ProtonMail", "protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion", "Privacy Tools"),
        ("Facebook", "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion", "Privacy Tools"),
        ("The Hidden Wiki", "zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion", "Privacy Tools")
    ]
    async with aiosqlite.connect(DB_PATH) as db:
        for name, url, category in initial_links:
            await db.execute(
                "INSERT INTO directory_links (name, url, category, is_online, last_checked) VALUES (?, ?, ?, 0, datetime('now', 'utc'))",
                (name, url, category)
            )
        await db.commit()

async def ban_user(public_key: str, reason: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO blacklist (public_key, reason, banned_at) VALUES (?, ?, datetime('now', 'utc'))",
            (public_key, reason)
        )
        await db.commit()

async def is_banned(public_key: str) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT 1 FROM blacklist WHERE public_key = ?", (public_key,)) as cursor:
            row = await cursor.fetchone()
            return row is not None

async def create_post(public_key: str, content: str, image_path: str, signature: str, location: str = None, expiry_date: str = None) -> str:
    post_id = str(uuid.uuid4())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO posts (id, public_key, content, image_path, signature, location, expiry_date) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (post_id, public_key, content, image_path, signature, location, expiry_date)
        )
        await db.commit()
    return post_id

async def get_posts(limit: int = 50, offset: int = 0):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM posts ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        ) as cursor:
            return [dict(row) for row in await cursor.fetchall()]

async def get_post(post_id: str):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM posts WHERE id = ?", (post_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def like_post(post_id: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE posts SET likes = likes + 1 WHERE id = ?", (post_id,))
        await db.commit()

async def prune_old_posts():
    """
    Deletes posts where expiry_date < now, OR older than 30 days.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        # Get posts to delete to remove images
        async with db.execute("""
            SELECT id, image_path FROM posts 
            WHERE (expiry_date IS NOT NULL AND expiry_date <= datetime('now', 'utc'))
               OR (created_at <= datetime('now', '-30 days'))
        """) as cursor:
            async for row in cursor:
                 if row["image_path"] and os.path.exists(row["image_path"]):
                     os.remove(row["image_path"])

        await db.execute("""
            DELETE FROM posts 
            WHERE (expiry_date IS NOT NULL AND expiry_date <= datetime('now', 'utc'))
               OR (created_at <= datetime('now', '-30 days'))
        """)
        await db.commit()
        # Optimize size
        await db.execute("VACUUM")

async def get_directory_links():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM directory_links ORDER BY category, name") as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

async def update_link_status(link_id: int, is_online: bool):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE directory_links SET is_online = ?, last_checked = datetime('now', 'utc') WHERE id = ?",
            (1 if is_online else 0, link_id)
        )
        await db.commit()

async def add_directory_link(name: str, url: str, category: str):
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute(
                "INSERT INTO directory_links (name, url, category, is_online, last_checked) VALUES (?, ?, ?, 0, datetime('now', 'utc'))",
                (name, url, category)
            )
            await db.commit()
        except aiosqlite.IntegrityError:
            pass

async def vote_directory_link(link_id: int, vote: int):
    """
    Apply a vote. vote = 1 for upvote, -1 for downvote.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        if vote == 1:
            await db.execute("UPDATE directory_links SET upvotes = upvotes + 1 WHERE id = ?", (link_id,))
        elif vote == -1:
            await db.execute("UPDATE directory_links SET downvotes = downvotes + 1 WHERE id = ?", (link_id,))
        await db.commit()

async def get_directory_link_by_id(link_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM directory_links WHERE id = ?", (link_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def log_link_uptime(link_id: int, is_online: bool):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO link_uptime_logs (link_id, is_online, timestamp) VALUES (?, ?, datetime('now', 'utc'))",
            (link_id, 1 if is_online else 0)
        )
        # Prune logs older than 24h
        await db.execute("DELETE FROM link_uptime_logs WHERE timestamp < datetime('now', '-24 hours')")
        await db.commit()

async def get_link_uptime_history(link_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT is_online, timestamp FROM link_uptime_logs WHERE link_id = ? ORDER BY timestamp ASC", (link_id,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

async def get_online_mirror(name: str, avoid_link_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM directory_links WHERE name = ? AND id != ? AND is_online = 1 ORDER BY upvotes DESC LIMIT 1", (name, avoid_link_id)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def check_vote_hash(vote_hash: str) -> bool:
    """Check if a vote hash already exists (server-side anti-duplicate)."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT 1 FROM vote_hashes WHERE hash = ?", (vote_hash,)) as cursor:
            return (await cursor.fetchone()) is not None

async def record_vote_hash(vote_hash: str):
    """Record a vote hash to prevent future duplicates."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO vote_hashes (hash, created_at) VALUES (?, datetime('now', 'utc'))",
            (vote_hash,)
        )
        # Prune old hashes periodically
        await db.execute("DELETE FROM vote_hashes WHERE created_at < datetime('now', '-7 days')")
        await db.commit()

async def get_or_create_user_btc_address(public_key: str, zpub_str: str) -> str:
    """
    Returns the deterministic Bitcoin address for the user.
    If the user doesn't exist, it registers them, assigns an ID, generates the address, 
    and saves it to the DB so it is permanently mapped.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        # Check if address already exists
        async with db.execute("SELECT btc_address FROM users WHERE public_key = ?", (public_key,)) as cursor:
            row = await cursor.fetchone()
            if row and row[0]:
                return row[0]
                
        # If not, insert user
        await db.execute(
            "INSERT OR IGNORE INTO users (public_key) VALUES (?)",
            (public_key,)
        )
        await db.commit()
        
        # Get the assigned id
        async with db.execute("SELECT id FROM users WHERE public_key = ?", (public_key,)) as cursor:
            user_id = (await cursor.fetchone())[0]
            
        # HD Wallets usually start at index 0. User ID starts at 1. So index = user_id - 1
        index = user_id - 1
        
        # Generate BTC Address
        from backend.btc_generator import generate_receive_address
        new_address = generate_receive_address(zpub_str, index)
        
        # Save to DB
        await db.execute("UPDATE users SET btc_address = ? WHERE id = ?", (new_address, user_id))
        await db.commit()
        
        return new_address

