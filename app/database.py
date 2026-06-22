import aiosqlite
import json
import os
from pathlib import Path
from app.config import DATABASE_PATH

_db: aiosqlite.Connection | None = None


async def get_db() -> aiosqlite.Connection:
    global _db
    if _db is None:
        Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
        _db = await aiosqlite.connect(DATABASE_PATH)
        _db.row_factory = aiosqlite.Row
        await _db.execute("PRAGMA journal_mode=WAL")
        await _db.execute("PRAGMA foreign_keys=ON")
    return _db


async def init_db():
    db = await get_db()
    await db.execute("""
        CREATE TABLE IF NOT EXISTS checks (
            id TEXT PRIMARY KEY,
            proxy_link TEXT NOT NULL,
            server TEXT NOT NULL,
            port INTEGER NOT NULL,
            sni TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            tcp_result TEXT,
            tls_result TEXT,
            fingerprint_results TEXT,
            server_info TEXT,
            error_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            ip_address TEXT DEFAULT ''
        )
    """)
    await db.execute("CREATE INDEX IF NOT EXISTS idx_checks_created ON checks(created_at DESC)")
    await db.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    try:
        await db.execute("ALTER TABLE checks ADD COLUMN server_info TEXT")
    except Exception:
        pass
    await db.commit()


async def save_check(check_id: str, proxy_link: str, server: str, port: int, sni: str, ip_address: str):
    db = await get_db()
    await db.execute(
        "INSERT INTO checks (id, proxy_link, server, port, sni, status, ip_address) VALUES (?, ?, ?, ?, ?, 'pending', ?)",
        (check_id, proxy_link, server, port, sni, ip_address),
    )
    await db.commit()


async def update_check_result(check_id: str, status: str, tcp_result=None, tls_result=None,
                               fingerprint_results=None, server_info=None, error_message=None):
    db = await get_db()
    await db.execute(
        """UPDATE checks SET status=?, tcp_result=?, tls_result=?, fingerprint_results=?,
           server_info=?, error_message=?, completed_at=CURRENT_TIMESTAMP WHERE id=?""",
        (
            status,
            json.dumps(tcp_result) if tcp_result else None,
            json.dumps(tls_result) if tls_result else None,
            json.dumps(fingerprint_results) if fingerprint_results else None,
            json.dumps(server_info) if server_info else None,
            error_message,
            check_id,
        ),
    )
    await db.commit()


async def get_check(check_id: str) -> dict | None:
    db = await get_db()
    cursor = await db.execute("SELECT * FROM checks WHERE id=?", (check_id,))
    row = await cursor.fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


async def get_checks(page: int = 1, per_page: int = 20, status_filter: str = "",
                     search: str = "") -> tuple[list[dict], int]:
    db = await get_db()
    conditions = []
    params = []
    if status_filter:
        conditions.append("status = ?")
        params.append(status_filter)
    if search:
        conditions.append("(proxy_link LIKE ? OR server LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    cursor = await db.execute(f"SELECT COUNT(*) FROM checks {where}", params)
    row = await cursor.fetchone()
    total = row[0]

    params_page = params + [per_page, (page - 1) * per_page]
    cursor = await db.execute(
        f"SELECT * FROM checks {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params_page,
    )
    rows = await cursor.fetchall()
    return [_row_to_dict(r) for r in rows], total


async def get_stats() -> dict:
    db = await get_db()
    cursor = await db.execute("SELECT COUNT(*) FROM checks")
    total = (await cursor.fetchone())[0]
    cursor = await db.execute("SELECT COUNT(*) FROM checks WHERE status='completed'")
    completed = (await cursor.fetchone())[0]
    cursor = await db.execute("SELECT COUNT(*) FROM checks WHERE date(created_at)=date('now')")
    today = (await cursor.fetchone())[0]
    cursor = await db.execute(
        "SELECT COUNT(*) FROM checks WHERE status='completed' AND json_extract(tcp_result, '$.success')=1"
    )
    tcp_ok = (await cursor.fetchone())[0]
    return {"total": total, "completed": completed, "today": today, "tcp_ok": tcp_ok}


async def get_setting(key: str) -> str | None:
    db = await get_db()
    cursor = await db.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = await cursor.fetchone()
    return row[0] if row else None


async def set_setting(key: str, value: str):
    db = await get_db()
    await db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    await db.commit()


async def close_db():
    global _db
    if _db:
        await _db.close()
        _db = None


def _row_to_dict(row) -> dict:
    d = dict(row)
    for key in ("tcp_result", "tls_result", "fingerprint_results", "server_info"):
        if d.get(key):
            d[key] = json.loads(d[key])
    return d
