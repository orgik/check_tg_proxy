import asyncio
import time
from uuid import uuid4

from app.config import MAX_CONCURRENT_CHECKS
from app.checks.tcp_tls_check import check_tcp, check_tls
from app.checks.fingerprint_check import run_all_fingerprint_checks
from app.checks.server_info import get_server_info, get_checker_info
from app.checks.diagnostics import check_tls_certificate, check_stability, check_dpi, check_dns
from app.checks.mtproto_check import check_mtproto
from app.proxy_parser import parse_proxy_link
from app import database

_semaphore: asyncio.Semaphore | None = None
_tasks: dict[str, dict] = {}
_subscribers: dict[str, list[asyncio.Queue]] = {}


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    return _semaphore


def _notify(task_id: str):
    task = _tasks.get(task_id)
    if not task:
        return
    for q in _subscribers.get(task_id, []):
        q.put_nowait(dict(task))


def subscribe(task_id: str) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue()
    _subscribers.setdefault(task_id, []).append(q)
    if task_id in _tasks:
        q.put_nowait(dict(_tasks[task_id]))
    return q


def unsubscribe(task_id: str, q: asyncio.Queue):
    subs = _subscribers.get(task_id, [])
    if q in subs:
        subs.remove(q)
    if not subs and task_id in _subscribers:
        del _subscribers[task_id]


def get_queue_position(task_id: str) -> int | None:
    task = _tasks.get(task_id)
    if not task or task["status"] != "queued":
        return None
    pos = 0
    for t in _tasks.values():
        if t["status"] == "queued" and t["created_at"] < task["created_at"]:
            pos += 1
    return pos + 1


async def submit_check(proxy_link: str, ip_address: str = "", safe_mode: bool = False) -> tuple[str, dict]:
    server, port, sni, secret_hex, proxy_mode = parse_proxy_link(proxy_link)

    task_id = str(uuid4())
    task = {
        "task_id": task_id,
        "proxy_link": proxy_link,
        "server": server,
        "port": port,
        "sni": sni,
        "secret_hex": secret_hex,
        "proxy_mode": proxy_mode,
        "safe_mode": safe_mode,
        "status": "queued",
        "results": None,
        "error": None,
        "created_at": time.time(),
    }
    _tasks[task_id] = task

    await database.save_check(task_id, proxy_link, server, port, sni, ip_address)
    _notify(task_id)

    asyncio.create_task(_execute(task_id))
    return task_id, {"server": server, "port": port, "sni": sni}


async def _execute(task_id: str):
    task = _tasks.get(task_id)
    if not task:
        return

    sem = _get_semaphore()
    async with sem:
        task["status"] = "running"
        _notify(task_id)

        server = task["server"]
        port = task["port"]
        sni = task["sni"]
        secret_hex = task.get("secret_hex", "")
        proxy_mode = task.get("proxy_mode", "unknown")

        safe = task.get("safe_mode", False)
        delay = 2.0 if safe else 0

        async def _safe_delay():
            if delay:
                await asyncio.sleep(delay)

        try:
            if safe:
                server_info, checker_info, dns_check = await asyncio.gather(
                    get_server_info(server, port),
                    get_checker_info(),
                    check_dns(server),
                )
                tcp_result = await check_tcp(server, port)
                await _safe_delay()
                mtproto_result = None
                if secret_hex:
                    mtproto_result = await check_mtproto(server, port, secret_hex)
                    await _safe_delay()
                tls_result = await check_tls(server, port, sni)
                await _safe_delay()
                tls_cert = await check_tls_certificate(server, port, sni)
                await _safe_delay()
                fingerprint_results = await run_all_fingerprint_checks(server, port, sni, delay=delay)
                stability = await check_stability(server, port, delay=delay)
                dpi = await check_dpi(server, port, sni, delay=delay)
            else:
                tcp_result, server_info, checker_info, dns_check = await asyncio.gather(
                    check_tcp(server, port),
                    get_server_info(server, port),
                    get_checker_info(),
                    check_dns(server),
                )
                mtproto_result = None
                if secret_hex:
                    mtproto_result = await check_mtproto(server, port, secret_hex)
                tls_result, fingerprint_results = await asyncio.gather(
                    check_tls(server, port, sni),
                    run_all_fingerprint_checks(server, port, sni),
                )
                tls_cert, stability, dpi = await asyncio.gather(
                    check_tls_certificate(server, port, sni),
                    check_stability(server, port),
                    check_dpi(server, port, sni),
                )

            fp_pass = sum(1 for f in fingerprint_results if f["success"])
            fp_total = len(fingerprint_results)

            if mtproto_result and mtproto_result.get("success"):
                if fp_total == 0 or fp_pass == fp_total:
                    overall = "healthy"
                elif fp_pass > 0:
                    overall = "degraded"
                else:
                    overall = "degraded"
            elif tcp_result["success"] and (tls_result.get("success") is True or tls_result.get("success") is None):
                if fp_total == 0 or fp_pass == fp_total:
                    overall = "healthy"
                else:
                    overall = "degraded"
            else:
                overall = "unhealthy"

            results = {
                "server": server,
                "port": port,
                "sni": sni,
                "proxy_mode": proxy_mode,
                "tcp": tcp_result,
                "tls": tls_result,
                "mtproto": mtproto_result,
                "fingerprints": fingerprint_results,
                "server_info": server_info,
                "checker_info": checker_info,
                "tls_cert": tls_cert,
                "stability": stability,
                "dpi": dpi,
                "dns": dns_check,
                "overall_status": overall,
            }

            task["status"] = "completed"
            task["results"] = results
            await database.update_check_result(
                task_id, "completed",
                tcp_result=tcp_result,
                tls_result=tls_result,
                fingerprint_results=fingerprint_results,
                server_info=server_info,
                full_results=results,
            )
        except Exception as e:
            task["status"] = "failed"
            task["error"] = str(e)
            await database.update_check_result(task_id, "failed", error_message=str(e))

        _notify(task_id)


def get_task(task_id: str) -> dict | None:
    return _tasks.get(task_id)


async def cleanup_old_tasks(max_age_seconds: int = 3600):
    now = time.time()
    to_remove = [
        tid for tid, t in _tasks.items()
        if now - t["created_at"] > max_age_seconds and t["status"] in ("completed", "failed")
    ]
    for tid in to_remove:
        del _tasks[tid]
        _subscribers.pop(tid, None)
