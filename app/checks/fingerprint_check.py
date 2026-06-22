import asyncio
import secrets as secrets_mod
import time
from pathlib import Path

from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSServerHello
from scapy.layers.tls.extensions import ServerName

from app.config import CLIENT_HELLO_DIR

_client_hellos: list[dict] | None = None


def load_client_hellos() -> list[dict]:
    global _client_hellos
    if _client_hellos is not None:
        return _client_hellos

    _client_hellos = []
    hello_dir = Path(CLIENT_HELLO_DIR)
    if not hello_dir.exists():
        return _client_hellos

    for f in sorted(hello_dir.iterdir()):
        if f.is_file():
            raw = f.read_bytes()
            _client_hellos.append({"name": f.name, "raw": raw})

    return _client_hellos


def patch_sni(raw_payload: bytes, sni: str) -> bytes:
    tls_packet = TLS(raw_payload)
    client_hello = tls_packet.msg[0]
    for ext in client_hello.ext:
        if ext.name == "TLS Extension - Server Name":
            ext.servernames = [ServerName(servername=sni)]
            ext.len = None
            ext.servernameslen = None
    tls_packet.len = None
    client_hello.msglen = None
    client_hello.extlen = None
    return bytes(tls_packet)


def randomize_session_id(payload: bytes) -> bytes:
    tls_packet = TLS(payload)
    client_hello = tls_packet.msg[0]
    sidlen = client_hello.sidlen
    buf = list(payload)
    for i, b in enumerate(secrets_mod.token_bytes(sidlen)):
        buf[i + 44] = b
    return bytes(buf)


async def send_client_hello(payload: bytes, host: str, port: int, timeout: float = 10) -> bool:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout
    )
    try:
        writer.write(payload)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        tls_packet = TLS(data)
        return tls_packet.haslayer(TLSServerHello)
    finally:
        writer.close()
        await writer.wait_closed()


async def _check_single(patched: bytes, host: str, port: int) -> dict:
    start = time.monotonic()
    try:
        payload = randomize_session_id(patched)
        result = await send_client_hello(payload, host, port)
        duration = (time.monotonic() - start) * 1000
        return {"success": result, "duration_ms": round(duration, 1), "error": None}
    except asyncio.TimeoutError:
        return {"success": False, "duration_ms": 0, "error": "timeout"}
    except Exception as e:
        return {"success": False, "duration_ms": 0, "error": str(e)}


async def _check_parallel(patched: bytes, host: str, port: int, count: int = 5) -> dict:
    start = time.monotonic()
    try:
        tasks = []
        for _ in range(count):
            payload = randomize_session_id(patched)
            tasks.append(send_client_hello(payload, host, port))
        results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=30)
        duration = (time.monotonic() - start) * 1000
        all_ok = all(r is True for r in results)
        errors = list(set(str(r) for r in results if isinstance(r, Exception)))
        return {
            "success": all_ok,
            "duration_ms": round(duration, 1),
            "error": "; ".join(errors) if errors else None,
        }
    except asyncio.TimeoutError:
        return {"success": False, "duration_ms": 0, "error": "timeout"}
    except Exception as e:
        return {"success": False, "duration_ms": 0, "error": str(e)}


async def run_all_fingerprint_checks(host: str, port: int, sni: str) -> list[dict]:
    if not sni:
        return []

    hellos = load_client_hellos()
    if not hellos:
        return []

    prepared = []
    for hello in hellos:
        patched = patch_sni(hello["raw"], sni)
        prepared.append((hello["name"], patched))

    single_coros = [_check_single(p, host, port) for _, p in prepared]
    single_raw = await asyncio.gather(*single_coros, return_exceptions=True)

    parallel_sem = asyncio.Semaphore(2)

    async def _guarded_parallel(patched):
        async with parallel_sem:
            return await _check_parallel(patched, host, port)

    parallel_coros = [_guarded_parallel(p) for _, p in prepared]
    parallel_raw = await asyncio.gather(*parallel_coros, return_exceptions=True)

    results = []
    for i, (name, _) in enumerate(prepared):
        sr = single_raw[i]
        if isinstance(sr, Exception):
            sr = {"success": False, "duration_ms": 0, "error": str(sr)}
        results.append({"client_name": name, "mode": "single", **sr})

        pr = parallel_raw[i]
        if isinstance(pr, Exception):
            pr = {"success": False, "duration_ms": 0, "error": str(pr)}
        results.append({"client_name": name, "mode": "parallel", **pr})

    return results

