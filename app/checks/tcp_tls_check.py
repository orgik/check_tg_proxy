import asyncio
import ssl
import time


async def check_tcp(host: str, port: int, timeout: float = 10) -> dict:
    start = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        rtt = (time.monotonic() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return {"success": True, "rtt_ms": round(rtt, 1), "error": None}
    except asyncio.TimeoutError:
        return {"success": False, "rtt_ms": 0, "error": "timeout"}
    except Exception as e:
        return {"success": False, "rtt_ms": 0, "error": str(e)}


async def check_tls(host: str, port: int, sni: str, timeout: float = 10) -> dict:
    if not sni:
        return {"success": None, "rtt_ms": 0, "error": "no SNI available"}

    start = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni),
            timeout=timeout,
        )
        rtt = (time.monotonic() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return {"success": True, "rtt_ms": round(rtt, 1), "error": None}
    except asyncio.TimeoutError:
        return {"success": False, "rtt_ms": 0, "error": "timeout"}
    except Exception as e:
        return {"success": False, "rtt_ms": 0, "error": str(e)}
