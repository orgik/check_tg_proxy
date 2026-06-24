import asyncio
import ssl
import time


def _classify_tcp_error(e: Exception) -> str:
    msg = str(e).lower()
    if isinstance(e, asyncio.TimeoutError):
        return "timeout"
    if isinstance(e, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(e, ConnectionResetError) or "reset" in msg:
        return "connection_reset"
    if "unreachable" in msg or "network" in msg:
        return "network_unreachable"
    if "no route" in msg:
        return "no_route"
    if "name or service not known" in msg or "getaddrinfo" in msg:
        return "dns_error"
    return str(e)


def _classify_tls_error(e: Exception) -> str:
    msg = str(e).lower()
    if isinstance(e, asyncio.TimeoutError):
        return "timeout"
    if isinstance(e, ConnectionResetError) or "reset" in msg:
        return "connection_reset"
    if isinstance(e, ssl.SSLError):
        if "eof" in msg or "unexpected eof" in msg:
            return "unexpected_eof"
        if "handshake" in msg:
            return "handshake_failure"
        if "certificate" in msg:
            return "certificate_error"
        if "alert" in msg:
            return "tls_alert"
        return f"ssl_error: {e}"
    if isinstance(e, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(e, OSError) and ("timed out" in msg or "timeout" in msg):
        return "timeout"
    return str(e)


async def check_tcp(host: str, port: int, timeout: float = 10) -> dict:
    start = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        rtt = (time.monotonic() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return {"success": True, "rtt_ms": round(rtt, 1), "error": None, "error_type": None}
    except Exception as e:
        return {
            "success": False, "rtt_ms": 0,
            "error": str(e),
            "error_type": _classify_tcp_error(e),
        }


async def check_tls(host: str, port: int, sni: str, timeout: float = 10) -> dict:
    if not sni:
        return {"success": None, "rtt_ms": 0, "error": "no SNI available", "error_type": None}

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
        return {"success": True, "rtt_ms": round(rtt, 1), "error": None, "error_type": None}
    except Exception as e:
        return {
            "success": False, "rtt_ms": 0,
            "error": str(e),
            "error_type": _classify_tls_error(e),
        }
