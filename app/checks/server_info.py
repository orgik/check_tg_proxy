import asyncio
import socket
import json
from urllib.request import urlopen, Request
from urllib.error import URLError

_checker_info: dict | None = None


async def get_server_info(host: str, port: int) -> dict:
    ip = await _resolve_host(host)
    if not ip:
        return {"ip": None, "error": "DNS resolution failed"}

    ip_info, reverse_dns = await asyncio.gather(
        _fetch_ip_info(ip),
        _reverse_dns(ip),
    )

    result = {
        "ip": ip,
        "reverse_dns": reverse_dns,
        "country": ip_info.get("country"),
        "country_code": ip_info.get("countryCode"),
        "region": ip_info.get("regionName"),
        "city": ip_info.get("city"),
        "isp": ip_info.get("isp"),
        "org": ip_info.get("org"),
        "as_number": ip_info.get("as"),
        "hosting": ip_info.get("hosting", False),
        "proxy": ip_info.get("proxy", False),
    }

    return result


async def get_checker_info() -> dict:
    global _checker_info
    if _checker_info is not None:
        return _checker_info

    info = await _fetch_ip_info_self()
    _checker_info = {
        "ip": info.get("query"),
        "country": info.get("country"),
        "country_code": info.get("countryCode"),
        "region": info.get("regionName"),
        "city": info.get("city"),
        "isp": info.get("isp"),
        "org": info.get("org"),
        "as_number": info.get("as"),
    }
    return _checker_info


async def _resolve_host(host: str) -> str | None:
    loop = asyncio.get_event_loop()
    try:
        results = await loop.getaddrinfo(host, None, family=socket.AF_INET)
        if results:
            return results[0][4][0]
    except Exception:
        pass
    return None


async def _reverse_dns(ip: str) -> str | None:
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip)),
            timeout=5,
        )
        return result[0]
    except Exception:
        return None


async def _fetch_ip_info(ip: str) -> dict:
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, lambda: _http_get_json(
                f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,hosting,proxy,query"
            )),
            timeout=10,
        )
    except Exception:
        return {}


async def _fetch_ip_info_self() -> dict:
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, lambda: _http_get_json(
                "http://ip-api.com/json/?fields=status,country,countryCode,regionName,city,isp,org,as,query"
            )),
            timeout=10,
        )
    except Exception:
        return {}


def _http_get_json(url: str) -> dict:
    req = Request(url, headers={"User-Agent": "TGProxyChecker/1.0"})
    with urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode())
