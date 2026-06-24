import asyncio
import json
import socket
import time
from urllib.request import urlopen, Request
from urllib.error import URLError

from app.config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, SHODAN_API_KEY

RBL_SERVERS = [
    ("zen.spamhaus.org", "Spamhaus"),
    ("b.barracudacentral.org", "Barracuda"),
    ("bl.spamcop.net", "SpamCop"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("dnsbl-1.uceprotect.net", "UCEPROTECT"),
]

_vt_last_call = 0.0
_vt_lock: asyncio.Lock | None = None
_shodan_last_call = 0.0
_shodan_lock: asyncio.Lock | None = None


def _get_vt_lock() -> asyncio.Lock:
    global _vt_lock
    if _vt_lock is None:
        _vt_lock = asyncio.Lock()
    return _vt_lock


def _get_shodan_lock() -> asyncio.Lock:
    global _shodan_lock
    if _shodan_lock is None:
        _shodan_lock = asyncio.Lock()
    return _shodan_lock


def _http_get_json_with_headers(url: str, headers: dict) -> dict:
    h = {"User-Agent": "TGProxyChecker/1.0"}
    h.update(headers)
    req = Request(url, headers=h)
    with urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode())


async def _check_rbl(ip: str) -> dict:
    parts = ip.split(".")
    if len(parts) != 4:
        return {"available": False, "checked": 0, "listed_count": 0, "listed_on": []}
    reversed_ip = ".".join(reversed(parts))

    async def _check_one(server: str, name: str) -> dict:
        query = f"{reversed_ip}.{server}"
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.getaddrinfo(query, None, family=socket.AF_INET),
                timeout=5,
            )
            return {"server": name, "listed": bool(result)}
        except (socket.gaierror, OSError):
            return {"server": name, "listed": False}
        except Exception:
            return {"server": name, "listed": False}

    results = await asyncio.gather(
        *[_check_one(srv, name) for srv, name in RBL_SERVERS]
    )
    listed = [r["server"] for r in results if r["listed"]]
    return {
        "available": True,
        "checked": len(RBL_SERVERS),
        "listed_count": len(listed),
        "listed_on": listed,
        "details": results,
    }


async def _check_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"available": False}
    loop = asyncio.get_event_loop()
    try:
        data = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: _http_get_json_with_headers(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            )),
            timeout=10,
        )
        d = data.get("data", {})
        return {
            "available": True,
            "abuse_confidence": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "usage_type": d.get("usageType"),
            "is_tor": d.get("isTor", False),
            "domain": d.get("domain"),
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


async def _check_virustotal(ip: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"available": False}

    global _vt_last_call
    lock = _get_vt_lock()
    async with lock:
        now = time.monotonic()
        if now - _vt_last_call < 15:
            return {"available": False, "error": "rate_limited"}
        _vt_last_call = now

    loop = asyncio.get_event_loop()
    try:
        data = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: _http_get_json_with_headers(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                {"x-apikey": VIRUSTOTAL_API_KEY},
            )),
            timeout=10,
        )
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "available": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "network": attrs.get("network", ""),
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


async def _check_shodan(ip: str) -> dict:
    if not SHODAN_API_KEY:
        return {"available": False}

    global _shodan_last_call
    lock = _get_shodan_lock()
    async with lock:
        now = time.monotonic()
        if now - _shodan_last_call < 1:
            await asyncio.sleep(1 - (now - _shodan_last_call))
        _shodan_last_call = time.monotonic()

    loop = asyncio.get_event_loop()
    try:
        data = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: _http_get_json_with_headers(
                f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}",
                {},
            )),
            timeout=10,
        )
        return {
            "available": True,
            "open_ports": data.get("ports", []),
            "vulns": data.get("vulns", [])[:10],
            "tags": data.get("tags", []),
            "os": data.get("os"),
            "isp": data.get("isp", ""),
            "last_update": data.get("last_update", ""),
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


def _calculate_risk(reputation: dict) -> str:
    score = 0
    abuse = reputation.get("abuseipdb", {})
    if abuse.get("available"):
        if abuse.get("abuse_confidence", 0) > 50:
            score += 3
        elif abuse.get("abuse_confidence", 0) > 20:
            score += 1

    vt = reputation.get("virustotal", {})
    if vt.get("available"):
        if vt.get("malicious", 0) > 3:
            score += 3
        elif vt.get("malicious", 0) > 0:
            score += 1

    rbl = reputation.get("rbl", {})
    if rbl.get("listed_count", 0) > 2:
        score += 3
    elif rbl.get("listed_count", 0) > 0:
        score += 1

    shodan = reputation.get("shodan", {})
    if shodan.get("available") and len(shodan.get("vulns", [])) > 0:
        score += 2

    if score >= 5:
        return "high"
    elif score >= 2:
        return "medium"
    return "low"


async def check_ip_reputation(ip: str | None) -> dict:
    if not ip:
        return {}

    tasks = []
    task_names = []

    tasks.append(_check_rbl(ip))
    task_names.append("rbl")

    if ABUSEIPDB_API_KEY:
        tasks.append(_check_abuseipdb(ip))
        task_names.append("abuseipdb")

    if VIRUSTOTAL_API_KEY:
        tasks.append(_check_virustotal(ip))
        task_names.append("virustotal")

    if SHODAN_API_KEY:
        tasks.append(_check_shodan(ip))
        task_names.append("shodan")

    results = await asyncio.gather(*tasks, return_exceptions=True)

    reputation = {}
    for name, result in zip(task_names, results):
        if isinstance(result, Exception):
            reputation[name] = {"available": False, "error": str(result)}
        else:
            reputation[name] = result

    reputation["risk_level"] = _calculate_risk(reputation)
    return reputation
