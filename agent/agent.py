#!/usr/bin/env python3
"""
TG Proxy Checker Agent
Connects to master server and executes proxy checks on demand.
Supports WebSocket (primary) and HTTP Polling (fallback).

Usage:
    python agent.py --master http://194.87.110.184 --token YOUR_TOKEN
"""

import argparse
import asyncio
import json
import os
import socket
import ssl
import struct
import hashlib
import secrets as secrets_mod
import sys
import time
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

try:
    import websockets
    HAS_WS = True
except ImportError:
    HAS_WS = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


CLIENT_HELLO_DIR = Path(__file__).parent / "client_hello"


def get_self_info():
    try:
        req = Request("http://ip-api.com/json/?fields=status,country,countryCode,regionName,city,isp,org,as,query",
                      headers={"User-Agent": "TGProxyAgent/1.0"})
        with urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
            return {
                "ip": data.get("query", ""),
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
            }
    except Exception:
        return {"ip": "", "country": "", "city": "", "isp": ""}


# ═══════════════════════════════════════════
#  CHECK FUNCTIONS (self-contained)
# ═══════════════════════════════════════════

def _classify_tcp_error(e):
    msg = str(e).lower()
    if isinstance(e, asyncio.TimeoutError): return "timeout"
    if isinstance(e, ConnectionRefusedError): return "connection_refused"
    if isinstance(e, ConnectionResetError) or "reset" in msg: return "connection_reset"
    if "unreachable" in msg or "network" in msg: return "network_unreachable"
    if "no route" in msg: return "no_route"
    if "name or service not known" in msg or "getaddrinfo" in msg: return "dns_error"
    return str(e)


def _classify_tls_error(e):
    msg = str(e).lower()
    if isinstance(e, asyncio.TimeoutError): return "timeout"
    if isinstance(e, ConnectionResetError) or "reset" in msg: return "connection_reset"
    if isinstance(e, ssl.SSLError):
        if "eof" in msg or "unexpected eof" in msg: return "unexpected_eof"
        if "handshake" in msg: return "handshake_failure"
        if "certificate" in msg: return "certificate_error"
        if "alert" in msg: return "tls_alert"
        return f"ssl_error: {e}"
    if isinstance(e, ConnectionRefusedError): return "connection_refused"
    if isinstance(e, OSError) and ("timed out" in msg or "timeout" in msg): return "timeout"
    return str(e)


async def check_tcp(host, port, timeout=10):
    start = time.monotonic()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        rtt = (time.monotonic() - start) * 1000
        w.close(); await w.wait_closed()
        return {"success": True, "rtt_ms": round(rtt, 1), "error": None, "error_type": None}
    except Exception as e:
        return {"success": False, "rtt_ms": 0, "error": str(e), "error_type": _classify_tcp_error(e)}


async def check_tls(host, port, sni, timeout=10):
    if not sni:
        return {"success": None, "rtt_ms": 0, "error": "no SNI available", "error_type": None}
    start = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni), timeout=timeout)
        rtt = (time.monotonic() - start) * 1000
        w.close(); await w.wait_closed()
        return {"success": True, "rtt_ms": round(rtt, 1), "error": None, "error_type": None}
    except Exception as e:
        return {"success": False, "rtt_ms": 0, "error": str(e), "error_type": _classify_tls_error(e)}


async def check_mtproto(host, port, secret_hex):
    start = time.monotonic()
    try:
        sb = bytes.fromhex(secret_hex)
    except ValueError:
        return {"success": False, "rtt_ms": 0, "error": "invalid secret"}
    if len(sb) < 17:
        return {"success": False, "rtt_ms": 0, "error": "secret too short"}
    tag, key_secret = sb[0], sb[1:17]
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
    except Exception as e:
        return {"success": False, "rtt_ms": 0, "error": str(e)}
    try:
        init = _build_init(key_secret, tag)
        writer.write(init)
        await writer.drain()
        crtt = (time.monotonic() - start) * 1000
        try:
            data = await asyncio.wait_for(reader.read(128), timeout=3)
            if data:
                return {"success": True, "rtt_ms": round(crtt, 1), "detail": "responded"}
            elapsed = (time.monotonic() - start) * 1000 - crtt
            if elapsed > 1000:
                return {"success": True, "rtt_ms": round(crtt, 1), "detail": "kept_alive"}
            return {"success": False, "rtt_ms": round(crtt, 1), "error": "connection closed", "detail": "closed"}
        except asyncio.TimeoutError:
            return {"success": True, "rtt_ms": round(crtt, 1), "detail": "kept_alive"}
    except ConnectionResetError:
        return {"success": False, "rtt_ms": round((time.monotonic()-start)*1000, 1), "error": "connection reset"}
    except Exception as e:
        return {"success": False, "rtt_ms": round((time.monotonic()-start)*1000, 1), "error": str(e)}
    finally:
        writer.close()
        await writer.wait_closed()


async def check_stability(host, port, count=10, delay=0):
    results = []
    pause = max(delay, 0.3)
    for i in range(count):
        start = time.monotonic()
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
            rtt = (time.monotonic() - start) * 1000
            w.close(); await w.wait_closed()
            results.append({"ok": True, "rtt_ms": round(rtt, 1)})
        except asyncio.TimeoutError:
            results.append({"ok": False, "rtt_ms": 0, "error": "timeout"})
        except Exception as e:
            results.append({"ok": False, "rtt_ms": 0, "error": str(e)})
        if i < count - 1:
            await asyncio.sleep(pause)

    success = sum(1 for r in results if r["ok"])
    rtts = [r["rtt_ms"] for r in results if r["ok"]]
    avg = round(sum(rtts)/len(rtts), 1) if rtts else 0
    mn = round(min(rtts), 1) if rtts else 0
    mx = round(max(rtts), 1) if rtts else 0
    first_fail = next((i+1 for i, r in enumerate(results) if not r["ok"]), None)
    pattern = "stable"
    if success == 0:
        all_refused = all("refused" in r.get("error","").lower() for r in results)
        pattern = "connection_refused" if all_refused else "blocked"
    elif success < count:
        pattern = "rate_limited" if first_fail and first_fail <= 3 else "unstable"
    return {"total": count, "success": success, "success_rate": round(success/count*100),
            "avg_rtt_ms": avg, "min_rtt_ms": mn, "max_rtt_ms": mx,
            "jitter_ms": round(mx-mn, 1) if rtts else 0, "pattern": pattern,
            "first_fail_at": first_fail, "details": results}


def _classify_dns_error(e):
    msg = str(e).lower()
    if isinstance(e, asyncio.TimeoutError) or "timed out" in msg: return "timeout"
    if "nxdomain" in msg or "name or service not known" in msg or "no address" in msg: return "nxdomain"
    if "servfail" in msg or "server fail" in msg: return "servfail"
    if "refused" in msg: return "refused"
    if "unreachable" in msg or "network" in msg: return "network_error"
    return str(e)


def _skip_dns_name(data, offset):
    while offset < len(data):
        length = data[offset]
        if length == 0: return offset + 1
        if (length & 0xC0) == 0xC0: return offset + 2
        offset += 1 + length
    return offset


def _resolve_via(host, dns_server):
    qname = b""
    for part in host.encode().split(b"."):
        qname += bytes([len(part)]) + part
    qname += b"\x00"
    tx_id = struct.pack("!H", 0x1234)
    header = tx_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    question = qname + struct.pack("!HH", 1, 1)
    packet = header + question
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(packet, (dns_server, 53))
        data, _ = sock.recvfrom(512)
        flags = struct.unpack("!H", data[2:4])[0]
        rcode = flags & 0x0F
        if rcode == 3: return {"error": "nxdomain"}
        if rcode == 2: return {"error": "servfail"}
        if rcode == 5: return {"error": "refused"}
        if rcode != 0: return {"error": f"dns_error_{rcode}"}
        ancount = struct.unpack("!H", data[6:8])[0]
        if ancount == 0: return None
        offset = 12
        offset = _skip_dns_name(data, offset)
        offset += 4
        ips = []
        for _ in range(ancount):
            if offset >= len(data): break
            offset = _skip_dns_name(data, offset)
            if offset + 10 > len(data): break
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            if rtype == 1 and rdlen == 4 and offset + 4 <= len(data):
                ips.append(socket.inet_ntoa(data[offset:offset + 4]))
            offset += rdlen
        return ips if ips else None
    except socket.timeout:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}
    finally:
        sock.close()


async def check_dns(host):
    if _is_ip(host):
        return {"direct_ip": True, "all_ips": [host], "consistent": True}
    loop = asyncio.get_event_loop()
    results = {}
    try:
        res = await loop.getaddrinfo(host, None, family=socket.AF_INET)
        ips = list(set(r[4][0] for r in res))
        results["system"] = {"ips": ips, "ok": True}
    except Exception as e:
        results["system"] = {"ips": [], "ok": False, "error": _classify_dns_error(e)}
    for name, dns_ip in [("google", "8.8.8.8"), ("cloudflare", "1.1.1.1")]:
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda d=dns_ip: _resolve_via(host, d)), timeout=5)
            if isinstance(result, dict) and "error" in result:
                results[name] = {"ips": [], "ok": False, "error": result["error"]}
            elif result:
                results[name] = {"ips": result if isinstance(result, list) else [result], "ok": True}
            else:
                results[name] = {"ips": [], "ok": False, "error": "nxdomain"}
        except asyncio.TimeoutError:
            results[name] = {"ips": [], "ok": False, "error": "timeout"}
        except Exception as e:
            results[name] = {"ips": [], "ok": False, "error": _classify_dns_error(e)}
    all_ips = set()
    for v in results.values():
        if isinstance(v, dict):
            all_ips.update(v.get("ips", []))
    results["consistent"] = len(all_ips) <= 1
    results["all_ips"] = sorted(all_ips)
    return results


def _is_ip(host):
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


async def check_tls_cert(host, port, sni):
    if not sni:
        return {"available": False, "error": "no SNI"}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni), timeout=10)
        ssl_obj = w.get_extra_info("ssl_object")
        cert_bin = ssl_obj.getpeercert(binary_form=True)
        tls_version = ssl_obj.version()
        cipher = ssl_obj.cipher()
        w.close(); await w.wait_closed()
        parsed = {}
        if cert_bin:
            try:
                from cryptography import x509
                from cryptography.x509.oid import NameOID
                cert = x509.load_der_x509_certificate(cert_bin)
                def fmt(name):
                    parts = []
                    for oid in [NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME, NameOID.COUNTRY_NAME]:
                        vals = name.get_attributes_for_oid(oid)
                        if vals: parts.append(vals[0].value)
                    return ", ".join(parts) if parts else name.rfc4514_string()
                san = []
                try:
                    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    san = ext.value.get_values_for_type(x509.DNSName)
                except x509.ExtensionNotFound:
                    pass
                parsed = {"subject": fmt(cert.subject), "issuer": fmt(cert.issuer),
                          "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M UTC"),
                          "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC"),
                          "san": san[:5]}
            except Exception:
                pass
        subject = parsed.get("subject", "")
        san = parsed.get("san", [])
        return {"available": True, "subject": subject, "issuer": parsed.get("issuer", ""),
                "not_before": parsed.get("not_before", ""), "not_after": parsed.get("not_after", ""),
                "san": san, "sni_match": sni in san or sni in subject,
                "tls_version": tls_version, "cipher_suite": cipher[0] if cipher else "",
                "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else 0}
    except Exception as e:
        return {"available": False, "error": str(e)}


SNI_PROFILES = [
    ("correct", None),
    ("cdn", "www.google.com"),
    ("nonexistent", "rand-check-8372.invalid"),
    ("empty", ""),
]


async def check_dpi(host, port, sni, delay=0):
    result = {}
    if sni:
        sni_results = {}
        for pname, psni in SNI_PROFILES:
            test_sni = sni if psni is None else psni
            if pname == "empty":
                sni_results[pname] = await _try_tls(host, port, "a")
                sni_results[pname]["sni"] = "(empty-like)"
            else:
                sni_results[pname] = await _try_tls(host, port, test_sni)
                sni_results[pname]["sni"] = test_sni
            if delay: await asyncio.sleep(delay)
        result["sni_profiles"] = sni_results
        correct_ok = sni_results["correct"]["ok"]
        cdn_ok = sni_results["cdn"]["ok"]
        nonexist_ok = sni_results["nonexistent"]["ok"]
        if correct_ok and cdn_ok and nonexist_ok: result["sni_filtering"] = False
        elif not correct_ok and cdn_ok: result["sni_filtering"] = True
        elif not correct_ok and not cdn_ok and not nonexist_ok: result["sni_filtering"] = None
        elif correct_ok and not cdn_ok: result["sni_filtering"] = False
        else: result["sni_filtering"] = "partial"
        result["correct_sni"] = sni_results["correct"]
        result["wrong_sni"] = sni_results["cdn"]
    http = await _http_probe(host, port, sni)
    if delay: await asyncio.sleep(delay)
    result["http_probe"] = http
    rst = await _rst_check(host, port)
    result["rst_detected"] = rst
    return result


async def _try_tls(host, port, sni):
    start = time.monotonic()
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni), timeout=8)
        rtt = (time.monotonic() - start) * 1000; w.close(); await w.wait_closed()
        return {"ok": True, "rtt_ms": round(rtt, 1)}
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def _http_probe(host, port, sni=""):
    hostname = sni or host
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        w.write(f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode()); await w.drain()
        data = await asyncio.wait_for(r.read(1024), timeout=5)
        w.close(); await w.wait_closed()
        resp = data[:200].decode("utf-8", errors="replace")
        return {"responds": True, "is_http": resp.startswith("HTTP/"), "snippet": resp[:100]}
    except Exception:
        return {"responds": False, "is_http": False, "snippet": ""}


async def _rst_check(host, port):
    start = time.monotonic()
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        send_time = time.monotonic()
        w.write(b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00"); await w.drain()
        try:
            data = await asyncio.wait_for(r.read(64), timeout=3)
            elapsed = round((time.monotonic() - send_time) * 1000, 1)
            if not data: return {"type": "connection_closed", "immediate": elapsed < 50, "timing_ms": elapsed, "phase": "after_clienthello"}
            return {"type": "response", "immediate": False, "timing_ms": elapsed, "phase": "after_clienthello"}
        except asyncio.TimeoutError:
            return {"type": "no_response", "immediate": False, "timing_ms": 3000, "phase": "after_clienthello"}
        except ConnectionResetError:
            elapsed = round((time.monotonic() - send_time) * 1000, 1)
            phase = "during_clienthello" if elapsed < 100 else "after_clienthello"
            return {"type": "rst", "immediate": elapsed < 50, "timing_ms": elapsed, "phase": phase}
        finally:
            w.close(); await w.wait_closed()
    except ConnectionResetError:
        elapsed = round((time.monotonic() - start) * 1000, 1)
        return {"type": "rst_on_connect", "immediate": True, "timing_ms": elapsed, "phase": "on_connect"}
    except asyncio.TimeoutError:
        return {"type": "connect_timeout", "immediate": False, "timing_ms": 5000, "phase": "on_connect"}
    except Exception as e:
        return {"type": "error", "immediate": False, "timing_ms": 0, "phase": "unknown", "error": str(e)}


async def run_fingerprints(host, port, sni, delay=0):
    if not sni:
        return []
    hello_dir = Path(__file__).parent / "client_hello"
    if not hello_dir.exists():
        return []
    try:
        from scapy.layers.tls.record import TLS
        from scapy.layers.tls.handshake import TLSServerHello
        from scapy.layers.tls.extensions import ServerName
    except ImportError:
        return []

    results = []
    for f in sorted(hello_dir.iterdir()):
        if not f.is_file(): continue
        raw = f.read_bytes()
        tls_pkt = TLS(raw)
        ch = tls_pkt.msg[0]
        for ext in ch.ext:
            if ext.name == "TLS Extension - Server Name":
                ext.servernames = [ServerName(servername=sni)]
                ext.len = None; ext.servernameslen = None
        tls_pkt.len = None; ch.msglen = None; ch.extlen = None
        patched = bytes(tls_pkt)

        for mode in ["single", "parallel"]:
            start = time.monotonic()
            try:
                if mode == "single":
                    payload = _rand_sid(patched)
                    ok = await _send_hello(payload, host, port, TLS, TLSServerHello)
                    dur = (time.monotonic() - start) * 1000
                    results.append({"client_name": f.name, "mode": mode, "success": ok, "duration_ms": round(dur, 1), "error": None})
                else:
                    tasks = [_send_hello(_rand_sid(patched), host, port, TLS, TLSServerHello) for _ in range(5)]
                    raw_r = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=30)
                    dur = (time.monotonic() - start) * 1000
                    all_ok = all(r is True for r in raw_r)
                    errs = list(set(str(r) for r in raw_r if isinstance(r, Exception)))
                    results.append({"client_name": f.name, "mode": mode, "success": all_ok, "duration_ms": round(dur, 1), "error": "; ".join(errs) if errs else None})
            except asyncio.TimeoutError:
                results.append({"client_name": f.name, "mode": mode, "success": False, "duration_ms": 0, "error": "timeout"})
            except Exception as e:
                results.append({"client_name": f.name, "mode": mode, "success": False, "duration_ms": 0, "error": str(e)})
            if delay: await asyncio.sleep(delay)
    return results


def _rand_sid(payload):
    buf = list(payload)
    for i, b in enumerate(os.urandom(32)):
        buf[i + 44] = b
    return bytes(buf)


async def _send_hello(payload, host, port, TLS, TLSServerHello):
    r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
    try:
        w.write(payload); await w.drain()
        data = await asyncio.wait_for(r.read(4096), timeout=10)
        return TLS(data).haslayer(TLSServerHello)
    finally:
        w.close(); await w.wait_closed()


async def get_server_info(host):
    loop = asyncio.get_event_loop()
    ip = None
    try:
        res = await loop.getaddrinfo(host, None, family=socket.AF_INET)
        if res:
            ip = res[0][4][0]
    except Exception:
        pass
    if not ip:
        return {"ip": None, "error": "DNS resolution failed"}
    try:
        data = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: _http_json(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,hosting,proxy,query")),
            timeout=10)
        return {"ip": ip, "country": data.get("country"), "country_code": data.get("countryCode"),
                "region": data.get("regionName"), "city": data.get("city"),
                "isp": data.get("isp"), "org": data.get("org"), "as_number": data.get("as"),
                "hosting": data.get("hosting", False), "proxy": data.get("proxy", False)}
    except Exception:
        return {"ip": ip}


def _http_json(url):
    req = Request(url, headers={"User-Agent": "TGProxyAgent/1.0"})
    with urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode())


def _build_init(key_secret, tag):
    while True:
        nonce = os.urandom(64)
        if nonce[0] == 0xEF:
            continue
        first = struct.unpack("<I", nonce[:4])[0]
        if first in (0x44414548, 0x54534F50, 0x20544547, 0x4954504F, 0xDDDDDDDD, 0xEEEEEEEE):
            continue
        break
    nonce = bytearray(nonce)
    nonce[56:60] = b'\xdd\xdd\xdd\xdd' if tag == 0xDD else b'\xef\xef\xef\xef'
    enc_key = hashlib.sha256(bytes(nonce[8:40]) + key_secret).digest()
    enc_iv = bytes(nonce[40:56])
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    encryptor = Cipher(algorithms.AES(enc_key), modes.CTR(enc_iv)).encryptor()
    nonce[56:64] = encryptor.update(bytes(nonce[56:64]))
    return bytes(nonce)


# ═══════════════════════════════════════════
#  MAIN CHECK EXECUTOR
# ═══════════════════════════════════════════

async def execute_check(task: dict, self_info: dict) -> dict:
    server = task["server"]
    port = task["port"]
    sni = task.get("sni", "")
    secret_hex = task.get("secret_hex", "")
    safe = task.get("safe_mode", False)
    delay = 2.0 if safe else 0

    async def _d():
        if delay: await asyncio.sleep(delay)

    tcp_result, server_info, dns_check = await asyncio.gather(
        check_tcp(server, port),
        get_server_info(server),
        check_dns(server),
    )
    await _d()

    mtproto_result = None
    if secret_hex:
        mtproto_result = await check_mtproto(server, port, secret_hex)
        await _d()

    tls_result = await check_tls(server, port, sni)
    await _d()

    tls_cert = await check_tls_cert(server, port, sni)
    await _d()

    fingerprint_results = await run_fingerprints(server, port, sni, delay=delay)

    stability = await check_stability(server, port, delay=delay)

    dpi = await check_dpi(server, port, sni, delay=delay)

    fp_pass = sum(1 for f in fingerprint_results if f["success"])
    fp_total = len(fingerprint_results)

    if mtproto_result and mtproto_result.get("success"):
        if fp_total == 0 or fp_pass == fp_total:
            overall = "healthy"
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
        "server": server, "port": port, "sni": sni,
        "proxy_mode": task.get("proxy_mode", ""),
        "tcp": tcp_result, "tls": tls_result,
        "mtproto": mtproto_result,
        "fingerprints": fingerprint_results,
        "server_info": server_info,
        "checker_info": {k: v for k, v in self_info.items() if k != "ip"},
        "tls_cert": tls_cert,
        "stability": stability,
        "dpi": dpi,
        "dns": dns_check,
        "overall_status": overall,
    }
    return results


# ═══════════════════════════════════════════
#  WEBSOCKET MODE
# ═══════════════════════════════════════════

async def run_ws(master_url: str, token: str, self_info: dict):
    ws_url = master_url.replace("http://", "ws://").replace("https://", "wss://") + "/ws/agent"
    while True:
        try:
            print(f"[WS] Connecting to {ws_url}...")
            async with websockets.connect(ws_url, ping_interval=30, ping_timeout=10) as ws:
                await ws.send(json.dumps({"token": token, **self_info}))
                resp = json.loads(await ws.recv())
                if resp.get("type") != "auth_ok":
                    print(f"[WS] Auth failed: {resp}")
                    return
                print(f"[WS] Connected as {resp.get('agent_id')}")

                async for msg_str in ws:
                    msg = json.loads(msg_str)
                    if msg.get("type") == "ping":
                        await ws.send(json.dumps({"type": "pong"}))
                    elif msg.get("type") == "task":
                        task = msg["task"]
                        print(f"[WS] Task: {task['task_id']} → {task['server']}:{task['port']}")
                        result = await execute_check(task, self_info)
                        await ws.send(json.dumps({"type": "result", "task_id": task["task_id"], "result": result}))
                        print(f"[WS] Done: {task['task_id']} → {result['overall_status']}")

        except Exception as e:
            print(f"[WS] Disconnected: {e}. Reconnecting in 5s...")
            await asyncio.sleep(5)


# ═══════════════════════════════════════════
#  POLLING MODE
# ═══════════════════════════════════════════

async def run_polling(master_url: str, token: str, self_info: dict):
    base = master_url.rstrip("/")
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Agent-IP": self_info.get("ip", ""),
        "X-Agent-Country": self_info.get("country", ""),
        "X-Agent-City": self_info.get("city", ""),
        "X-Agent-ISP": self_info.get("isp", ""),
    }
    print(f"[Poll] Starting polling {base}/api/agent/task")

    while True:
        try:
            resp = requests.get(f"{base}/api/agent/task", headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                task = data.get("task")
                if task:
                    print(f"[Poll] Task: {task['task_id']} → {task['server']}:{task['port']}")
                    result = await execute_check(task, self_info)
                    requests.post(f"{base}/api/agent/result", headers=headers,
                                  json={"task_id": task["task_id"], "result": result}, timeout=10)
                    print(f"[Poll] Done: {task['task_id']} → {result['overall_status']}")
            elif resp.status_code == 401:
                print("[Poll] Invalid token!")
                return
        except Exception as e:
            print(f"[Poll] Error: {e}")

        await asyncio.sleep(3)


# ═══════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="TG Proxy Checker Agent")
    parser.add_argument("--master", required=True, help="Master server URL (http://...)")
    parser.add_argument("--token", required=True, help="Agent auth token")
    parser.add_argument("--mode", choices=["ws", "poll", "auto"], default="auto", help="Connection mode")
    args = parser.parse_args()

    print("Detecting self info...")
    self_info = get_self_info()
    print(f"IP: {self_info.get('ip')} | {self_info.get('city')}, {self_info.get('country')}")

    if args.mode == "auto":
        mode = "ws" if HAS_WS else "poll"
    else:
        mode = args.mode

    if mode == "ws":
        if not HAS_WS:
            print("websockets not installed! pip install websockets")
            sys.exit(1)
        asyncio.run(run_ws(args.master, args.token, self_info))
    else:
        if not HAS_REQUESTS:
            print("requests not installed! pip install requests")
            sys.exit(1)
        asyncio.run(run_polling(args.master, args.token, self_info))


if __name__ == "__main__":
    main()
