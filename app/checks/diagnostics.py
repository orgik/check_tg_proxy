import asyncio
import socket
import ssl
import time
import struct


async def check_tls_certificate(host: str, port: int, sni: str) -> dict:
    if not sni:
        return {"available": False, "error": "no SNI"}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni),
            timeout=10,
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert(binary_form=False)
        cert_bin = ssl_obj.getpeercert(binary_form=True)

        tls_version = ssl_obj.version()
        cipher = ssl_obj.cipher()

        subject = _parse_cert_field(cert.get("subject", ())) if cert else ""
        issuer = _parse_cert_field(cert.get("issuer", ())) if cert else ""
        not_before = cert.get("notBefore", "") if cert else ""
        not_after = cert.get("notAfter", "") if cert else ""
        san = []
        if cert:
            for t, v in cert.get("subjectAltName", ()):
                san.append(v)

        sni_match = sni in san or sni == subject

        writer.close()
        await writer.wait_closed()

        return {
            "available": True,
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "san": san[:5],
            "sni_match": sni_match,
            "tls_version": tls_version,
            "cipher_suite": cipher[0] if cipher else "",
            "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else 0,
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


def _parse_cert_field(field_tuple) -> str:
    parts = []
    for rdn in field_tuple:
        for attr_type, attr_value in rdn:
            parts.append(f"{attr_type}={attr_value}")
    return ", ".join(parts)


async def check_stability(host: str, port: int, count: int = 10) -> dict:
    results = []

    async def _single_connect(i):
        start = time.monotonic()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            rtt = (time.monotonic() - start) * 1000
            writer.close()
            await writer.wait_closed()
            return {"ok": True, "rtt_ms": round(rtt, 1)}
        except asyncio.TimeoutError:
            return {"ok": False, "rtt_ms": 0, "error": "timeout"}
        except Exception as e:
            return {"ok": False, "rtt_ms": 0, "error": str(e)}

    for i in range(count):
        r = await _single_connect(i)
        results.append(r)
        if i < count - 1:
            await asyncio.sleep(0.3)

    success = sum(1 for r in results if r["ok"])
    rtts = [r["rtt_ms"] for r in results if r["ok"]]
    avg_rtt = round(sum(rtts) / len(rtts), 1) if rtts else 0
    min_rtt = round(min(rtts), 1) if rtts else 0
    max_rtt = round(max(rtts), 1) if rtts else 0
    jitter = round(max_rtt - min_rtt, 1) if rtts else 0

    first_fail = None
    for i, r in enumerate(results):
        if not r["ok"]:
            first_fail = i + 1
            break

    pattern = "stable"
    if success == 0:
        all_refused = all("refused" in r.get("error", "").lower() for r in results)
        pattern = "connection_refused" if all_refused else "blocked"
    elif success < count:
        if first_fail and first_fail <= 3:
            pattern = "rate_limited"
        else:
            pattern = "unstable"

    return {
        "total": count,
        "success": success,
        "success_rate": round(success / count * 100),
        "avg_rtt_ms": avg_rtt,
        "min_rtt_ms": min_rtt,
        "max_rtt_ms": max_rtt,
        "jitter_ms": jitter,
        "pattern": pattern,
        "first_fail_at": first_fail,
        "details": results,
    }


async def check_dpi(host: str, port: int, sni: str) -> dict:
    result = {}

    if sni:
        wrong_sni = await _try_tls_connect(host, port, "decoy-" + sni[:20] + ".example.com")
        correct_sni = await _try_tls_connect(host, port, sni)
        result["wrong_sni"] = wrong_sni
        result["correct_sni"] = correct_sni
        if wrong_sni["ok"] and correct_sni["ok"]:
            result["sni_filtering"] = False
        elif not correct_sni["ok"] and not wrong_sni["ok"]:
            result["sni_filtering"] = None
        else:
            result["sni_filtering"] = True

    http_result = await _http_probe(host, port)
    result["http_probe"] = http_result

    rst_result = await _check_rst(host, port)
    result["rst_detected"] = rst_result

    return result


async def _try_tls_connect(host: str, port: int, sni: str) -> dict:
    start = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni),
            timeout=8,
        )
        rtt = (time.monotonic() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return {"ok": True, "rtt_ms": round(rtt, 1)}
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def _http_probe(host: str, port: int) -> dict:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=5
        )
        writer.write(b"GET / HTTP/1.1\r\nHost: check\r\nConnection: close\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=5)
        writer.close()
        await writer.wait_closed()
        response = data[:200].decode("utf-8", errors="replace")
        is_http = response.startswith("HTTP/")
        return {"responds": True, "is_http": is_http, "snippet": response[:100]}
    except asyncio.TimeoutError:
        return {"responds": False, "is_http": False, "snippet": ""}
    except Exception as e:
        return {"responds": False, "is_http": False, "snippet": str(e)[:100]}


async def _check_rst(host: str, port: int) -> dict:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=5
        )
        writer.write(b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00")
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(64), timeout=3)
            if not data:
                return {"type": "connection_closed", "immediate": True}
            return {"type": "response", "immediate": False}
        except asyncio.TimeoutError:
            return {"type": "no_response", "immediate": False}
        except ConnectionResetError:
            return {"type": "rst", "immediate": True}
        finally:
            writer.close()
            await writer.wait_closed()
    except ConnectionResetError:
        return {"type": "rst_on_connect", "immediate": True}
    except asyncio.TimeoutError:
        return {"type": "connect_timeout", "immediate": False}
    except Exception as e:
        return {"type": "error", "immediate": False, "error": str(e)}


def _is_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


async def check_dns(host: str) -> dict:
    if _is_ip(host):
        return {"direct_ip": True, "all_ips": [host], "consistent": True}

    loop = asyncio.get_event_loop()
    results = {}

    try:
        res = await loop.getaddrinfo(host, None, family=socket.AF_INET)
        ips = list(set(r[4][0] for r in res))
        results["system"] = {"ips": ips, "ok": True}
    except Exception as e:
        results["system"] = {"ips": [], "ok": False, "error": str(e)}

    for name, dns_ip in [("google", "8.8.8.8"), ("cloudflare", "1.1.1.1")]:
        try:
            ip = await asyncio.wait_for(
                loop.run_in_executor(None, lambda d=dns_ip: _resolve_via(host, d)),
                timeout=5,
            )
            results[name] = {"ips": [ip] if ip else [], "ok": bool(ip)}
        except Exception as e:
            results[name] = {"ips": [], "ok": False, "error": str(e)}

    all_ips = set()
    for v in results.values():
        all_ips.update(v.get("ips", []))

    results["consistent"] = len(all_ips) <= 1
    results["all_ips"] = sorted(all_ips)

    return results


def _resolve_via(host: str, dns_server: str) -> str | None:
    import struct as st
    qname = b""
    for part in host.encode().split(b"."):
        qname += bytes([len(part)]) + part
    qname += b"\x00"

    tx_id = struct.pack("!H", 0x1234)
    header = tx_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    question = qname + st.pack("!HH", 1, 1)
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(packet, (dns_server, 53))
        data, _ = sock.recvfrom(512)
        ancount = st.unpack("!H", data[6:8])[0]
        if ancount == 0:
            return None
        offset = 12 + len(question)
        for _ in range(ancount):
            if offset + 12 > len(data):
                break
            rtype, rclass, ttl, rdlen = st.unpack("!HHIH", data[offset + 2:offset + 12])
            if rtype == 1 and rdlen == 4:
                ip = socket.inet_ntoa(data[offset + 12:offset + 16])
                return ip
            offset += 12 + rdlen
        return None
    finally:
        sock.close()
