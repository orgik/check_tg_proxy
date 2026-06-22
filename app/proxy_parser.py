import base64
import urllib.parse


def _decode_secret(secret: str) -> bytes | None:
    try:
        return bytes.fromhex(secret)
    except ValueError:
        pass

    padded = secret + "=" * (-len(secret) % 4)
    for alt in [secret, padded]:
        for variant in [alt, alt.replace("-", "+").replace("_", "/")]:
            try:
                return base64.b64decode(variant)
            except Exception:
                continue
    return None


def parse_proxy_link(url: str) -> tuple[str, int, str, str, str]:
    """Returns (server, port, sni, secret_hex, proxy_mode)."""
    url = url.strip()
    if "t.me/proxy" in url:
        idx = url.find("t.me/proxy") + len("t.me/proxy")
        url = "tg://proxy" + url[idx:]
    if url.startswith("https://t.me/"):
        url = url.replace("https://t.me/", "tg://", 1)

    parsed = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(parsed.query)

    server = q.get("server", [""])[0]
    port_str = q.get("port", ["443"])[0]
    secret = q.get("secret", [""])[0]

    if not server:
        raise ValueError("Missing 'server' parameter in proxy link")

    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"Invalid port: {port_str}")

    if not 1 <= port <= 65535:
        raise ValueError(f"Port out of range: {port}")

    sni = ""
    secret_hex = ""
    proxy_mode = "unknown"

    if secret:
        b = _decode_secret(secret)
        if b:
            secret_hex = b.hex()
            if b[0] == 0xEE and len(b) > 17:
                proxy_mode = "fake_tls"
                sni = b[17:].decode("utf-8", errors="replace")
            elif b[0] == 0xDD:
                proxy_mode = "padded"
            elif len(b) == 16:
                proxy_mode = "simple"
            else:
                proxy_mode = "unknown"

    return server, port, sni, secret_hex, proxy_mode
