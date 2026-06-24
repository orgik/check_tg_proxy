import base64
import re
import urllib.parse


def _decode_secret(secret: str) -> bytes | None:
    try:
        return bytes.fromhex(secret)
    except ValueError:
        pass

    padded = secret + "=" * (-len(secret) % 4)
    for alt in [secret, padded]:
        urlsafe = alt.replace("-", "+").replace("_", "/")
        for variant in [alt, urlsafe]:
            try:
                return base64.b64decode(variant, validate=True)
            except Exception:
                continue
    return None


def _validate_sni(sni: str) -> str:
    if not sni:
        return ""
    sni = sni.strip().lower()
    if not sni:
        return ""
    # No control characters
    if any(ord(c) < 32 for c in sni):
        return ""
    # Must look like a hostname, not an IP
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', sni):
        return ""
    # Each label: 1-63 chars, alphanumeric + hyphens, no leading/trailing hyphen
    labels = sni.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return ""
        if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', label):
            return ""
    return sni


def _detect_proxy_mode(secret_bytes: bytes) -> tuple[str, str]:
    """Returns (proxy_mode, sni)."""
    if not secret_bytes:
        return "unknown", ""

    tag = secret_bytes[0]

    if tag == 0xEE and len(secret_bytes) > 17:
        raw_sni = secret_bytes[17:].decode("utf-8", errors="replace")
        sni = _validate_sni(raw_sni)
        return "fake_tls", sni

    if tag == 0xDD and len(secret_bytes) == 17:
        return "padded", ""

    if len(secret_bytes) == 16:
        return "simple", ""

    if tag == 0xDD:
        return "padded", ""

    return "unknown", ""


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
            proxy_mode, sni = _detect_proxy_mode(b)

    return server, port, sni, secret_hex, proxy_mode
