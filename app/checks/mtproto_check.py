import asyncio
import hashlib
import os
import struct
import time


async def check_mtproto(host: str, port: int, secret_hex: str) -> dict:
    start = time.monotonic()
    try:
        secret_bytes = bytes.fromhex(secret_hex)
    except ValueError:
        return {"success": False, "rtt_ms": 0, "error": "invalid secret hex"}

    if len(secret_bytes) < 17:
        return {"success": False, "rtt_ms": 0, "error": "secret too short"}

    tag = secret_bytes[0]
    key_secret = secret_bytes[1:17]

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10
        )
    except asyncio.TimeoutError:
        return {"success": False, "rtt_ms": 0, "error": "tcp timeout"}
    except Exception as e:
        return {"success": False, "rtt_ms": 0, "error": str(e)}

    try:
        init_payload = _build_obfuscated_init(key_secret, tag)
        writer.write(init_payload)
        await writer.drain()
        connect_rtt = (time.monotonic() - start) * 1000

        try:
            data = await asyncio.wait_for(reader.read(128), timeout=3)
            rtt = (time.monotonic() - start) * 1000
            if data:
                return {"success": True, "rtt_ms": round(connect_rtt, 1), "response_size": len(data), "detail": "responded"}
            else:
                elapsed_after_send = rtt - connect_rtt
                if elapsed_after_send > 1000:
                    return {"success": True, "rtt_ms": round(connect_rtt, 1), "response_size": 0, "detail": "kept_alive"}
                return {"success": False, "rtt_ms": round(connect_rtt, 1), "error": "init rejected", "detail": "closed"}
        except asyncio.TimeoutError:
            return {"success": True, "rtt_ms": round(connect_rtt, 1), "response_size": 0, "detail": "kept_alive"}

    except ConnectionResetError:
        rtt = (time.monotonic() - start) * 1000
        return {"success": False, "rtt_ms": round(rtt, 1), "error": "connection reset"}
    except Exception as e:
        rtt = (time.monotonic() - start) * 1000
        return {"success": False, "rtt_ms": round(rtt, 1), "error": str(e)}
    finally:
        writer.close()
        await writer.wait_closed()


def _build_obfuscated_init(key_secret: bytes, tag: int) -> bytes:
    while True:
        nonce = os.urandom(64)
        if nonce[0] == 0xEF:
            continue
        first_int = struct.unpack("<I", nonce[:4])[0]
        if first_int in (0x44414548, 0x54534F50, 0x20544547, 0x4954504F,
                         0xDDDDDDDD, 0xEEEEEEEE, 0x02010316):
            continue
        if nonce[:4] == b'\x16\x03\x01\x02':
            continue
        break

    nonce = bytearray(nonce)

    if tag == 0xDD:
        nonce[56:60] = b'\xdd\xdd\xdd\xdd'
    elif tag == 0xEE:
        nonce[56:60] = b'\xef\xef\xef\xef'
    else:
        nonce[56:60] = b'\xef\xef\xef\xef'

    enc_key_data = bytes(nonce[8:40]) + key_secret
    enc_key = hashlib.sha256(enc_key_data).digest()
    enc_iv = bytes(nonce[40:56])

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    enc_cipher = Cipher(algorithms.AES(enc_key), modes.CTR(enc_iv))
    encryptor = enc_cipher.encryptor()

    encrypted_part = encryptor.update(bytes(nonce[56:64]))
    result = bytearray(nonce)
    result[56:64] = encrypted_part

    return bytes(result)
