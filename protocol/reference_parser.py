#!/usr/bin/env python3
"""
CITP (Chameleon Intent Transport Protocol) — Independent Python Reference Parser
Демонстрирует независимую проверку бинарных структур wire-format CITP и HMAC-подписей.
"""

import struct
import hmac
import hashlib
import time
import argparse
import json

HEADER_LEN = 50  # 8+8+4+2+1+1+8+8+8+2 = 50 байт
AUTH_TAG_LEN = 32

class CITPObject:
    def __init__(self, object_id, parent_id, stream_id, obj_type, mode, flags, offset, expiry_ms, seq, payload, auth_tag=b""):
        self.object_id = object_id
        self.parent_id = parent_id
        self.stream_id = stream_id
        self.type = obj_type
        self.mode = mode
        self.flags = flags
        self.offset = offset
        self.expiry_unix_ms = expiry_ms
        self.monotonic_seq = seq
        self.payload = payload
        self.auth_tag = auth_tag

    @classmethod
    def decode(cls, data: bytes):
        if len(data) < HEADER_LEN:
            raise ValueError("CITP data too short")
        
        (obj_id, parent_id, stream_id, obj_type, mode, flags, 
         offset, expiry_ms, seq, p_len) = struct.unpack(">QQIHBBQQQH", data[:HEADER_LEN])
        
        if len(data) < HEADER_LEN + p_len:
            raise ValueError("Truncated payload")
        
        payload = data[HEADER_LEN:HEADER_LEN + p_len]
        rem = len(data) - (HEADER_LEN + p_len)
        if rem not in (0, AUTH_TAG_LEN):
            raise ValueError("Invalid trailing data")
        auth_tag = b""
        if rem == AUTH_TAG_LEN:
            auth_tag = data[HEADER_LEN + p_len:]

        return cls(obj_id, parent_id, stream_id, obj_type, mode, flags, offset, expiry_ms, seq, payload, auth_tag)

    def encode(self) -> bytes:
        header = struct.pack(">QQIHBBQQQH",
                             self.object_id, self.parent_id, self.stream_id,
                             self.type, self.mode, self.flags,
                             self.offset, self.expiry_unix_ms,
                             self.monotonic_seq, len(self.payload))
        return header + self.payload + (self.auth_tag if len(self.auth_tag) == AUTH_TAG_LEN else b"")

    def verify_auth_tag(self, session_key: bytes) -> bool:
        if len(self.auth_tag) != AUTH_TAG_LEN:
            return False
        header = struct.pack(">QQIHBBQQQH",
                             self.object_id, self.parent_id, self.stream_id,
                             self.type, self.mode, self.flags,
                             self.offset, self.expiry_unix_ms,
                             self.monotonic_seq, len(self.payload))
        sign_data = header + self.payload
        expected = hmac.new(session_key, sign_data, hashlib.sha256).digest()
        return hmac.compare_digest(self.auth_tag, expected)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--decode-hex")
    args = ap.parse_args()
    if args.decode_hex is not None:
        raw = bytes.fromhex(args.decode_hex)
        decoded = CITPObject.decode(raw)
        print(json.dumps({
            "object_id": decoded.object_id,
            "parent_id": decoded.parent_id,
            "stream_id": decoded.stream_id,
            "type": decoded.type,
            "mode": decoded.mode,
            "flags": decoded.flags,
            "offset": decoded.offset,
            "expiry_unix_ms": decoded.expiry_unix_ms,
            "monotonic_seq": decoded.monotonic_seq,
            "payload_hex": decoded.payload.hex(),
            "auth_tag_hex": decoded.auth_tag.hex(),
            "encoded_hex": decoded.encode().hex(),
        }, separators=(",", ":")))
        raise SystemExit(0)

    test_key = b"0" * 32
    obj = CITPObject(
        object_id=1001,
        parent_id=1000,
        stream_id=42,
        obj_type=1,
        mode=1,
        flags=0,
        offset=1024,
        expiry_ms=int(time.time() * 1000) + 10000,
        seq=5,
        payload=b"test-citp-interoperability"
    )
    # Sign in python
    header = struct.pack(">QQIHBBQQQH",
                         obj.object_id, obj.parent_id, obj.stream_id,
                         obj.type, obj.mode, obj.flags,
                         obj.offset, obj.expiry_unix_ms,
                         obj.monotonic_seq, len(obj.payload))
    obj.auth_tag = hmac.new(test_key, header + obj.payload, hashlib.sha256).digest()
    
    encoded = obj.encode()
    decoded = CITPObject.decode(encoded)
    assert decoded.verify_auth_tag(test_key)
    assert decoded.payload == b"test-citp-interoperability"
    print(f"[OK] CITP Reference Parser: object_id={decoded.object_id}, valid={decoded.verify_auth_tag(test_key)}")
