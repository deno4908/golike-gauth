from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import uuid
from typing import Any, Mapping, MutableMapping, Optional, Union
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Constants from app JS (B_="glk-gauth", E_="v3-2026", S_="q3")
SALT = "glk-gauth-v3-2026q3"
HKDF_INFO = "aes-gcm-key"
APP_VERSION = "26.07.10.2"
APP_CLIENT = "109096667105508"
BASE_API = "https://gateway.golike.net/api"

JsonBody = Union[None, str, bytes, Mapping[str, Any], list]


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data.replace("-", "+").replace("_", "/") + pad)


def parse_signing_key(signing_key: str) -> bytes:
    """Decode 32-byte signing key from hex or base64/base64url."""
    if not signing_key or not isinstance(signing_key, str):
        raise ValueError("signing_key empty or not a string")

    attempts = []
    s = signing_key.strip()

    if len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
        try:
            raw = bytes.fromhex(s)
            attempts.append(("hex", len(raw)))
            if len(raw) == 32:
                return raw
        except Exception as ex:
            attempts.append(("hex", str(ex)))

    for label, decoder in (
        ("b64", base64.b64decode),
        ("b64url", b64url_decode),
    ):
        try:
            raw = decoder(s)
            attempts.append((label, len(raw)))
            if len(raw) == 32:
                return raw
        except Exception as ex:
            attempts.append((label, str(ex)))

    raise ValueError(
        f"signing key must decode to 32 bytes (AES-256); attempts={attempts}"
    )


def derive_aes_key(signing_key: str) -> bytes:
    """HKDF-SHA256(signing_key, salt=SALT, info=aes-gcm-key) -> 32 bytes."""
    ikm = parse_signing_key(signing_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT.encode("utf-8"),
        info=HKDF_INFO.encode("utf-8"),
    ).derive(ikm)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def body_hash(body: JsonBody = None) -> str:
    """SHA256 hex of request body string (GET uses empty string)."""
    if body is None:
        s = ""
    elif isinstance(body, bytes):
        s = body.decode("utf-8")
    elif isinstance(body, str):
        s = body
    else:
        s = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    return sha256_hex(s)


def request_digest(ts_ms: int, device_id: str, q: str) -> str:
    return sha256_hex(f"{ts_ms}:{device_id}:{q}:{SALT}")[:16]


def generate_device_id(existing: Optional[str] = None) -> str:
    if existing:
        return existing
    return str(uuid.uuid4())


def generate_nonce_x() -> str:
    return b64url_encode(secrets.token_bytes(16))


def triple_btoa(value: str) -> str:
    x = value.encode("utf-8")
    for _ in range(3):
        x = base64.b64encode(x)
    return x.decode("ascii")


def make_t_header(ts: Optional[int] = None) -> str:
    if ts is None:
        ts = int(time.time())
    return triple_btoa(str(ts))


def normalize_path(path: str, base_url: str = BASE_API) -> str:
    """Pathname used in g-auth payload (no query/hash)."""
    p = (path or "").split("?")[0].split("#")[0]
    if not p.startswith("/"):
        p = "/" + p
    base = (base_url or "").rstrip("/")
    if p.startswith("/api/"):
        return p
    if base.endswith("/api"):
        return "/api" + p
    return urlparse(base + p).path


def generate_g_auth(
    *,
    method: str,
    path: str,
    signing_key: str,
    device_id: str,
    user_id: int,
    body: JsonBody = None,
    base_url: str = BASE_API,
    ts_ms: Optional[int] = None,
) -> str:
    """
    Build g-auth token (AES-GCM).
    Payload: {t,x,d,u,n,k,q,r}  Output: b64url(iv12 || ciphertext+tag)
    """
    aes_key = derive_aes_key(signing_key)
    iv = secrets.token_bytes(12)
    t = int(ts_ms if ts_ms is not None else time.time() * 1000)
    k = normalize_path(path, base_url)
    q = body_hash("" if body is None else body)
    payload = {
        "t": t,
        "x": generate_nonce_x(),
        "d": device_id,
        "u": int(user_id),
        "n": method.upper(),
        "k": k,
        "q": q,
        "r": request_digest(t, device_id, q),
    }
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    ct = AESGCM(aes_key).encrypt(iv, plaintext, None)
    return b64url_encode(iv + ct)


def decode_g_auth(token: str, signing_key: str) -> dict:
    """Decrypt g-auth for debugging."""
    aes_key = derive_aes_key(signing_key)
    raw = b64url_decode(token)
    if len(raw) < 12 + 16:
        raise ValueError("token too short")
    iv, ct = raw[:12], raw[12:]
    pt = AESGCM(aes_key).decrypt(iv, ct, None)
    return json.loads(pt.decode("utf-8"))


def build_headers(
    *,
    token: str,
    signing_key: str,
    user_id: int,
    username: str,
    method: str,
    path: str,
    body: JsonBody = None,
    device_id: Optional[str] = None,
    g_version: str = APP_VERSION,
    g_client: str = APP_CLIENT,
    user_agent: Optional[str] = None,
    extra: Optional[Mapping[str, str]] = None,
) -> dict:
    """Build request headers with fresh g-auth / g-device-id / t."""
    did = generate_device_id(device_id)
    # GET/HEAD/DELETE in app use body "" for signing
    sign_body: JsonBody = "" if body is None else body
    g_auth = generate_g_auth(
        method=method,
        path=path,
        body=sign_body,
        signing_key=signing_key,
        device_id=did,
        user_id=int(user_id),
    )
    ua = user_agent or (
        "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/150.0.0.0 Mobile Safari/537.36"
    )
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "vi,en-US;q=0.9,en;q=0.8",
        "authorization": f"Bearer {token}",
        "content-type": "application/json;charset=utf-8",
        "g-auth": g_auth,
        "g-device-id": did,
        "g-username": username,
        "g-version": g_version,
        "g-client": g_client,
        "origin": "https://app.golike.net",
        "referer": "https://app.golike.net/",
        "t": make_t_header(),
        "user-agent": ua,
        "sec-ch-ua": '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
    }
    if extra:
        headers.update(dict(extra))
    return headers


class GolikeAuth:
    """Reusable helper that keeps token / signing_key / device_id."""

    def __init__(
        self,
        *,
        token: str,
        signing_key: str,
        user_id: int,
        username: str,
        device_id: Optional[str] = None,
        g_version: str = APP_VERSION,
        g_client: str = APP_CLIENT,
        base_url: str = BASE_API,
        user_agent: Optional[str] = None,
    ) -> None:
        self.token = token
        self.signing_key = signing_key
        self.user_id = int(user_id)
        self.username = username
        self.device_id = generate_device_id(device_id)
        self.g_version = g_version
        self.g_client = g_client
        self.base_url = base_url.rstrip("/")
        self.user_agent = user_agent

    def g_auth(
        self,
        method: str,
        path: str,
        body: JsonBody = None,
        ts_ms: Optional[int] = None,
    ) -> str:
        return generate_g_auth(
            method=method,
            path=path,
            body="" if body is None else body,
            signing_key=self.signing_key,
            device_id=self.device_id,
            user_id=self.user_id,
            base_url=self.base_url,
            ts_ms=ts_ms,
        )

    def headers(
        self,
        method: str,
        path: str,
        body: JsonBody = None,
        extra: Optional[Mapping[str, str]] = None,
    ) -> dict:
        return build_headers(
            token=self.token,
            signing_key=self.signing_key,
            user_id=self.user_id,
            username=self.username,
            method=method,
            path=path,
            body=body,
            device_id=self.device_id,
            g_version=self.g_version,
            g_client=self.g_client,
            user_agent=self.user_agent,
            extra=extra,
        )

    def decode(self, g_auth_token: str) -> dict:
        return decode_g_auth(g_auth_token, self.signing_key)

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Any = None,
        data: Any = None,
        timeout: float = 30,
        session=None,
    ):
        """Signed HTTP request via requests (optional dependency)."""
        import requests

        method_u = method.upper()
        if data is not None:
            body: JsonBody = data if isinstance(data, (str, bytes)) else data
            sign_body = body
            headers = self.headers(method_u, path, body=sign_body)
            url = path if path.startswith("http") else self.base_url + (
                path if path.startswith("/") else "/" + path
            )
            return (session or requests).request(
                method_u,
                url,
                params=params,
                data=data,
                headers=headers,
                timeout=timeout,
            )

        if json_body is not None:
            raw = json.dumps(json_body, ensure_ascii=False, separators=(",", ":"))
            headers = self.headers(method_u, path, body=raw)
            url = path if path.startswith("http") else self.base_url + (
                path if path.startswith("/") else "/" + path
            )
            return (session or requests).request(
                method_u,
                url,
                params=params,
                data=raw.encode("utf-8"),
                headers=headers,
                timeout=timeout,
            )

        # no body (GET etc.) — sign with empty string
        headers = self.headers(method_u, path, body="")
        url = path if path.startswith("http") else self.base_url + (
            path if path.startswith("/") else "/" + path
        )
        return (session or requests).request(
            method_u, url, params=params, headers=headers, timeout=timeout
        )

    def get_instagram_job(self, instagram_account_id: str, session=None):
        return self.request(
            "GET",
            "/advertising/publishers/instagram/jobs",
            params={
                "instagram_account_id": str(instagram_account_id),
                "data": "null",
            },
            session=session,
        )
