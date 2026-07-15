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
# Mobile UA — app web gen g-version/g-client/header theo client mobile
MOBILE_UA = (
    "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/150.0.0.0 Mobile Safari/537.36"
)

JsonBody = Union[None, str, bytes, Mapping[str, Any], list]


def jwt_payload(token: str) -> dict:
    """Decode JWT payload (no verify)."""
    parts = (token or "").strip().split(".")
    if len(parts) != 3:
        raise ValueError("token phai la JWT 3 phan (header.payload.sig)")
    raw = b64url_decode(parts[1])
    return json.loads(raw.decode("utf-8"))


def jwt_user_id(token: str) -> int:
    """user_id = JWT sub."""
    payload = jwt_payload(token)
    sub = payload.get("sub")
    if sub is None:
        raise ValueError("JWT thieu sub (user_id)")
    return int(sub)


def mobile_bearer_headers(token: str, device_id: Optional[str] = None) -> dict:
    """Header mobile khi goi API chi can Bearer (vd /users/me)."""
    did = generate_device_id(device_id)
    return {
        "accept": "application/json, text/plain, */*",
        "accept-language": "vi,en-US;q=0.9,en;q=0.8",
        "authorization": f"Bearer {token}",
        "content-type": "application/json;charset=utf-8",
        "origin": "https://app.golike.net",
        "referer": "https://app.golike.net/",
        "user-agent": MOBILE_UA,
        "g-device-id": did,
        "g-version": APP_VERSION,
        "g-client": APP_CLIENT,
        "sec-ch-ua": '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "t": make_t_header(),
    }


def fetch_user_me(token: str, *, device_id: Optional[str] = None, timeout: float = 30) -> dict:
    """
    GET /users/me — chi can token (khong bat g-auth).
    Tra ve dict user (data) + raw response.
    """
    import requests

    did = generate_device_id(device_id)
    headers = mobile_bearer_headers(token, did)
    resp = requests.get(f"{BASE_API}/users/me", headers=headers, timeout=timeout)
    try:
        body = resp.json()
    except Exception:
        raise ValueError(f"/users/me HTTP {resp.status_code}: {resp.text[:200]}")
    if resp.status_code != 200 or not (body.get("success") or body.get("status") == 200):
        raise ValueError(
            f"/users/me fail: {body.get('message') or body} (HTTP {resp.status_code})"
        )
    data = body.get("data") or {}
    if not isinstance(data, dict):
        raise ValueError("/users/me data khong hop le")
    return data


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
    ua = user_agent or MOBILE_UA
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
        self.user_agent = user_agent or MOBILE_UA
        self.profile: dict = {}  # raw /users/me data (neu co)

    # ------------------------------------------------------------------
    # Bootstrap tu token
    # ------------------------------------------------------------------
    @classmethod
    def from_token(
        cls,
        token: str,
        *,
        signing_key: Optional[str] = None,
        device_id: Optional[str] = None,
        username: Optional[str] = None,
        verify: bool = True,
        timeout: float = 30,
    ) -> "GolikeAuth":
        """
        Chi can JWT token — lay user_id / username / (signing_key) tu API.

        Flow:
          1. Decode JWT → user_id (sub)
          2. GET /users/me (UA mobile) → username, coin, firebase_id, ...
          3. signing_key:
               - neu truyen vao → dung
               - else thu data.firebase_id (app set_signing_key(firebase_id))
               - verify qua POST /security/echo (neu verify=True)
          4. device_id: truyen vao hoac random UUID

        Luu y: mot so acc firebase_id != store.signing_key → can truyen
        signing_key thu cong (console: store.state.signing_key).
        """
        token = (token or "").strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        user_id = jwt_user_id(token)
        did = generate_device_id(device_id)

        me = fetch_user_me(token, device_id=did, timeout=timeout)
        uname = (username or me.get("username") or me.get("name") or "user").strip()
        sk = (signing_key or "").strip() or None
        if not sk:
            # App: e.signing_key = firebase_id (khi co)
            cand = me.get("firebase_id")
            if cand and isinstance(cand, str) and cand.strip():
                sk = cand.strip()

        if not sk:
            raise ValueError(
                "API /users/me khong co firebase_id/signing_key. "
                "Truyen signing_key= store.state.signing_key tu browser."
            )

        # Validate key 32 bytes
        parse_signing_key(sk)

        auth = cls(
            token=token,
            signing_key=sk,
            user_id=user_id,
            username=uname,
            device_id=did,
            user_agent=MOBILE_UA,
        )
        auth.profile = me

        if verify:
            ok, detail = auth.verify_signing_key(timeout=timeout)
            if not ok:
                raise ValueError(
                    "signing_key (firebase_id) server decrypt_fail. "
                    "Hay lay store.state.signing_key tu browser va truyen signing_key=... "
                    f"detail={detail}"
                )
        return auth

    def verify_signing_key(self, timeout: float = 30) -> tuple:
        """
        POST /security/echo de xac nhan signing_key.
        Returns (ok: bool, detail: dict|str)
        """
        import requests

        body = json.dumps({"ping": 1}, separators=(",", ":"))
        headers = self.headers("POST", "/security/echo", body=body)
        try:
            resp = requests.post(
                f"{self.base_url}/security/echo",
                headers=headers,
                data=body.encode("utf-8"),
                timeout=timeout,
            )
            data = resp.json()
        except Exception as e:
            return False, str(e)

        msg = str(data.get("message") or data.get("error") or "")
        if data.get("code") == 429 or "429" in msg or "qua nhanh" in msg.lower():
            # rate-limit: khong ket luan key sai
            return True, {"rate_limited": True, "message": msg}

        g = {}
        if isinstance(data.get("data"), dict):
            g = data["data"].get("gauth") or {}
        errs = g.get("errors") or []
        decoded = g.get("decoded")
        if decoded is not None and not any("decrypt" in str(e).lower() for e in errs):
            return True, {"decoded": decoded, "version": g.get("version_detected")}
        return False, {"errors": errs, "status": data.get("status"), "message": msg}

    def refresh_profile(self, timeout: float = 30) -> dict:
        """Cap nhat self.profile tu /users/me."""
        self.profile = fetch_user_me(
            self.token, device_id=self.device_id, timeout=timeout
        )
        if self.profile.get("username"):
            self.username = self.profile["username"]
        return self.profile

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

    def _url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        return self.base_url + (path if path.startswith("/") else "/" + path)

    @staticmethod
    def _compact_json(obj: Any) -> str:
        """Match JS JSON.stringify (no spaces) — body bytes must equal signed body."""
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json: Any = None,
        json_body: Any = None,
        data: Any = None,
        timeout: float = 30,
        session=None,
    ):
        """
        Signed HTTP request for ANY gateway path.

        - GET/HEAD/DELETE without body → sign body as ""
        - POST/PUT/PATCH with json=dict → sign + send compact JSON (no spaces)
        - Do not use requests' json= yourself (it may add spaces and break q hash)

        Examples:
            auth.request("GET", "/advertising/publishers/instagram/jobs", params={...})
            auth.request("POST", "/advertising/publishers/instagram/skip-jobs", json={...})
        """
        import requests

        method_u = method.upper()
        payload = json if json is not None else json_body

        if data is not None and payload is not None:
            raise ValueError("pass only one of data= or json=")

        if data is not None:
            if isinstance(data, (dict, list)):
                raw = self._compact_json(data)
                headers = self.headers(method_u, path, body=raw)
                send: Any = raw.encode("utf-8")
            elif isinstance(data, str):
                headers = self.headers(method_u, path, body=data)
                send = data.encode("utf-8")
            elif isinstance(data, bytes):
                headers = self.headers(method_u, path, body=data.decode("utf-8"))
                send = data
            else:
                raise TypeError("data must be dict/list/str/bytes")
            return (session or requests).request(
                method_u,
                self._url(path),
                params=params,
                data=send,
                headers=headers,
                timeout=timeout,
            )

        if payload is not None:
            raw = self._compact_json(payload)
            headers = self.headers(method_u, path, body=raw)
            return (session or requests).request(
                method_u,
                self._url(path),
                params=params,
                data=raw.encode("utf-8"),
                headers=headers,
                timeout=timeout,
            )

        # no body
        headers = self.headers(method_u, path, body="")
        return (session or requests).request(
            method_u,
            self._url(path),
            params=params,
            headers=headers,
            timeout=timeout,
        )

    def get(self, path: str, *, params: Optional[Mapping[str, Any]] = None, **kw):
        return self.request("GET", path, params=params, **kw)

    def post(self, path: str, *, json: Any = None, params=None, **kw):
        return self.request("POST", path, json=json, params=params, **kw)

    # ---- Instagram helpers (same contract as web app) ----

    def get_instagram_job(self, instagram_account_id: str, session=None):
        """GET /advertising/publishers/instagram/jobs"""
        return self.get(
            "/advertising/publishers/instagram/jobs",
            params={
                "instagram_account_id": str(instagram_account_id),
                "data": "null",
            },
            session=session,
        )

    def skip_instagram_job(
        self,
        *,
        ads_id: int,
        object_id: str,
        account_id: int,
        type: str,
        session=None,
    ):
        """
        POST /advertising/publishers/instagram/skip-jobs

        Body (from JobDetail.skipJobs):
          {ads_id, object_id, account_id, type}
        """
        return self.post(
            "/advertising/publishers/instagram/skip-jobs",
            json={
                "ads_id": ads_id,
                "object_id": str(object_id),
                "account_id": account_id,
                "type": type,
            },
            session=session,
        )

    def complete_instagram_job(
        self,
        *,
        instagram_users_advertising_id: int,
        instagram_account_id: int,
        async_: bool = True,
        data: Any = None,
        comment_id: Optional[int] = None,
        message: Optional[str] = None,
        captcha: Optional[str] = None,
        captcha_data: Any = None,
        session=None,
    ):
        """
        POST /advertising/publishers/instagram/complete-jobs

        Body (from JobDetail.completeJob):
          {instagram_users_advertising_id, instagram_account_id, async, data, ...}
        """
        body: dict = {
            "instagram_users_advertising_id": instagram_users_advertising_id,
            "instagram_account_id": instagram_account_id,
            "async": async_,
            "data": data,
        }
        if comment_id is not None:
            body["comment_id"] = comment_id
        if message is not None:
            body["message"] = message
        if captcha is not None:
            body["captcha"] = captcha
        if captcha_data is not None:
            body["captcha_data"] = captcha_data
        return self.post(
            "/advertising/publishers/instagram/complete-jobs",
            json=body,
            session=session,
        )
