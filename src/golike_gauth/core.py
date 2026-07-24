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

# --- Crypto schemes (JS_24_7 index bundle) ---
# Gateway g-auth (hA / tm):
SALT = "glk-gauth-v3-2026q3"
HKDF_INFO = "aes-gcm-key"
# Sectoken mint g-auth (xA / dA) → server tra header sig:
SECTOKEN_SALT = "glk-sectoken-v31-2026q3"
SECTOKEN_HKDF_INFO = "aes-gcm-key-v31"

APP_VERSION = "26.07.24.1"
APP_CLIENT = "109096667105508"
BASE_API = "https://gateway.golike.net/api"
SECURITY_API = "https://api.golike.net"
SECURITY_SESSION_PATH = "/api/v1/security/session"
SECURITY_TOKEN_PATH = "/api/v1/security/token"
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
        raise ValueError("token must be a JWT with three segments")
    raw = b64url_decode(parts[1])
    return json.loads(raw.decode("utf-8"))


def jwt_user_id(token: str) -> int:
    """user_id = JWT sub."""
    payload = jwt_payload(token)
    sub = payload.get("sub")
    if sub is None:
        raise ValueError("JWT payload is missing required claim: sub")
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
        raise ValueError(
            f"GET /users/me returned non-JSON response: HTTP {resp.status_code}"
        )
    if resp.status_code != 200 or not (body.get("success") or body.get("status") == 200):
        detail = body.get("message") or body.get("error") or body
        raise ValueError(f"GET /users/me failed: HTTP {resp.status_code}: {detail}")
    data = body.get("data") or {}
    if not isinstance(data, dict):
        raise ValueError("GET /users/me returned an invalid data payload")
    return data


def security_session_headers(token: str) -> dict:
    """Header goi api.golike.net security (giong curl app — khong can g-device-id)."""
    return {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "vi,en-US;q=0.9,en;q=0.8",
        "Authorization": f"Bearer {token}",
        "Cache-Control": "no-cache",
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": "https://app.golike.net",
        "Pragma": "no-cache",
        "Referer": "https://app.golike.net/",
        "User-Agent": MOBILE_UA,
        "sec-ch-ua": '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }


def fetch_security_session(
    token: str,
    *,
    timeout: float = 30,
    session=None,
) -> dict:
    """
    POST https://api.golike.net/api/v1/security/session

    App goi API nay TRUOC khi get job TikTok. Response:
      {
        "signing_key": "<b64 32B>",
        "exp": 1784887743,
        "epoch": "0",
        "schemeVersion": "v3.2"
      }

    Raise ValueError neu rejected / thieu key.
    """
    import requests

    token = (token or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    http = session or requests
    url = f"{SECURITY_API}{SECURITY_SESSION_PATH}"
    resp = http.post(
        url,
        headers=security_session_headers(token),
        json={},
        timeout=timeout,
    )
    try:
        body = resp.json()
    except Exception:
        raise ValueError(
            f"POST /security/session returned non-JSON response: HTTP {resp.status_code}"
        )
    if not isinstance(body, dict):
        raise ValueError(
            f"POST /security/session returned an invalid payload: {type(body).__name__}"
        )

    sk = body.get("signing_key")
    if not sk or not isinstance(sk, str) or not sk.strip():
        reason = body.get("reason") or body.get("message") or "unknown"
        raise ValueError(
            f"POST /security/session did not return a signing_key: {reason}"
        )
    sk = sk.strip()
    parse_signing_key(sk)  # validate 32 bytes
    return {
        "signing_key": sk,
        "exp": body.get("exp"),
        "epoch": body.get("epoch"),
        "schemeVersion": body.get("schemeVersion") or body.get("scheme_version"),
        "raw": body,
    }


def resolve_signing_key(
    profile: Optional[Mapping[str, Any]] = None,
    *,
    signing_key: Optional[str] = None,
) -> Optional[str]:
    """
    Lay signing_key / firebase_id tu profile /users/me.

    App web: store.signing_key = data.firebase_id (khi co).
    Thu nhieu field vi API doi ten theo thoi ky.
    """
    if signing_key and str(signing_key).strip():
        cand = str(signing_key).strip()
        try:
            parse_signing_key(cand)
            return cand
        except ValueError:
            pass

    if not isinstance(profile, Mapping):
        return None

    # uu tien cac key thuong gap
    keys = (
        "firebase_id",
        "signing_key",
        "gauth_key",
        "g_auth_key",
        "store_signing_key",
        "firebaseId",
        "signingKey",
    )
    for key in keys:
        val = profile.get(key)
        if isinstance(val, str) and val.strip():
            try:
                parse_signing_key(val.strip())
                return val.strip()
            except ValueError:
                continue

    # nested: data.security / data.gauth
    for nest_key in ("security", "gauth", "auth", "meta"):
        nest = profile.get(nest_key)
        if not isinstance(nest, Mapping):
            continue
        for key in keys:
            val = nest.get(key)
            if isinstance(val, str) and val.strip():
                try:
                    parse_signing_key(val.strip())
                    return val.strip()
                except ValueError:
                    continue
    return None


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data.replace("-", "+").replace("_", "/") + pad)


def parse_signing_key(signing_key: str) -> bytes:
    """Decode 32-byte signing key from hex or base64/base64url."""
    if not signing_key or not isinstance(signing_key, str):
        raise ValueError("signing_key must be a non-empty string")

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
        f"signing_key must decode to exactly 32 bytes for AES-256; attempts={attempts}"
    )


def derive_aes_key(
    signing_key: str,
    *,
    salt: str = SALT,
    info: str = HKDF_INFO,
) -> bytes:
    """HKDF-SHA256(signing_key, salt, info) -> 32 bytes."""
    ikm = parse_signing_key(signing_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode("utf-8"),
        info=info.encode("utf-8"),
    ).derive(ikm)


def derive_sectoken_aes_key(signing_key: str) -> bytes:
    """Key cho mint sig (xA): salt glk-sectoken-v31-2026q3."""
    return derive_aes_key(
        signing_key, salt=SECTOKEN_SALT, info=SECTOKEN_HKDF_INFO
    )


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
    """r field for gateway g-auth (uA)."""
    return sha256_hex(f"{ts_ms}:{device_id}:{q}:{SALT}")[:16]


def sectoken_digest_r(ts_ms: int, user_id: int, q: str) -> str:
    """r field for sectoken g-auth (cA): sha256(sh:t:userId:q)[:16]."""
    return sha256_hex(f"{SECTOKEN_SALT}:{ts_ms}:{int(user_id)}:{q}")[:16]


def sectoken_digest_r2(device_id: str, method: str, path: str) -> str:
    """r2 field (fA): sha256hex(device|method|path|sh)[16:40]."""
    return sha256_hex(
        f"{device_id}|{method.upper()}|{path}|{SECTOKEN_SALT}"
    )[16:40]


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


def _aes_gcm_b64url(aes_key: bytes, payload: dict) -> str:
    """AES-GCM encrypt JSON payload -> b64url(iv12 || ct+tag)."""
    iv = secrets.token_bytes(12)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    ct = AESGCM(aes_key).encrypt(iv, plaintext, None)
    return b64url_encode(iv + ct)


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
    Gateway g-auth (hA) — salt glk-gauth-v3-2026q3.
    Payload: {t,x,d,u,n,k,q,r}
    """
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
    return _aes_gcm_b64url(derive_aes_key(signing_key), payload)


def generate_sectoken_g_auth(
    *,
    method: str,
    path: str,
    signing_key: str,
    device_id: str,
    user_id: int,
    body: JsonBody = None,
    ts_ms: Optional[int] = None,
) -> str:
    """
    Sectoken g-auth (xA) de POST /api/v1/security/token.
    salt glk-sectoken-v31-2026q3 + field r2.
    path: dung raw path API security, vd /api/v1/security/token
    """
    t = int(ts_ms if ts_ms is not None else time.time() * 1000)
    method_u = method.upper()
    # JS: k = path as passed (dx = "/api/v1/security/token")
    k = path if path.startswith("/") else "/" + path
    q = body_hash("" if body is None else body)
    payload = {
        "t": t,
        "x": generate_nonce_x(),
        "d": device_id,
        "u": int(user_id),
        "n": method_u,
        "k": k,
        "q": q,
        "r": sectoken_digest_r(t, int(user_id), q),
        "r2": sectoken_digest_r2(device_id, method_u, k),
    }
    return _aes_gcm_b64url(derive_sectoken_aes_key(signing_key), payload)


def resolve_tiktok_sig_act(path: str) -> Optional[str]:
    """
    uA match table in app:
      /tiktok/complete-jobs -> complete_job
      /tiktok/jobs          -> get_job
    """
    s = path or ""
    if "/tiktok/complete-jobs" in s:
        return "complete_job"
    if "/tiktok/jobs" in s and "/skip" not in s:
        return "get_job"
    return None


def split_path_query(path: str) -> tuple:
    """Return (path_no_query, query_string)."""
    s = path or ""
    if "?" in s:
        p, q = s.split("?", 1)
        return p, q
    return s, ""


def generate_sig(
    *,
    method: str,
    path: str,
    signing_key: str,
    device_id: str,
    user_id: int,
    token: str,
    body: JsonBody = None,
    base_url: str = BASE_API,
    plt: str = "tiktok",
    act: Optional[str] = None,
    timeout: float = 30,
) -> Optional[str]:
    """
    Mint header ``sig`` cho TikTok (JS_24_7: _A / xx).

    Flow:
      1. body = {plt, act, req:{method,path,query,body}}
      2. g-auth = generate_sectoken_g_auth(POST, /api/v1/security/token, body)
      3. POST https://api.golike.net/api/v1/security/token
      4. return response.data.token  (hoac response.token)
    """
    return mint_security_token(
        method=method,
        path=path,
        signing_key=signing_key,
        device_id=device_id,
        user_id=user_id,
        token=token,
        body=body,
        base_url=base_url,
        plt=plt,
        act=act,
        timeout=timeout,
    )


def mint_security_token(
    *,
    method: str,
    path: str,
    signing_key: str,
    device_id: str,
    user_id: int,
    token: str,
    body: JsonBody = None,
    base_url: str = BASE_API,
    plt: str = "tiktok",
    act: Optional[str] = None,
    timeout: float = 30,
) -> Optional[str]:
    """POST /api/v1/security/token → token dung lam header sig."""
    import requests

    act = act or resolve_tiktok_sig_act(path)
    if not act:
        return None

    path_only, query = split_path_query(path)
    if body is None:
        body_str = ""
    elif isinstance(body, str):
        body_str = body
    elif isinstance(body, bytes):
        body_str = body.decode("utf-8")
    else:
        body_str = json.dumps(body, ensure_ascii=False, separators=(",", ":"))

    canon = normalize_path(path_only, base_url)
    mint_body_obj = {
        "plt": plt,
        "act": act,
        "req": {
            "method": method.upper(),
            "path": canon,
            "query": query,
            "body": body_str,
        },
    }
    mint_body = json.dumps(mint_body_obj, ensure_ascii=False, separators=(",", ":"))
    g_auth = generate_sectoken_g_auth(
        method="POST",
        path=SECURITY_TOKEN_PATH,
        body=mint_body,
        signing_key=signing_key,
        device_id=device_id,
        user_id=int(user_id),
    )
    jwt = (token or "").strip()
    if jwt.lower().startswith("bearer "):
        jwt = jwt[7:].strip()
    headers = {
        "Content-Type": "application/json;charset=utf-8",
        "Authorization": f"Bearer {jwt}",
        "g-auth": g_auth,
        "g-device-id": device_id,
        "Origin": "https://app.golike.net",
        "Referer": "https://app.golike.net/",
        "User-Agent": MOBILE_UA,
        "Accept": "application/json, text/plain, */*",
    }
    url = f"{SECURITY_API}{SECURITY_TOKEN_PATH}"
    resp = requests.post(
        url, headers=headers, data=mint_body.encode("utf-8"), timeout=timeout
    )
    try:
        data = resp.json()
    except Exception:
        raise ValueError(
            f"POST /security/token returned non-JSON response: HTTP {resp.status_code}"
        )
    if resp.status_code >= 400:
        raise ValueError(
            f"POST /security/token failed: HTTP {resp.status_code}: {data!r}"
        )
    if isinstance(data, dict):
        if isinstance(data.get("token"), str) and data["token"]:
            return data["token"]
        inner = data.get("data")
        if isinstance(inner, dict) and isinstance(inner.get("token"), str):
            return inner["token"]
        if isinstance(inner, str) and inner:
            return inner
    raise ValueError("POST /security/token response is missing a token field")


def decode_g_auth(token: str, signing_key: str) -> dict:
    """Decrypt g-auth for debugging."""
    aes_key = derive_aes_key(signing_key)
    raw = b64url_decode(token)
    if len(raw) < 12 + 16:
        raise ValueError("g-auth token is too short to decrypt")
    iv, ct = raw[:12], raw[12:]
    pt = AESGCM(aes_key).decrypt(iv, ct, None)
    return json.loads(pt.decode("utf-8"))


def build_headers(
    *,
    token: str,
    signing_key: Optional[str] = None,
    user_id: int = 0,
    username: str = "",
    method: str = "GET",
    path: str = "/",
    body: JsonBody = None,
    device_id: Optional[str] = None,
    g_version: str = APP_VERSION,
    g_client: str = APP_CLIENT,
    user_agent: Optional[str] = None,
    extra: Optional[Mapping[str, str]] = None,
    with_sig: Optional[bool] = None,
    with_gauth: Optional[bool] = None,
    legacy_client_headers: bool = False,
) -> dict:
    """
    Build gateway headers.

    **Golike moi (2026):** chi can Bearer + g-device-id + g-username + t
    (khong g-auth, khong firebase_id, khong g-version/g-client) — giong curl app.

    **Legacy:** neu co signing_key va with_gauth=True (hoac auto khi co key
    + legacy_client_headers) thi them g-auth / sig.
    """
    did = generate_device_id(device_id)
    sign_body: JsonBody = "" if body is None else body
    ua = user_agent or MOBILE_UA
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "vi,en-US;q=0.9,en;q=0.8",
        "authorization": f"Bearer {token}",
        "content-type": "application/json;charset=utf-8",
        "g-device-id": did,
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
    if username:
        headers["g-username"] = username

    sk = (signing_key or "").strip() or None
    # Mac dinh: KHONG gui g-auth (API moi). Chi bat khi with_gauth=True.
    use_gauth = False
    if with_gauth is True:
        use_gauth = True
    elif with_gauth is False:
        use_gauth = False
    elif legacy_client_headers and sk:
        use_gauth = True

    if use_gauth:
        if not sk:
            raise ValueError("with_gauth=True requires a valid signing_key")
        headers["g-auth"] = generate_g_auth(
            method=method,
            path=path,
            body=sign_body,
            signing_key=sk,
            device_id=did,
            user_id=int(user_id or 0),
        )
        if legacy_client_headers:
            headers["g-version"] = g_version
            headers["g-client"] = g_client

    # TikTok: mint sig qua POST api.golike.net/api/v1/security/token
    need_sig = with_sig if with_sig is not None else (
        resolve_tiktok_sig_act(path) is not None
    )
    if need_sig:
        if not sk:
            raise ValueError(
                "TikTok requests require a signing_key to mint the sig header; "
                "call GolikeAuth.from_token with fetch_session=True or pass signing_key"
            )
        sig = mint_security_token(
            method=method,
            path=path,
            body=sign_body,
            signing_key=sk,
            device_id=did,
            user_id=int(user_id or 0),
            token=token,
        )
        if not sig:
            raise ValueError(
                "failed to mint sig: path is not a recognized TikTok jobs endpoint"
            )
        headers["sig"] = sig
    if extra:
        headers.update(dict(extra))
    return headers


class GolikeAuth:
    """Auth helper — Golike moi: chi JWT + device_id (khong bat g-auth)."""

    def __init__(
        self,
        *,
        token: str,
        signing_key: Optional[str] = None,
        user_id: int = 0,
        username: str = "",
        device_id: Optional[str] = None,
        g_version: str = APP_VERSION,
        g_client: str = APP_CLIENT,
        base_url: str = BASE_API,
        user_agent: Optional[str] = None,
        enable_sig: Optional[bool] = None,
        enable_gauth: Optional[bool] = None,
    ) -> None:
        self.token = token
        self.signing_key = (signing_key or "").strip() or None
        self.user_id = int(user_id or 0)
        self.username = username or ""
        self.device_id = generate_device_id(device_id)
        self.g_version = g_version
        self.g_client = g_client
        self.base_url = base_url.rstrip("/")
        self.user_agent = user_agent or MOBILE_UA
        self.profile: dict = {}
        self.security_session: dict = {}
        self.signing_key_exp: Optional[int] = None
        self.scheme_version: Optional[str] = None
        # None = auto bat sig cho path TikTok jobs/complete khi co signing_key
        # True = luon co gang gan sig | False = tat
        self.enable_sig = True if enable_sig is None else enable_sig
        # False = API moi (khong header g-auth). True = legacy AES g-auth
        self.enable_gauth = enable_gauth if enable_gauth is not None else False

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
        verify: bool = False,
        enable_sig: Optional[bool] = None,
        enable_gauth: Optional[bool] = None,
        fetch_session: bool = True,
        timeout: float = 30,
    ) -> "GolikeAuth":
        """
        Chi can JWT token.

        Golike moi (2026):
          1. GET gateway /users/me → profile
          2. POST api.golike.net/api/v1/security/session → signing_key
          3. TikTok jobs: header ``sig`` (AES token, khong con g-auth)

        fetch_session=False: bo buoc (2) — phai tu truyen signing_key.
        """
        token = (token or "").strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        user_id = jwt_user_id(token)
        did = generate_device_id(device_id)

        me = fetch_user_me(token, device_id=did, timeout=timeout)
        uname = (username or me.get("username") or me.get("name") or "user").strip()

        sk = resolve_signing_key(me, signing_key=signing_key)
        session_meta: dict = {}
        if not sk and fetch_session:
            session_meta = fetch_security_session(token, timeout=timeout)
            sk = session_meta.get("signing_key")

        use_gauth = bool(enable_gauth) if enable_gauth is not None else False
        if use_gauth and not sk:
            raise ValueError(
                "enable_gauth=True requires a signing_key from security/session "
                "or an explicit signing_key argument"
            )

        auth = cls(
            token=token,
            signing_key=sk,
            user_id=user_id,
            username=uname,
            device_id=did,
            user_agent=MOBILE_UA,
            enable_sig=enable_sig,
            enable_gauth=use_gauth,
        )
        auth.profile = dict(me)
        if session_meta:
            auth._apply_security_session(session_meta)

        if verify and use_gauth and sk:
            ok, detail = auth.verify_signing_key(timeout=timeout)
            if not ok:
                raise ValueError(
                    f"signing_key verification failed via /security/echo: {detail}"
                )
        return auth

    def _apply_security_session(self, meta: Mapping[str, Any]) -> None:
        self.security_session = dict(meta.get("raw") or meta)
        sk = meta.get("signing_key")
        if sk:
            self.signing_key = str(sk).strip()
        exp = meta.get("exp")
        try:
            self.signing_key_exp = int(exp) if exp is not None else None
        except (TypeError, ValueError):
            self.signing_key_exp = None
        ver = meta.get("schemeVersion") or meta.get("scheme_version")
        self.scheme_version = str(ver) if ver else None

    def refresh_signing_key(self, *, timeout: float = 30, force: bool = False) -> str:
        """
        Goi lai POST /security/session khi key het han (exp) hoac force=True.
        """
        if not force and self.signing_key and self.signing_key_exp:
            # refresh som 60s
            if int(time.time()) < int(self.signing_key_exp) - 60:
                return self.signing_key
        meta = fetch_security_session(self.token, timeout=timeout)
        self._apply_security_session(meta)
        if not self.signing_key:
            raise ValueError("refresh_signing_key returned an empty signing_key")
        return self.signing_key

    @property
    def firebase_id(self) -> Optional[str]:
        """Legacy alias — API moi thuong None."""
        if self.signing_key:
            return self.signing_key
        val = (self.profile or {}).get("firebase_id")
        return str(val).strip() if val else None

    @firebase_id.setter
    def firebase_id(self, value: Optional[str]) -> None:
        self.signing_key = (value or "").strip() or None

    def verify_signing_key(self, timeout: float = 30) -> tuple:
        """
        POST /security/echo (legacy). API moi khong can.
        Returns (ok: bool, detail: dict|str)
        """
        import requests

        if not self.signing_key:
            return False, "no signing_key"
        body = json.dumps({"ping": 1}, separators=(",", ":"))
        headers = self.headers(
            "POST", "/security/echo", body=body, with_gauth=True
        )
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
        if not self.signing_key:
            raise ValueError(
                "g_auth is unavailable without a signing_key; "
                "use headers, get, or post for the current API"
            )
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
        with_sig: Optional[bool] = None,
        with_gauth: Optional[bool] = None,
    ) -> dict:
        gauth_flag = self.enable_gauth if with_gauth is None else with_gauth
        if with_sig is not None:
            sig_flag = with_sig
        elif self.enable_sig is False:
            sig_flag = False
        elif self.enable_sig is True:
            # True: chi auto cho path TikTok; path khac khong ep sig
            sig_flag = (
                True
                if resolve_tiktok_sig_act(path) is not None
                else False
            )
        else:
            sig_flag = None  # auto trong build_headers

        # Auto refresh signing_key truoc khi ky sig
        need_sig = sig_flag if sig_flag is not None else (
            resolve_tiktok_sig_act(path) is not None
        )
        if need_sig:
            try:
                self.refresh_signing_key(force=False)
            except Exception:
                # neu chua co key / session reject — de build_headers raise ro
                pass

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
            with_sig=sig_flag,
            with_gauth=gauth_flag,
            legacy_client_headers=bool(gauth_flag),
        )

    def decode(self, g_auth_token: str) -> dict:
        if not self.signing_key:
            raise ValueError("signing_key is required to decode a g-auth token")
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
        with_sig: Optional[bool] = None,
    ):
        """
        Signed HTTP request for ANY gateway path.

        - GET/HEAD/DELETE without body → sign body as ""
        - POST/PUT/PATCH with json=dict → sign + send compact JSON (no spaces)
        - TikTok paths auto-add header `sig` (plt/act binding)
        - Do not use requests' json= yourself (it may add spaces and break q hash)
        """
        import requests
        from urllib.parse import urlencode

        method_u = method.upper()
        payload = json if json is not None else json_body

        # Path dung de ky g-auth/sig: gop query vao path string
        # (g-auth chi lay pathname; sig can ca query)
        sign_path = path
        if params and "?" not in path:
            sign_path = f"{path}?{urlencode(params)}"

        if data is not None and payload is not None:
            raise ValueError("pass only one of data or json")

        if data is not None:
            if isinstance(data, (dict, list)):
                raw = self._compact_json(data)
                headers = self.headers(
                    method_u, sign_path, body=raw, with_sig=with_sig
                )
                send: Any = raw.encode("utf-8")
            elif isinstance(data, str):
                headers = self.headers(
                    method_u, sign_path, body=data, with_sig=with_sig
                )
                send = data.encode("utf-8")
            elif isinstance(data, bytes):
                headers = self.headers(
                    method_u,
                    sign_path,
                    body=data.decode("utf-8"),
                    with_sig=with_sig,
                )
                send = data
            else:
                raise TypeError("data must be a dict, list, str, or bytes")
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
            headers = self.headers(method_u, sign_path, body=raw, with_sig=with_sig)
            return (session or requests).request(
                method_u,
                self._url(path),
                params=params,
                data=raw.encode("utf-8"),
                headers=headers,
                timeout=timeout,
            )

        # no body
        headers = self.headers(method_u, sign_path, body="", with_sig=with_sig)
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

    def put(self, path: str, *, json: Any = None, params=None, **kw):
        return self.request("PUT", path, json=json, params=params, **kw)

    def delete(self, path: str, *, params=None, **kw):
        return self.request("DELETE", path, params=params, **kw)
