# golike-gauth

[![PyPI](https://img.shields.io/pypi/v/golike-gauth.svg)](https://pypi.org/project/golike-gauth/)
[![Python](https://img.shields.io/pypi/pyversions/golike-gauth.svg)](https://pypi.org/project/golike-gauth/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Client auth for the **Golike gateway API** (2026): JWT + device headers, TikTok `sig` minting, optional legacy `g-auth`.

**Repo:** https://github.com/deno4908/golike-gauth  
**Version:** `0.1.8`

## Changelog

### 0.1.8 — TikTok `sig` encryption overhaul (JS bundle 24/7)

App no longer puts a locally encrypted blob directly into `sig`.  
TikTok jobs use a **two-step security API** on `api.golike.net`, with a **new AES-GCM scheme** separate from gateway `g-auth`.

#### Request flow

```text
JWT
 │
 ├─① POST https://api.golike.net/api/v1/security/session
 │     body: {}
 │     → { signing_key, exp, epoch, schemeVersion: "v3.2" }
 │
 ├─② POST https://api.golike.net/api/v1/security/token
 │     body: { plt, act, req: { method, path, query, body } }
 │     headers: Authorization, g-auth (sectoken scheme), g-device-id
 │     → { token }   ← this value is the gateway header `sig`
 │
 └─③ GET  https://gateway.golike.net/api/advertising/publishers/tiktok/jobs?...
       headers: Authorization, g-device-id, g-username, t, sig
       (no g-auth on the gateway TikTok call)
```

Missing `sig` on TikTok jobs → HTTP **403**  
`Vui lòng tải lại trang để cập nhật phiên bản mới nhất.`

#### Two crypto schemes

| | Gateway `g-auth` (legacy / optional) | Sectoken mint (`security/token`) |
|---|---|---|
| Used for | Optional gateway binding | Build `g-auth` **only** for step ② |
| HKDF salt | `glk-gauth-v3-2026q3` | `glk-sectoken-v31-2026q3` |
| HKDF info | `aes-gcm-key` | `aes-gcm-key-v31` |
| Digest `r` | `sha256(t:deviceId:bodyHash:salt)[:16]` | `sha256(salt:t:userId:bodyHash)[:16]` |
| Extra field | — | `r2 = sha256hex(deviceId\|METHOD\|path\|salt)[16:40]` |
| Output header | `g-auth` | server returns `token` → client sends as **`sig`** |

Cipher for both: **AES-256-GCM**, output `base64url(iv12 ‖ ciphertext+tag)`.

Sectoken payload example (step ② `g-auth` plaintext):

```json
{
  "t": 1784884100123,
  "x": "<nonce b64url>",
  "d": "<device-uuid>",
  "u": 639111,
  "n": "POST",
  "k": "/api/v1/security/token",
  "q": "<sha256 hex of mint body>",
  "r": "<16 hex chars>",
  "r2": "<24 hex chars>"
}
```

Mint body (`req.path` is gateway pathname, including `/api/...`):

```json
{
  "plt": "tiktok",
  "act": "get_job",
  "req": {
    "method": "GET",
    "path": "/api/advertising/publishers/tiktok/jobs",
    "query": "account_id=711964&data=null",
    "body": ""
  }
}
```

`act` mapping:

| Gateway path contains | `act` |
|---|---|
| `/tiktok/jobs` (not skip) | `get_job` |
| `/tiktok/complete-jobs` | `complete_job` |

#### Library API (0.1.8)

```python
from golike_gauth import GolikeAuth

auth = GolikeAuth.from_token("eyJ...")  # JWT only
# 1) GET gateway /users/me
# 2) POST security/session → signing_key
# 3) on TikTok get/post: mint security/token → header sig

r = auth.get(
    "/advertising/publishers/tiktok/jobs",
    params={"account_id": "711964", "data": "null"},
)
print(r.status_code, r.json())
```

Public helpers:

| Function | Role |
|---|---|
| `fetch_security_session(token)` | step ① |
| `mint_security_token(...)` / `generate_sig(...)` | step ② |
| `generate_sectoken_g_auth(...)` | local AES for step ② `g-auth` |
| `generate_g_auth(...)` | legacy gateway scheme |
| `auth.refresh_signing_key()` | refresh before `exp` |

Constants: `SALT`, `SECTOKEN_SALT`, `SECURITY_API`, `APP_VERSION` (`26.07.24.1`).

#### Breaking notes vs 0.1.6 / early 0.1.7

- Do **not** put gateway-style `generate_g_auth(...)` into header `sig` — server rejects it.
- Do **not** expect `firebase_id` from `/users/me`.
- `signing_key` comes from **`security/session`**, not profile.
- `sig` is a **server-minted** token from `security/token`, not a pure local encrypt of the jobs request.

### 0.1.7

- Auto `POST /security/session` in `from_token` (`fetch_session=True`).
- `fetch_security_session` / `refresh_signing_key`.

### 0.1.6

- Default **no** gateway `g-auth` on normal requests.
- Bearer + `g-device-id` + `g-username` + `t`.
- `/users/me` without `firebase_id`.

### 0.1.5

- Gỡ helper theo platform (`get_instagram_job`, `get_tiktok_job`, …).
- Auth dùng chung: `from_token` + `get` / `post` / `put` / `delete` / `request` / `headers`.

### 0.1.4

- `enable_sig` trên `GolikeAuth` / `from_token` (TikTok `sig`).

### 0.1.3

- Header `sig` TikTok; gộp query vào path khi ký.

### 0.1.2

- `from_token(token)` bootstrap `/users/me` + `firebase_id` (API cũ).

### 0.1.1 / 0.1.0

- HKDF + AES-GCM `g-auth`, `g-device-id`, header `t`.

### Nâng cấp

```bash
pip install -U "golike-gauth[requests]"
```

**Breaking (0.1.6):** mặc định **không** sinh `g-auth`. Code cũ dựa vào `auth.signing_key` / `auth.g_auth()` bắt buộc → truyền `enable_gauth=True` + `signing_key`, hoặc bỏ hẳn (API mới không cần).

**Breaking (0.1.5):** `get_tiktok_job` / `get_instagram_job` → dùng `auth.get` / `auth.post`.

## Install

```bash
pip install -U golike-gauth

# HTTP helper (requests) — khuyến nghị
pip install -U "golike-gauth[requests]"

# từ GitHub
pip install -U git+https://github.com/deno4908/golike-gauth.git
```

## Quick start

### Chỉ cần token (API 2026 — khuyến dùng)

```python
from golike_gauth import GolikeAuth

auth = GolikeAuth.from_token("eyJ...")  # chỉ token

print(auth.user_id)       # JWT sub
print(auth.username)      # /users/me
print(auth.device_id)     # UUID tự sinh
print(auth.signing_key)   # None (API mới không firebase_id)
print(auth.profile)       # raw /users/me
```

#### Flow `from_token` làm gì?

| Bước | Nguồn | Kết quả |
|---|---|---|
| 1 | Decode JWT | `user_id` = `sub` |
| 2 | `GET /users/me` (UA mobile) | `username`, `coin`, profile… (**không** `firebase_id`) |
| 3 | `signing_key` | `None` (API mới) — chỉ set nếu `enable_gauth=True` |
| 4 | `device_id` | UUID v4 (tự tạo) |
| 5 | Headers | Bearer + `g-device-id` + `g-username` + `t` — **không** `g-auth` |

```python
# mac dinh API moi
auth = GolikeAuth.from_token("eyJ...")

# legacy g-auth (hiếm)
auth = GolikeAuth.from_token(
    "eyJ...",
    signing_key="cxbbf6td1EXc...",
    enable_gauth=True,
    verify=True,
)
```

#### Lấy token từ đâu?

Trên https://app.golike.net (đã login, F12 → Network):

- Request bất kỳ → header `Authorization: Bearer eyJ...`
- Hoặc Application / Local Storage / vuex (field `token`)

#### Ví dụ: lấy job Facebook chỉ với token

```python
from golike_gauth import GolikeAuth

auth = GolikeAuth.from_token("eyJ...")

# list account FB tren Golike
accs = auth.get("/fb-account", params={"limit": 200}).json().get("data") or []
fb_id = accs[0]["fb_id"]

r = auth.get(
    "/advertising/publishers/get-jobs-2026",
    params={"fb_id": fb_id, "server": "sv2", "high_job": 1, "low_job": 1},
)
print(r.status_code, r.json())
```

Script mẫu trong workspace: `test_fb_jobs.py` (chỉ hỏi token).

### Thủ công (5 trường)

```python
from golike_gauth import GolikeAuth

auth = GolikeAuth(
    token="eyJ...",              # JWT Bearer
    signing_key="...",           # = firebase_id hoac store.state.signing_key
    user_id=123456,              # JWT sub
    username="your_username",
    device_id="32484704-8a4e-4909-9d42-866773b321d6",  # nên giữ cố định
)
```

Lib dùng được với **mọi** path gateway. Chỉ cần đúng **method + path + body/query** như browser.

### Cách dùng chung (khuyến nghị)

```python
# GET — không body, params = query string
r = auth.get("/path/to/api", params={"key": "value"})
print(r.status_code, r.json())

# POST — có JSON body (g-auth ký đúng body compact, không space)
r = auth.post("/path/to/api", json={"a": 1, "b": "x"})
print(r.status_code, r.json())

# method bất kỳ
r = auth.request("PUT", "/path/to/api", json={...})
r = auth.request("DELETE", "/path/to/api")
```

### Ví dụ thật theo platform

#### Instagram — lấy job (GET)

```python
r = auth.get(
    "/advertising/publishers/instagram/jobs",
    params={
        "instagram_account_id": "966624",
        "data": "null",
    },
)
# hoặc helper:
r = auth.get_instagram_job("966624")
print(r.json())
```

#### Instagram — skip job (POST, không phải GET!)

```python
r = auth.post(
    "/advertising/publishers/instagram/skip-jobs",
    json={
        "ads_id": 620978,
        "object_id": "6155111723",
        "account_id": 966624,
        "type": "follow",  # follow | like | comment | ...
    },
)
# hoặc helper:
r = auth.skip_instagram_job(
    ads_id=620978,
    object_id="6155111723",
    account_id=966624,
    type="follow",
)
print(r.json())
```

#### Instagram — complete job (POST)

```python
r = auth.post(
    "/advertising/publishers/instagram/complete-jobs",
    json={
        "instagram_users_advertising_id": 620978,
        "instagram_account_id": 966624,
        "async": True,
        "data": None,
    },
)
# hoặc helper:
r = auth.complete_instagram_job(
    instagram_users_advertising_id=620978,
    instagram_account_id=966624,
)
print(r.json())
```

#### Twitter / X — lấy job (GET)

Tương đương curl:

`GET /api/advertising/publishers/twitter/jobs?account_id=97445`

```python
r = auth.get(
    "/advertising/publishers/twitter/jobs",
    params={"account_id": "97445"},
)
print(r.status_code, r.json())
```

#### TikTok / Facebook / … (cùng pattern)

```python
# GET jobs (query tùy platform — copy từ Network tab browser)
r = auth.get(
    "/advertising/publishers/tiktok/jobs",
    params={"account_id": "123"},  # hoặc param khác tùy API
)

# POST skip / complete — luôn dùng auth.post(..., json={...})
r = auth.post(
    "/advertising/publishers/tiktok/skip-jobs",
    json={...},  # body copy từ Network tab
)
```

#### Users / endpoint khác

```python
r = auth.get("/users/me")
r = auth.post("/some/path", json={"foo": "bar"})
```

### Sai thường gặp

```python
# ❌ SAI: auth.post() đã gọi API, không phải headers
# ❌ SAI: skip-jobs dùng GET → 405
response = requests.get(
    "https://gateway.golike.net/api/advertising/publishers/instagram/skip-jobs",
    headers=auth.post("/advertising/publishers/instagram/skip-jobs", json={...}),
)

# ✅ ĐÚNG
response = auth.post(
    "/advertising/publishers/instagram/skip-jobs",
    json={
        "ads_id": 620978,
        "object_id": "6155111723",
        "account_id": 966624,
        "type": "follow",
    },
)
print(response.json())
```

Nếu tự dùng `requests`, **method + body bytes** phải khớp lúc ký:

```python
import json
import requests

body = {
    "ads_id": 620978,
    "object_id": "6155111723",
    "account_id": 966624,
    "type": "follow",
}
raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False)  # không space
headers = auth.headers(
    "POST",
    "/advertising/publishers/instagram/skip-jobs",
    body=raw,
)
response = requests.post(
    "https://gateway.golike.net/api/advertising/publishers/instagram/skip-jobs",
    headers=headers,
    data=raw.encode("utf-8"),
)
```

### Headers only / low-level

```python
from golike_gauth import generate_g_auth, generate_device_id, decode_g_auth

# headers: method/path/body phải trùng request thật
headers = auth.headers(
    "GET",
    "/advertising/publishers/twitter/jobs",
    body="",  # GET không body
)

g_auth = generate_g_auth(
    method="GET",
    path="/advertising/publishers/twitter/jobs",
    body="",
    signing_key="...",
    device_id=generate_device_id(),
    user_id=123456,
)
print(decode_g_auth(g_auth, "..."))
```

### Method cheatsheet

| API | Method | Params / Body |
|---|---|---|
| `/advertising/publishers/instagram/jobs` | **GET** | query: `instagram_account_id`, `data` |
| `/advertising/publishers/instagram/skip-jobs` | **POST** | JSON: `{ads_id, object_id, account_id, type}` |
| `/advertising/publishers/instagram/complete-jobs` | **POST** | JSON: `{instagram_users_advertising_id, instagram_account_id, async, data, ...}` |
| `/advertising/publishers/twitter/jobs` | **GET** | query: `account_id` |
| `/users/me` | **GET** | — |
| path khác | copy từ browser Network | **đúng method + body như browser** |

Quy tắc:

1. **GET** → `auth.get(path, params=...)` — body ký = `""`
2. **POST** → `auth.post(path, json=...)` — body ký = JSON compact
3. **405** = sai method (vd. GET `skip-jobs`)
4. **g-auth** tạo mới **mỗi request**, khớp method + path + body
5. Path truyền vào **không** cần `/api` prefix (`auth` tự thêm base `.../api`)

## Where to get `signing_key`

On https://app.golike.net (logged in), DevTools console:

```js
document.querySelector('#app').__vue__.$store.state.signing_key
```

> This value may differ from `data.firebase_id` in `/users/me`. Always use the store key the browser actually signs with.

## CLI

```bash
golike-gauth \
  --token eyJ... \
  --signing-key ... \
  --user-id 123456 \
  --username your_username \
  --call --ig-account-id YOUR_IG_ACCOUNT_ID
```

## Notes

- `g-auth` must be **regenerated for every request** (binds method + path + body hash + timestamp).
- GET requests sign body as empty string `""`.
- Path signed is pathname only, e.g. `/api/advertising/publishers/instagram/jobs`.

## Development

```bash
git clone https://github.com/deno4908/golike-gauth.git
cd golike-gauth
python -m pip install -e ".[dev,requests]"
```

### Build & publish (PyPI)

```bash
python -m pip install -U build twine
python -m build
python -m twine upload dist/*
```

## Contributing

Issues and PRs: https://github.com/deno4908/golike-gauth/issues

## License

[MIT](LICENSE) — see [LICENSE](https://github.com/deno4908/golike-gauth/blob/main/LICENSE)

---

# Phân tích mã hóa / giải mã `g-auth` (Golike Gateway)

Tài liệu này mô tả cách app web Golike tạo header **`g-auth`** cho mỗi request tới `gateway.golike.net`, và cách server (hoặc client debug) giải mã token đó.

Nguồn reverse: bundle `index-68ef440b.js` (các hàm `H_`, `q_`, `Mg`, `M_`, `j_`, `Jd`, `aA`, `bu`).

---

## 1. Vai trò của `g-auth`

`g-auth` là **request-binding token**: mỗi request HTTP mang một token mới, gắn với:

| Trường payload | Ý nghĩa |
|---|---|
| `n` | HTTP method (`GET` / `POST` / …) |
| `k` | Pathname API (không có query) |
| `q` | SHA-256 hex của body |
| `d` | `g-device-id` (UUID) |
| `u` | `user_id` |
| `t` | timestamp client (ms) |
| `x` | nonce ngẫu nhiên |
| `r` | digest ngắn chống giả mạo thô |

Token được **mã hóa AES-GCM** bằng khóa dẫn xuất từ `signing_key` của user. Server giải mã → kiểm tra method/path/body/device/user/time → cho phép request.

> `g-auth` **không tái sử dụng** được giữa các request (path/body/time khác nhau, và có nonce).

---

## 2. Các header liên quan

Ngoài JWT `Authorization: Bearer …`, client còn gửi:

| Header | Nguồn / công thức |
|---|---|
| `g-auth` | AES-GCM token (mục 4–5) |
| `g-device-id` | UUID v4, lưu `localStorage.device_id` |
| `g-username` | username user |
| `g-version` | version app, ví dụ `26.07.10.2` |
| `g-client` | client id app |
| `t` | `btoa(btoa(btoa(unix_seconds)))` — timestamp 3 lớp Base64 |

---

## 3. `signing_key` — nguyên liệu khóa

### 3.1. Lấy key ở đâu?

Trong Vuex store:

```js
$store.state.signing_key
// DevTools:
document.querySelector('#app').__vue__.$store.state.signing_key
```

> **Lưu ý thực tế:** giá trị store **có thể khác** `data.firebase_id` trả về từ `GET /users/me`.  
> Luôn dùng đúng key mà browser đang ký (store / console), không chỉ dựa vào field API.

Key là **32 bytes**, thường encode **Base64** (có `+`, `/`, `=`), ví dụ:

```text
cxbbf6td1EXcoEWlnk0eVmJwG1NJYhiqPxNcUXG+cBc=
```

Client cũng chấp nhận hex 64 ký tự.

### 3.2. Parse key (`k_`)

```
nếu chuỗi là hex hợp lệ và decode ra 32 bytes  → dùng
else decode Base64 / Base64URL → 32 bytes     → dùng
else lỗi: signing key must decode to 32 bytes
```

---

## 4. Dẫn xuất khóa AES (HKDF)

Trước khi AES-GCM, raw key 32 bytes được đưa qua **HKDF-SHA256**:

| Tham số | Giá trị |
|---|---|
| IKM | 32 bytes từ `signing_key` |
| Hash | SHA-256 |
| Salt | `glk-gauth-v3-2026q3` |
| Info | `aes-gcm-key` |
| Output length | 32 bytes |

```
AES_KEY = HKDF-SHA256(
  ikm  = decode(signing_key),
  salt = "glk-gauth-v3-2026q3",
  info = "aes-gcm-key",
  len  = 32
)
```

Hằng số trong JS:

```js
B_ = "glk-gauth"
E_ = "v3-2026"          // sn(247)
S_ = "q3"
Sg = B_ + "-" + E_ + S_ // => "glk-gauth-v3-2026q3"
I_ = "aes-gcm-key"
```

`AES_KEY` import vào WebCrypto / OpenSSL dưới dạng **AES-256-GCM**.

---

## 5. Tạo payload trước khi mã hóa

### 5.1. Chuẩn hóa path (`Pg` + `yu`)

- Bỏ query (`?...`) và hash (`#...`)
- Ghép với base `https://gateway.golike.net/api`
- Chỉ lấy **pathname**

Ví dụ:

```text
request URL:
  /advertising/publishers/instagram/jobs?instagram_account_id=966624&data=null

signed path k:
  /api/advertising/publishers/instagram/jobs
```

### 5.2. Hash body (`j_`)

```text
body_str =
  null/undefined  →  ""
  string          →  chính nó
  object          →  JSON.stringify(obj)   // compact, không space
                     // JS: JSON.stringify → {"a":1}

q = SHA256_hex(body_str)
```

**GET / HEAD / DELETE** trong app: body ký = chuỗi rỗng `""`

```text
q = SHA256("")
  = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### 5.3. Digest `r` (`M_`)

```text
r = SHA256_hex( f"{t}:{device_id}:{q}:{salt}" )[0:16]
```

với `salt = glk-gauth-v3-2026q3`, `t` là timestamp **milliseconds**.

### 5.4. Object payload đầy đủ

Thứ tự key (quan trọng vì `JSON.stringify` giữ insertion order):

```json
{
  "t": 1783944428398,
  "x": "z7Yv5E5ClYSc0gyyjllQ2w",
  "d": "32484704-8a4e-4909-9d42-866773b321d6",
  "u": 639111,
  "n": "GET",
  "k": "/api/advertising/publishers/instagram/jobs",
  "q": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "r": "286c4f5bd68ec1c4"
}
```

| Field | Mô tả |
|---|---|
| `t` | `Date.now()` (ms) |
| `x` | 16 bytes random → Base64URL (no padding) |
| `d` | device UUID (`g-device-id`) |
| `u` | user id (number) |
| `n` | method upper-case |
| `k` | pathname đã chuẩn hóa |
| `q` | body hash |
| `r` | digest 16 hex chars |

Chuỗi plaintext:

```text
plaintext = JSON.stringify(payload)   // separators mặc định JS: không space
         → UTF-8 bytes
```

---

## 6. Mã hóa (encrypt) — `H_`

```
IV  = 12 bytes random          (crypto.getRandomValues)
CT  = AES-256-GCM.Encrypt(
        key = AES_KEY,
        iv  = IV,
        pt  = plaintext_utf8
      )
      // CT = ciphertext || 16-byte auth tag  (WebCrypto / cryptography)

token_bytes = IV || CT
g-auth      = Base64URL(token_bytes)   // bỏ padding '='
```

Sơ đồ:

```
signing_key (b64/hex)
        │
        ▼ decode 32B
       IKM
        │
        ▼ HKDF-SHA256(salt, info)
     AES_KEY (32B)
        │
        │   ┌─ method, path, body, device, user, now ─┐
        │   ▼                                         │
        │  JSON payload {t,x,d,u,n,k,q,r}             │
        │   ▼ UTF-8                                   │
        │  plaintext ──────────┐                      │
        │                      │                      │
        ▼                      ▼                      │
   AES-256-GCM(IV=12B)  ←── encrypt                   │
        │                                             │
        ▼                                             │
   IV || ciphertext+tag                               │
        │                                             │
        ▼ Base64URL                                   │
     header g-auth ───────────────────────────────────┘
```

---

## 7. Giải mã (decrypt) — `q_` / server / debug

```
raw = Base64URL_decode(g-auth)
IV  = raw[0:12]
CT  = raw[12:]          // ciphertext + tag

plaintext = AES-256-GCM.Decrypt(AES_KEY, IV, CT)
payload   = JSON.parse(plaintext)
```

Sau khi giải mã, server thường kiểm tra:

1. **Decrypt OK** (key + IV + tag đúng)
   - Fail → `decrypt_fail_check_signing_key_or_iv_or_tag_or_r_field`
2. **`n`** khớp HTTP method
3. **`k`** khớp pathname canonical (vd. `/api/...`)
4. **`q`** khớp SHA256 body thực tế nhận được
5. **`d` / `u`** khớp session / JWT
6. **`t`** không lệch quá xa server time (`ts_drift_ms`)
7. **`r`** khớp lại công thức digest

Endpoint debug hữu ích:

```http
POST /api/security/echo
```

Response có block `gauth` mô tả lỗi decode / match.

---

## 8. Ví dụ end-to-end (GET jobs)

### Request

```http
GET /api/advertising/publishers/instagram/jobs?instagram_account_id=966624&data=null
Authorization: Bearer <jwt>
g-device-id: 32484704-8a4e-4909-9d42-866773b321d6
g-username: vinhhacker
g-auth: Zmo3WFa5lp2X...
t: VFZSak5FMTZhekJPUkZGNVQwRTlQUT09
```

### Payload đã giải mã (thực tế từ browser)

```json
{
  "t": 1783944428398,
  "x": "z7Yv5E5ClYSc0gyyjllQ2w",
  "d": "32484704-8a4e-4909-9d42-866773b321d6",
  "u": 639111,
  "n": "GET",
  "k": "/api/advertising/publishers/instagram/jobs",
  "q": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "r": "286c4f5bd68ec1c4"
}
```

### Tính lại `q` và `r`

```text
q = SHA256("")
  = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

r = SHA256(
      "1783944428398"
      + ":" + "32484704-8a4e-4909-9d42-866773b321d6"
      + ":" + q
      + ":" + "glk-gauth-v3-2026q3"
    )[:16]
  = 286c4f5bd68ec1c4
```

---

## 9. Header `t` (không nằm trong AES)

```js
t = btoa(btoa(btoa(String(unix_seconds))))
```

Ví dụ:

```text
unix = 1783944424
→ btoa × 3 → "VFZSak5FMTZhekJPUkZGNVQwRTlQUT09"
```

Đây là timestamp phụ (giây), tách biệt field `t` (ms) bên trong `g-auth`.

---

## 10. Pseudocode Python

```python
import base64, hashlib, json, secrets, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

SALT = "glk-gauth-v3-2026q3"
INFO = "aes-gcm-key"

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def derive_key(signing_key_b64: str) -> bytes:
    ikm = base64.b64decode(signing_key_b64)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT.encode(),
        info=INFO.encode(),
    ).derive(ikm)

def encrypt_g_auth(method, path, body, signing_key, device_id, user_id) -> str:
    key = derive_key(signing_key)
    iv = secrets.token_bytes(12)
    t = int(time.time() * 1000)
    q = sha256_hex(body if body is not None else "")
    r = sha256_hex(f"{t}:{device_id}:{q}:{SALT}")[:16]
    payload = {
        "t": t,
        "x": b64url(secrets.token_bytes(16)),
        "d": device_id,
        "u": user_id,
        "n": method.upper(),
        "k": path,
        "q": q,
        "r": r,
    }
    pt = json.dumps(payload, separators=(",", ":")).encode()
    ct = AESGCM(key).encrypt(iv, pt, None)  # ct + tag
    return b64url(iv + ct)

def decrypt_g_auth(token: str, signing_key: str) -> dict:
    key = derive_key(signing_key)
    pad = "=" * (-len(token) % 4)
    raw = base64.urlsafe_b64decode(token.replace("-", "+").replace("_", "/") + pad)
    iv, ct = raw[:12], raw[12:]
    pt = AESGCM(key).decrypt(iv, ct, None)
    return json.loads(pt)
```

---

## 11. Lỗi thường gặp

| Triệu chứng | Nguyên nhân |
|---|---|
| `decrypt_fail_...` | Sai `signing_key`, hỏng token, hoặc không đúng thuật toán HKDF/AES |
| `AUTH_MISSING` | Không gửi `g-auth` (và/hoặc header bắt buộc khác) |
| `403` “cập nhật phiên bản…” | Token thiếu/sai trên endpoint jobs; server từ chối client “cũ/không ký” |
| 200 ở browser, 403 ở script | Reuse `g-auth` cũ; hoặc path/body hash khác (space trong JSON, thiếu `/api`, …) |
| Decode local OK nhưng server fail | Key local ≠ key server đang expect; lấy lại từ `store.state.signing_key` |

---

## 12. Checklist implement đúng

1. `signing_key` = **store browser**, decode ra đúng 32 bytes
2. HKDF salt = `glk-gauth-v3-2026q3`, info = `aes-gcm-key`
3. Path ký = pathname có prefix `/api/...`, **không** query
4. GET body ký = `""`
5. POST body ký = **cùng bytes** body gửi đi (`JSON` compact nếu stringify)
6. Payload JSON **không space**, đúng thứ tự key `t,x,d,u,n,k,q,r`
7. AES-GCM IV 12 bytes, output `Base64URL(IV || CT||TAG)`
8. **Mỗi request** tạo `g-auth` mới

---

## 13. Tóm tắt một dòng

> **`g-auth` = Base64URL( IV₁₂ ‖ AES-256-GCM<sub>HKDF(signing_key)</sub>( JSON{method, path, bodyHash, device, user, time, nonce, digest} ) )**
