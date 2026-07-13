# golike-gauth

Generate valid **`g-auth`** / **`g-device-id`** headers for the Golike gateway API.

## Install

```bash
pip install golike-gauth
# optional HTTP helper
pip install golike-gauth[requests]
```

## Quick start

```python
from golike_gauth import GolikeAuth

auth = GolikeAuth(
    token="eyJ...",                 # JWT Bearer
    signing_key="cxbbf6td1EXc...",  # from browser store.state.signing_key
    user_id=639111,
    username="vinhhacker",
    device_id="32484704-8a4e-4909-9d42-866773b321d6",  # optional, keep stable
)

# headers only
headers = auth.headers("GET", "/advertising/publishers/instagram/jobs", body="")

# full signed request (needs: pip install requests)
resp = auth.get_instagram_job("966624")
print(resp.status_code, resp.json())
```

### Low-level API

```python
from golike_gauth import generate_g_auth, generate_device_id, decode_g_auth

device_id = generate_device_id()
token = generate_g_auth(
    method="GET",
    path="/advertising/publishers/instagram/jobs",
    body="",
    signing_key="...",
    device_id=device_id,
    user_id=639111,
)
print(decode_g_auth(token, "..."))
```

## Where to get `signing_key`

On https://app.golike.net (logged in), DevTools console:

```js
document.querySelector('#app').__vue__.$store.state.signing_key
```

> Note: this may differ from `data.firebase_id` in `/users/me`. Always use the store value that the browser actually signs with.

## CLI

```bash
golike-gauth --token eyJ... --signing-key ... --user-id 639111 --username vinhhacker \
  --device-id 32484704-8a4e-4909-9d42-866773b321d6 \
  --call --ig-account-id 966624
```

## Notes

- `g-auth` must be **regenerated for every request** (binds method + path + body hash + timestamp).
- GET requests sign body as empty string `""`.
- Path signed is pathname only, e.g. `/api/advertising/publishers/instagram/jobs`.

## Publish to PyPI

```bash
cd golike-gauth
python -m pip install -U build twine
python -m build
python -m twine upload dist/*
```

## License

MIT

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
