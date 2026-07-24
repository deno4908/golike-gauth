"""
Test TikTok jobs API: so sanh request KHONG sig vs CO sig.

Golike moi (2026):
  - Khong g-auth / firebase_id
  - TikTok jobs VAN bat header `sig` (thieu -> 403)
  - Co sig hop le -> 200

Chay:
  python examples/test_tiktok_sig.py
  python examples/test_tiktok_sig.py --token eyJ... --account-id 711964
  python examples/test_tiktok_sig.py --sig "UGHM..."   # dung sig bat tu browser
  python examples/test_tiktok_sig.py --signing-key "..."  # thu gen sig bang lib
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# cho phep chay truc tiep tu source tree
_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import requests

from golike_gauth import GolikeAuth, generate_sig
from golike_gauth.core import BASE_API


DEFAULT_TOKEN = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
    "eyJpc3MiOiJodHRwOlwvXC9nYXRld2F5LmdvbGlrZS5uZXRcL2FwaVwvbG9naW4iLCJpYXQiOjE3ODQ4NjM2MzEsImV4cCI6MTgxNjM5OTYzMSwibmJmIjoxNzg0ODYzNjMxLCJqdGkiOiJ3Q0txRXJOelo0V0x5MFh0Iiwic3ViIjo2MzkxMTEsInBydiI6ImI5MTI3OTk3OGYxMWFhN2JjNTY3MDQ4N2ZmZjAxZTIyODI1M2ZlNDgifQ."
    "dkx0h78y-leZwoGMkvZxf6C1pI71cEvE-xAeqyhju_E"
)
DEFAULT_DEVICE = "6b9f29d1-97ba-4a0a-8e49-e14f04d39b33"
DEFAULT_ACCOUNT = "711964"
# sig bat tu browser (curl user) — co the het han theo thoi gian
DEFAULT_BROWSER_SIG = (
    "UGHMpHn7Brv-1oFQGcp67fpLOcmPmDH_4HozDfkamr7OqRYu-N2NhEXXh-R2AHWNn-6dK1_3nv_C6"
    "zuibixr1fuiRdjGeYPXO2i2wlKrabQljqi6GJjl2C7i-sZYJC0lvZeJjRKlEcO24GejJC53KtIcSUnI"
    "joB8hj2S0FXez0fOdf_sDWVDLnqn9AmjgbZANNy9d331Z1Gg62K3rouh70PR55Ajaph8qTEwUH8xeRM"
    "U_dAaq5NmhWbiEfrDSR2ze-aWBFX63zgDuKNf7sE7n6E0AuS4GEzWsd5zhldY45wdqEjUQQhogv0u87"
    "cAYw"
)

JOBS_PATH = "/advertising/publishers/tiktok/jobs"


def _brief(resp: requests.Response, limit: int = 280) -> str:
    text = (resp.text or "").replace("\n", " ")
    return f"HTTP {resp.status_code} | {text[:limit]}"


def _call(auth: GolikeAuth, *, sig: str | None, params: dict) -> requests.Response:
    """GET jobs voi headers API moi (+ optional sig)."""
    query = f"account_id={params['account_id']}&data={params.get('data', 'null')}"
    sign_path = f"{JOBS_PATH}?{query}"
    headers = auth.headers("GET", sign_path, body="")
    # dam bao khong dan g-auth
    headers.pop("g-auth", None)
    headers.pop("g-version", None)
    headers.pop("g-client", None)
    if sig:
        headers["sig"] = sig
    else:
        headers.pop("sig", None)

    print("  headers:", ", ".join(sorted(headers.keys())))
    if sig:
        print("  sig[:40]:", sig[:40] + "...")
    return requests.get(
        f"{BASE_API}{JOBS_PATH}",
        params=params,
        headers=headers,
        timeout=30,
    )


def main() -> int:
    p = argparse.ArgumentParser(description="Test TikTok jobs API vs header sig")
    p.add_argument("--token", default=DEFAULT_TOKEN)
    p.add_argument("--device-id", default=DEFAULT_DEVICE)
    p.add_argument("--account-id", default=DEFAULT_ACCOUNT)
    p.add_argument(
        "--sig",
        default=DEFAULT_BROWSER_SIG,
        help="sig bat tu browser (F12). De trong '' de bo qua case browser sig",
    )
    p.add_argument(
        "--signing-key",
        default=None,
        help="neu co: thu gen sig bang golike_gauth.generate_sig",
    )
    args = p.parse_args()

    print("=== bootstrap from_token (API moi, khong firebase_id) ===")
    auth = GolikeAuth.from_token(
        args.token,
        device_id=args.device_id,
        verify=False,
        enable_gauth=False,
    )
    print(f"  user={auth.username} id={auth.user_id}")
    print(f"  device={auth.device_id}")
    print(f"  signing_key={auth.signing_key!r}")
    print(f"  firebase_id={auth.firebase_id!r}")

    params = {"account_id": str(args.account_id), "data": "null"}
    results: list[tuple[str, int, bool]] = []

    # 1) KHONG sig -> expect 403
    print("\n=== [1] GET jobs KHONG sig (expect 403) ===")
    r1 = _call(auth, sig=None, params=params)
    print(" ", _brief(r1))
    ok1 = r1.status_code == 403
    results.append(("no_sig_expect_403", r1.status_code, ok1))
    print("  PASS" if ok1 else "  FAIL (ky vong 403)")

    # 2) CO sig browser
    browser_sig = (args.sig or "").strip()
    if browser_sig:
        print("\n=== [2] GET jobs + sig browser (expect 200) ===")
        r2 = _call(auth, sig=browser_sig, params=params)
        print(" ", _brief(r2))
        ok2 = r2.status_code == 200
        results.append(("browser_sig_expect_200", r2.status_code, ok2))
        print("  PASS" if ok2 else "  FAIL (ky vong 200 — sig co the het han, bat lai tu F12)")
        if ok2:
            try:
                data = r2.json().get("data")
                if isinstance(data, dict):
                    print(
                        f"  job: type={data.get('type')} "
                        f"object_id={data.get('object_id')} "
                        f"coin={data.get('price_per_after_cost') or data.get('price_coin_job')}"
                    )
                elif isinstance(data, list):
                    print(f"  jobs count={len(data)}")
            except Exception:
                pass
    else:
        print("\n=== [2] skip (khong co --sig) ===")

    # 3) Gen sig bang lib (can signing_key)
    sk = (args.signing_key or auth.signing_key or "").strip()
    if sk:
        print("\n=== [3] GET jobs + sig GEN boi lib (expect 200) ===")
        path_q = f"{JOBS_PATH}?account_id={params['account_id']}&data=null"
        gen = generate_sig(
            method="GET",
            path=path_q,
            signing_key=sk,
            device_id=auth.device_id,
            user_id=auth.user_id,
            body="",
        )
        print("  generated sig:", (gen or "")[:48] + "...")
        if not gen:
            print("  FAIL generate_sig tra None")
            results.append(("lib_sig", 0, False))
        else:
            r3 = _call(auth, sig=gen, params=params)
            print(" ", _brief(r3))
            ok3 = r3.status_code == 200
            results.append(("lib_sig_expect_200", r3.status_code, ok3))
            print("  PASS" if ok3 else "  FAIL (payload sig lib chua khop server)")
            if not ok3:
                try:
                    print("  body:", json.dumps(r3.json(), ensure_ascii=False)[:300])
                except Exception:
                    pass
    else:
        print("\n=== [3] skip gen sig (khong co --signing-key / firebase_id) ===")
        print("  Tip: F12 console:")
        print("    document.querySelector('#app').__vue__.$store.state.signing_key")
        print("  roi chay lai: --signing-key \"...\"")

    print("\n=== TONG KET ===")
    for name, code, ok in results:
        print(f"  [{'OK' if ok else 'FAIL'}] {name}: HTTP {code}")

    # ket luan thuc te
    print("\nKet luan:")
    print("  - API moi: Bearer + g-device-id + g-username + t (+ sig cho TikTok jobs)")
    print("  - Khong can g-auth")
    print("  - Thieu sig TikTok -> 403 'tai lai trang...'")
    print("  - Co sig hop le -> 200")

    return 0 if all(ok for _n, _c, ok in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
