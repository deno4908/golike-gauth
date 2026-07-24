"""
Get job TikTok co ban — Golike API moi.

Can:
  - JWT token
  - signing_key (F12: store.state.signing_key) de gen header `sig`
  - account_id TikTok tren Golike

Chay:
  python get_tiktok_job.py
  python get_tiktok_job.py --token eyJ... --signing-key "..." --account-id 711964
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir():
    sys.path.insert(0, str(_SRC))

from golike_gauth import GolikeAuth  # noqa: E402

# ============ DIEN VAO DAY ============
TOKEN = "eyJ..."  # Authorization Bearer
SIGNING_KEY = ""  # F12: document.querySelector('#app').__vue__.$store.state.signing_key
ACCOUNT_ID = "711964"  # id acc TikTok tren Golike
DEVICE_ID = None  # None = UUID tu sinh; hoac fix 1 UUID
# =====================================


def get_tiktok_job(
    token: str,
    account_id: str | int,
    *,
    signing_key: str,
    device_id: str | None = None,
) -> dict:
    """
    GET /advertising/publishers/tiktok/jobs

    API moi: Bearer + g-device-id + g-username + t + **sig**
    (khong g-auth / firebase_id)
    """
    token = (token or "").strip()
    sk = (signing_key or "").strip()
    if not token or token.startswith("eyJ..."):
        raise SystemExit("Dien TOKEN that (JWT eyJ...).")
    if not sk:
        raise SystemExit(
            "Dien SIGNING_KEY (F12 console):\n"
            "  document.querySelector('#app').__vue__.$store.state.signing_key"
        )

    # enable_sig=True -> moi request TikTok jobs/complete tu gen header sig
    auth = GolikeAuth.from_token(
        token,
        signing_key=sk,
        device_id=device_id,
        enable_sig=True,  # bat sig
        enable_gauth=False,  # API moi khong g-auth
        verify=False,
    )

    resp = auth.get(
        "/advertising/publishers/tiktok/jobs",
        params={"account_id": str(account_id), "data": "null"},
    )

    try:
        body = resp.json()
    except Exception:
        body = {"raw": (resp.text or "")[:500]}

    return {
        "http": resp.status_code,
        "has_sig_on_last_headers": "sig" in auth.headers(
            "GET",
            f"/advertising/publishers/tiktok/jobs?account_id={account_id}&data=null",
            body="",
        ),
        "user": auth.username,
        "device_id": auth.device_id,
        "body": body,
    }


def main() -> int:
    p = argparse.ArgumentParser(description="Get TikTok job + sig")
    p.add_argument("--token", default=TOKEN)
    p.add_argument("--signing-key", default=SIGNING_KEY)
    p.add_argument("--account-id", default=ACCOUNT_ID)
    p.add_argument("--device-id", default=DEVICE_ID)
    args = p.parse_args()

    out = get_tiktok_job(
        args.token,
        args.account_id,
        signing_key=args.signing_key,
        device_id=args.device_id or None,
    )
    print(json.dumps(out, ensure_ascii=False, indent=2))

    http = out["http"]
    body = out.get("body") or {}
    if http == 200 and (body.get("success") or body.get("status") == 200):
        data = body.get("data")
        if isinstance(data, dict):
            print(
                f"\nOK job: type={data.get('type')} "
                f"link={data.get('link')} "
                f"coin={data.get('price_per_after_cost') or data.get('price_coin_job')}"
            )
        return 0

    print(f"\nFAIL HTTP {http}", file=sys.stderr)
    if http == 403:
        print(
            "403: thieu/sai sig. Kiem tra SIGNING_KEY dung store.state.signing_key.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
