from __future__ import annotations

import argparse
import json
import sys

from .core import (
    GolikeAuth,
    build_headers,
    decode_g_auth,
    generate_device_id,
    normalize_path,
)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="golike-gauth", description="Golike g-auth helper")
    p.add_argument("--token", required=True)
    p.add_argument("--signing-key", required=True)
    p.add_argument("--user-id", type=int, required=True)
    p.add_argument("--username", required=True)
    p.add_argument("--device-id", default=None)
    p.add_argument("--path", default="/advertising/publishers/instagram/jobs")
    p.add_argument("--method", default="GET")
    p.add_argument("--decode", default=None, help="decode existing g-auth")
    p.add_argument("--ig-account-id", default=None)
    p.add_argument("--call", action="store_true", help="call instagram jobs API")
    args = p.parse_args(argv)

    if args.decode:
        print(json.dumps(decode_g_auth(args.decode, args.signing_key), indent=2))
        return 0

    auth = GolikeAuth(
        token=args.token,
        signing_key=args.signing_key,
        user_id=args.user_id,
        username=args.username,
        device_id=args.device_id,
    )
    headers = auth.headers(args.method, args.path, body="")
    print("g-device-id:", headers["g-device-id"])
    print("g-auth:", headers["g-auth"])
    print("t:", headers["t"])
    print("path:", normalize_path(args.path))
    print("decoded:", json.dumps(auth.decode(headers["g-auth"]), ensure_ascii=False))

    if args.call:
        if not args.ig_account_id:
            print("--ig-account-id required with --call", file=sys.stderr)
            return 2
        resp = auth.get_instagram_job(args.ig_account_id)
        print("status:", resp.status_code)
        try:
            print(resp.json())
        except Exception:
            print(resp.text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
