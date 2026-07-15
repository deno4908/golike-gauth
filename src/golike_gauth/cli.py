from __future__ import annotations

import argparse
import json
import sys

from .core import GolikeAuth, decode_g_auth, normalize_path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="golike-gauth", description="Golike auth helper")
    p.add_argument("--token", required=True, help="JWT (hoac dung from_token trong code)")
    p.add_argument("--signing-key", default=None)
    p.add_argument("--path", default="/users/me")
    p.add_argument("--method", default="GET")
    p.add_argument("--enable-sig", action="store_true", help="bat header sig")
    p.add_argument("--no-sig", action="store_true", help="tat header sig")
    p.add_argument("--decode", default=None, help="decode g-auth token")
    p.add_argument("--call", action="store_true", help="goi API path")
    args = p.parse_args(argv)

    if args.decode:
        if not args.signing_key:
            print("--signing-key required with --decode", file=sys.stderr)
            return 2
        print(json.dumps(decode_g_auth(args.decode, args.signing_key), indent=2))
        return 0

    enable_sig = True if args.enable_sig else (False if args.no_sig else None)
    try:
        if args.signing_key:
            # manual bootstrap nhe: from_token van goi /me neu muon day du
            auth = GolikeAuth.from_token(
                args.token,
                signing_key=args.signing_key,
                enable_sig=enable_sig,
                verify=False,
            )
        else:
            auth = GolikeAuth.from_token(
                args.token, enable_sig=enable_sig, verify=False
            )
    except Exception as e:
        print("auth fail:", e, file=sys.stderr)
        return 1

    headers = auth.headers(args.method, args.path, body="")
    print("user:", auth.username, auth.user_id)
    print("device:", auth.device_id)
    print("g-auth:", headers["g-auth"][:48] + "...")
    if "sig" in headers:
        print("sig:", headers["sig"][:48] + "...")
    print("path:", normalize_path(args.path))

    if args.call:
        resp = auth.request(args.method, args.path)
        print("status:", resp.status_code)
        try:
            print(resp.json())
        except Exception:
            print(resp.text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
