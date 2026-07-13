"""golike-gauth — generate g-auth / g-device-id headers for Golike gateway API."""

from .core import (
    APP_CLIENT,
    APP_VERSION,
    BASE_API,
    SALT,
    GolikeAuth,
    body_hash,
    build_headers,
    decode_g_auth,
    derive_aes_key,
    generate_device_id,
    generate_g_auth,
    make_t_header,
    normalize_path,
    parse_signing_key,
)

__version__ = "0.1.1"
__all__ = [
    "APP_CLIENT",
    "APP_VERSION",
    "BASE_API",
    "SALT",
    "GolikeAuth",
    "body_hash",
    "build_headers",
    "decode_g_auth",
    "derive_aes_key",
    "generate_device_id",
    "generate_g_auth",
    "make_t_header",
    "normalize_path",
    "parse_signing_key",
    "__version__",
]
