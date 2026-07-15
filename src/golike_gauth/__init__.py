"""golike-gauth — auth + g-auth/sig headers for Golike gateway."""

from .core import (
    APP_CLIENT,
    APP_VERSION,
    BASE_API,
    MOBILE_UA,
    GolikeAuth,
    decode_g_auth,
    generate_g_auth,
    generate_sig,
    jwt_user_id,
)

__version__ = "0.1.5"
__all__ = [
    "APP_CLIENT",
    "APP_VERSION",
    "BASE_API",
    "MOBILE_UA",
    "GolikeAuth",
    "decode_g_auth",
    "generate_g_auth",
    "generate_sig",
    "jwt_user_id",
    "__version__",
]
