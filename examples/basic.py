from golike_gauth import GolikeAuth

auth = GolikeAuth(
    token="YOUR_JWT",
    signing_key="YOUR_STORE_SIGNING_KEY",
    user_id=123456,
    username="your_username",
    device_id=None,  # auto UUID, or pass fixed UUID
)

# GET jobs
# print(auth.get_instagram_job("ACCOUNT_ID").json())

# POST skip (not GET!)
# print(auth.skip_instagram_job(
#     ads_id=1, object_id="xxx", account_id=2, type="follow"
# ).json())

# any path
# print(auth.post("/advertising/publishers/tiktok/skip-jobs", json={...}).json())
# print(auth.get("/users/me").json())
