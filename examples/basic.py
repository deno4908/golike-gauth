from golike_gauth import GolikeAuth

auth = GolikeAuth(
    token="YOUR_JWT",
    signing_key="YOUR_STORE_SIGNING_KEY",
    user_id=123456,
    username="your_username",
    device_id=None,  # auto UUID, or pass fixed UUID
)

headers = auth.headers("GET", "/advertising/publishers/instagram/jobs", body="")
print(headers["g-auth"][:48], "...")
print(auth.decode(headers["g-auth"]))

# resp = auth.get_instagram_job("ACCOUNT_ID")
# print(resp.json())
