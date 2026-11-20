import jwt

token = input("Token: ")

payload = jwt.decode(
    token,
    options={"verify_signature": False}
)

print(payload)