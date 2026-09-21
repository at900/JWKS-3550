import json
import time
import uuid

from fastapi import FastAPI
from jwcrypto import jwk

# dict to store keys along with their expiration timestamp
KEYS = {}

app = FastAPI()

def generate_key(expired):

    kid = str(uuid.uuid4())
    
    key = jwk.JWK.generate(
        kty='RSA', 
        size=2048, 
        alg='RS256', 
        use='sig', 
        kid=kid
    )
    if expired:
        expiration_timestamp = int(time.time()) - 10000 # expired 10000 seconds ago
    else:
        expires_in = 1 * 60 * 60 # expires in 1 hour
        expiration_timestamp = int(time.time()) + expires_in

    KEYS[kid] = {
        "key_obj": key,
        "expires_at": expiration_timestamp,
        "kid": kid
    }
    return kid

@app.on_event("startup")
def startup():
    generate_key(True)
    generate_key(True)
    generate_key(True)
    generate_key(False)
    generate_key(False)

@app.post("/auth")
def return_key(expired: bool):
    now = int(time.time())
    for key in KEYS.values():
        if expired:
            if key["expires_at"] < now:
                valid_key = key["key_obj"].export_public(as_dict=True)
                break
        else:
            if key["expires_at"] > now:
                valid_key = key["key_obj"].export_public(as_dict=True)
                break
    return json.dumps(valid_keyvalid_key)

@app.get("/.well-known/jwks.json")
def return_json():
    now = int(time.time())
    valid_keys = []
    for key in KEYS.values():
        if key["expires_at"] > now:
            valid_keys.append(key["key_obj"].export_public(as_dict=True))
    return {json.dumps(valid_keys)}












    # public_jwk = key.export_public(as_dict=True)

    # # 3. Create a public JSON Web Key Set (JWKS) structure
    # public_jwks = {
    #     "keys": [public_jwk]
    # }

    # # 4. Export the Private JWK (Keep this secret!)
    # private_jwk = key.export_private(as_dict=True)

    # # Print the Public JWKS
    # # print("Public JWKS:")
    # # print(json.dumps(public_jwks, indent=2))

    # print(public_jwk)

# generate_key()

# app = FastAPI()

# @app.get("/")
# def read_root():
#     return {"message": "Hello, FastAPI!"}


# @app.get("/.well-known")
# def read_root():
#     return {"message": "Hello, FastAPI!"}