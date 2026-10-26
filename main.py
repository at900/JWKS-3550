from http.client import HTTPException
import json
import time
# from urllib import request
import uuid
import uvicorn

from fastapi import FastAPI, Request, HTTPException
from jwcrypto import jwk, jwt

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

def pick_key(expired: bool):
    now = int(time.time())
    for entry in KEYS.values():
        if (entry["expires_at"] <= now) == expired:
            return entry
    return None

from contextlib import asynccontextmanager
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Generating keys...")
    generate_key(expired=True)
    generate_key(expired=False)
    yield

app = FastAPI(lifespan=lifespan)

@app.post("/auth")
def auth(request: Request):
    expired = "expired" in request.query_params
    entry = pick_key(expired)
    if entry is None:
        raise HTTPException(status_code=500, detail="no suitable key")

    now = int(time.time())
    token = jwt.JWT(
        header={"alg": "RS256", "typ": "JWT", "kid": entry["kid"]},
        claims={"sub": "fakeuser", "iat": now, "exp": entry["expires_at"]},
    )
    token.make_signed_token(entry["key_obj"])
    jwt_string = token.serialize()
    return {"token": jwt_string}

@app.get("/.well-known/jwks.json")
def return_jwks():
    now = int(time.time())
    valid_keys = []
    for key in KEYS.values():
        if key["expires_at"] > now:
            valid_keys.append(key["key_obj"].export_public(as_dict=True))
    return {"keys": valid_keys}


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=True)