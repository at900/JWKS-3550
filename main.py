from http.client import HTTPException
import json
import time
import uuid
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from jwcrypto import jwk, jwt
import sqlite3

# dict to store keys along with their expiration timestamp
# KEYS = {}

# python is awful why does anyone use this language.
# I can't tell what type anything is without printing it out
# and even then it's not clear. I hate this language.

DB_FILE = "totally_not_my_privateKeys.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)

app = FastAPI()

def generate_key(expired):

    # kid = str(uuid.uuid4())
    
    key = jwk.JWK.generate(
        kty='RSA', 
        size=2048, 
        alg='RS256', 
        use='sig',
    )
    if expired:
        expiration_timestamp = int(time.time()) - 10000 # expired 10000 seconds ago
    else:
        expires_in = 1 * 60 * 60 # expires in 1 hour
        expiration_timestamp = int(time.time()) + expires_in

    pem = key.export_to_pem(private_key=True, password=None)
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, expiration_timestamp))
        
    # return kid

def get_key(expired: bool):
    now = int(time.time())
    op = "<=" if expired else ">"
    with sqlite3.connect(DB_FILE) as conn:
        return conn.execute(
            f"SELECT kid, key, exp FROM keys WHERE exp {op} ? LIMIT 1", (now,)
        ).fetchone()
    return None

from contextlib import asynccontextmanager
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if get_key(expired=True) is None:
        print("GENERATING EXPIRED KEYS")
        generate_key(expired=True)
        generate_key(expired=True)
    if get_key(expired=False) is None:
        print("GENERATING NON-EXPIRED KEYS")
        generate_key(expired=False)
        generate_key(expired=False)
    yield

app = FastAPI(lifespan=lifespan)

@app.post("/auth")
def auth(request: Request):
    expired = "expired" in request.query_params
    entry = get_key(expired=expired)
    if entry is None:
        raise HTTPException(status_code=500, detail="no suitable key")
    (kid, pem, expires_at) = entry[0], entry[1], entry[2]
    key = jwk.JWK.from_pem(pem)
    print(kid, key, expires_at)

    now = int(time.time())
    token = jwt.JWT(
        header={"alg": "RS256", "typ": "JWT", "kid": str(kid)},
        claims={"sub": "fakeuser", "iat": now, "exp": str(expires_at)},
    )
    token.make_signed_token(key)
    jwt_string = token.serialize()
    return {"token": jwt_string}

@app.get("/.well-known/jwks.json")
def return_jwks():
    now = int(time.time())
    with sqlite3.connect(DB_FILE) as conn:
        valid_keys_data = conn.execute(
            "SELECT kid, key FROM keys WHERE exp > ?", (now,)
        ).fetchall()
    valid_keys = []
    for kid, key_pem in valid_keys_data:
        key = jwk.JWK.from_pem(key_pem)
        key["kid"] = str(kid)
        valid_keys.append(key.export_public(as_dict=True))
    return {"keys": valid_keys}


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=True)