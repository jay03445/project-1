from flask import Flask, jsonify, request
from datetime import datetime, timedelta, timezone
import base64
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# -----------------------------
# Helper functions
# -----------------------------
def b64url(data: bytes) -> str:
    """Base64 URL-safe encoding without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def make_kid(public_key) -> str:
    """Generate a key ID (kid) by hashing the public key."""
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(der)
    return b64url(digest.finalize())

def generate_key(expires_in_minutes: int):
    """Generate an RSA key pair with an expiry timestamp."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    kid = make_kid(public_key)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes)
    return {
        "private": private_key,
        "public": public_key,
        "kid": kid,
        "expires_at": expires_at
    }

def public_key_to_jwk(key):
    """Convert RSA public key to JWKS format."""
    numbers = key["public"].public_numbers()
    n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": key["kid"],
        "n": b64url(n_bytes),
        "e": b64url(e_bytes)
    }

# -----------------------------
# Flask App
# -----------------------------
def create_app(testing=False):
    app = Flask(__name__)
    app.config["TESTING"] = testing

    app.config["ACTIVE_KEY"] = generate_key(expires_in_minutes=30)
    app.config["EXPIRED_KEY"] = generate_key(expires_in_minutes=-30)

    @app.get("/jwks")
    @app.get("/.well-known/jwks.json")
    def jwks():
        now = datetime.now(timezone.utc)
        keys = []
        for key in (app.config["ACTIVE_KEY"], app.config["EXPIRED_KEY"]):
            if key["expires_at"] > now:
                keys.append(public_key_to_jwk(key))
        return jsonify({"keys": keys})

    @app.post("/auth")
    def auth():
        use_expired = "expired" in request.args
        key = app.config["EXPIRED_KEY"] if use_expired else app.config["ACTIVE_KEY"]

        now = datetime.now(timezone.utc)
        exp = now - timedelta(minutes=5) if use_expired else now + timedelta(minutes=15)

        payload = {
            "sub": "fake-user-id",
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "iss": "jwks-demo",
            "aud": "jwks-demo-client"
        }

        token = jwt.encode(
            payload,
            key["private"],
            algorithm="RS256",
            headers={"kid": key["kid"]}
        )

        return jsonify({"token": token})

    return app



app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)