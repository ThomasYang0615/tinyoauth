import base64, hashllib, json, time, uuid
from typing import Dict, Any
from jose import JWTError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# In-memory RSA keypair (rotate on restart). In prod: persist & rotate with KID timeline
_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_priv_pem = _key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
_pub = _key.public_key()
_pub_pem = _pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
KID = str(uuid.uuid4())

def jwk_from_public_pem(pem_bytes: bytes) -> Dict[str, Any]:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    pub = serialization.load_pem_public_key(pem_bytes, backend=default_backend())
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError("Only RSA keys supported.")
    numbers = pub.public_numbers()

    def b64u(x: bytes) -> str:
        return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
    
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": KID,
        "n": b64u(n),
        "e": b64u(e),
    }


def sign_jwt(claims: Dict[str, Any], issuer: str) -> str:
    headers = {"kid": KID, "alg": "RS256", "typ": "JWT"}
    return jwt.encode({**claims, "iss": issuer}, _priv_pem, algorithm="RS256", headers=headers)


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    digest = hashlib.sha256(code_verifier.encode()).digest()
    b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return b64 == code_challenge

JWKS = {"keys": [jwk_from_public_pem(_pub_pem)]}