#!/usr/bin/env python3

#
# A simple fake OIDC server for testing purposes.
# Kristofer Hallin (kristofer@sunet.se)
#

import base64
import json
import jwt
import sys
import time
import uuid


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

AUTH_CODES = {}
PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
PUBLIC_KEY = PRIVATE_KEY.public_key()
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9000


def get_jwks():
    """
    Return JWKS with the public key.
    """

    pub_numbers = PUBLIC_KEY.public_numbers()

    def int_to_base64url(n, length=None):
        data = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
        if length and len(data) < length:
            data = b"\x00" * (length - len(data)) + data
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    # 2048-bit key = 256 bytes for n
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "fake-key-1",
                "alg": "RS256",
                "n": int_to_base64url(pub_numbers.n, 256),
                "e": int_to_base64url(pub_numbers.e),
            }
        ]
    }


def create_token(
    client_id: str,
    username: str = "testuser@example.com",
    email: str = "testuser@example.com",
    scopes: str = "openid profile email",
    nonce: str = None,
    user_id: str = None,
    token_type: str = "access",
):
    """
    Create a signed JWT.
    """

    now = int(time.time())
    if not user_id:
        user_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, username))

    exp = now + (30 * 24 * 3600) if token_type == "refresh" else now + 3600

    payload = {
        "iss": f"http://localhost:{PORT}",
        "sub": user_id,
        "aud": client_id,
        "exp": exp,
        "iat": now,
        "nbf": now,
        "typ": token_type,
        "preferred_username": username,
        "email": email,
        "email_verified": True,
        "scope": scopes,
        "realm": username.split("@")[-1] if "@" in username else "local",
    }

    if nonce:
        payload["nonce"] = nonce

    private_pem = PRIVATE_KEY.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return jwt.encode(
        payload, private_pem, algorithm="RS256", headers={"kid": "fake-key-1"}
    )


class OIDCHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """
        Write log to stdout.
        """

        print(f"[OIDC] {args[0]}")

    def __send_json(self, data, status=200):
        """
        Send JSON response.
        """

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        """
        Handle GET requests.
        """

        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        match path:
            case "/.well-known/openid-configuration":
                self.__send_json(
                    {
                        "issuer": f"http://localhost:{PORT}",
                        "authorization_endpoint": f"http://localhost:{PORT}/authorize",
                        "token_endpoint": f"http://localhost:{PORT}/token",
                        "jwks_uri": f"http://localhost:{PORT}/jwks",
                        "userinfo_endpoint": f"http://localhost:{PORT}/userinfo",
                        "scopes_supported": ["openid", "profile", "email"],
                        "response_types_supported": ["code", "token", "id_token"],
                        "grant_types_supported": [
                            "authorization_code",
                            "client_credentials",
                            "refresh_token",
                        ],
                        "subject_types_supported": ["public"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                    }
                )
            case "/jwks":
                self.__send_json(get_jwks())
            case "/authorize":
                redirect_uri = query.get("redirect_uri", [""])[0]
                state = query.get("state", [""])[0]
                nonce = query.get("nonce", [""])[0]
                client_id = query.get("client_id", [""])[0]
                scope = query.get("scope", ["openid profile email"])[0]

                code = str(uuid.uuid4())
                AUTH_CODES[code] = {
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "nonce": nonce,
                    "scope": scope,
                    "created": time.time(),
                }

                params = urlencode({"code": code, "state": state})
                redirect_url = f"{redirect_uri}?{params}"

                self.send_response(302)
                self.send_header("Location", redirect_url)
                self.end_headers()
            case "/userinfo":
                username = "testuser@example.com"
                user_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, username))
                self.__send_json(
                    {
                        "sub": user_id,
                        "preferred_username": username,
                        "email": username,
                        "email_verified": True,
                    }
                )
            case _:
                self.send_error(404)

    def do_POST(self):
        """
        Handle POST requests.
        """

        path = urlparse(self.path).path

        match path:
            case "/token":
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length).decode()
                params = parse_qs(body)

                grant_type = params.get("grant_type", [""])[0]
                client_id = params.get("client_id", ["unknown"])[0]

                nonce = None
                scope = "openid profile email"

                # Handle authorization_code grant
                if grant_type == "authorization_code":
                    code = params.get("code", [""])[0]
                    if code in AUTH_CODES:
                        code_data = AUTH_CODES.pop(code)
                        client_id = code_data["client_id"]
                        nonce = code_data.get("nonce")
                        scope = code_data.get("scope", scope)

                username = params.get("username", ["testuser@example.com"])[0]
                scope = params.get("scope", [scope])[0]
                user_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, username))

                token = create_token(
                    client_id,
                    username=username,
                    scopes=scope,
                    nonce=nonce,
                    user_id=user_id,
                )

                userinfo = {
                    "sub": user_id,
                    "preferred_username": username,
                    "email": username,
                    "email_verified": True,
                }

                refresh_token = create_token(
                    client_id,
                    username=username,
                    scopes=scope,
                    nonce=nonce,
                    user_id=user_id,
                    token_type="refresh",
                )

                self.__send_json(
                    {
                        "access_token": token,
                        "id_token": token,
                        "refresh_token": refresh_token,
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "scope": scope,
                        "userinfo": userinfo,
                    }
                )
            case _:
                self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()


if __name__ == "__main__":
    print(f"Starting fake OIDC server on http://localhost:{PORT}")
    print(f"Issuer: http://localhost:{PORT}")
    print(f"JWKS URI: http://localhost:{PORT}/jwks")
    print(f"Token endpoint: http://localhost:{PORT}/token")
    print(f"Metadata: http://localhost:{PORT}/.well-known/openid-configuration")

    server = HTTPServer(("", PORT), OIDCHandler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()
