#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import re
import secrets
import sys
import traceback
import urllib.parse
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parent
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080

MOUNTS = {
    "/APP_HOST": ROOT / "APP_HOST",
    "/IMG_HOST": ROOT / "IMG_HOST",
    "/TABLE_HOST": ROOT / "TABLE_HOST",
    "/CLAN_HOST": ROOT / "CLAN_HOST",
}
LOG_ROOT = ROOT / "logs"
STATE_ROOT = ROOT / "state"
KEY_ROOT = ROOT / "keys"

DEFAULT_NETWORK_HASH = "ELqdT/y.pM#8+J##x7|3/tLb7jZhmqJ,"
DEFAULT_IV_128 = "yCNBH$$rCNGvC+#f"

# plain: useful while the client is patched to accept plain JSON responses.
# original: reproduce JSON -> zlib -> AES/Base64 + x-signature.
RESPONSE_MODE = os.environ.get("DPRO_RESPONSE_MODE", "plain").lower()
AUTO_CREATE_ENDPOINTS = True


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%fZ")


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)[:120] or "_"


def jd(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)


def parse_form(body: bytes) -> dict[str, str]:
    if not body:
        return {}

    text = body.decode("utf-8", errors="replace")
    result = {}

    for field in text.split("&"):
        if "=" in field:
            key, value = field.split("=", 1)
        else:
            key, value = field, ""

        # Important:
        # Use unquote(), NOT unquote_plus().
        #
        # This preserves literal '+' characters in Base64 data.
        key = urllib.parse.unquote(key)
        value = urllib.parse.unquote(value)

        result[key] = value

    return result


def get_cookie(headers: dict[str, str], name: str) -> Optional[str]:
    raw = headers.get("Cookie", "")
    for piece in raw.split(";"):
        piece = piece.strip()
        if "=" not in piece:
            continue
        key, value = piece.split("=", 1)
        if key.strip() == name:
            return value.strip()
    return None


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    n = block_size - (len(data) % block_size)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        return data
    n = data[-1]
    if n < 1 or n > block_size or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-n]


def aes_decrypt_b64(ciphertext_b64: str, key: str, iv: str) -> bytes:
    raw = base64.b64decode(ciphertext_b64)
    cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()))
    decryptor = cipher.decryptor()
    return pkcs7_unpad(decryptor.update(raw) + decryptor.finalize())


def aes_encrypt_b64(plaintext: bytes, key: str, iv: str) -> str:
    cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(pkcs7_pad(plaintext)) + encryptor.finalize()
    return base64.b64encode(encrypted).decode("ascii")


def rsa_sha256_signature_b64(text: str, private_key) -> str:
    signature = private_key.sign(
        text.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
    )
    return base64.b64encode(signature).decode("ascii")


def generate_rsa_keypair(private_path: Path, public_path: Path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_path.write_text(base64.b64encode(public_der).decode("ascii"), encoding="ascii")


class StateStore:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.accounts_path = root / "accounts.json"
        self.sessions_path = root / "sessions.json"
        if not self.accounts_path.exists():
            self.accounts_path.write_text('{"accounts":{}}', encoding="utf-8")
        if not self.sessions_path.exists():
            self.sessions_path.write_text('{"sessions":{}}', encoding="utf-8")

    def _read(self, path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _write(self, path: Path, value: dict):
        path.write_text(jd(value), encoding="utf-8")

    def create_account(self, device_id: str = "") -> dict:
        db = self._read(self.accounts_path)
        accounts = db.setdefault("accounts", {})
        ids = []
        for key in accounts:
            try:
                ids.append(int(key))
            except ValueError:
                pass
        user_id = max(ids or [0]) + 1
        account = {
            "userId": user_id,
            "userHash": secrets.token_hex(16) + "-0",
            "deviceId": device_id,
            "guestUser": True,
            "createdAt": utc_stamp(),
        }
        accounts[str(user_id)] = account
        self._write(self.accounts_path, db)
        return account

    def create_session(self, user_id: int, user_hash: str, token: Optional[str] = None) -> str:
        db = self._read(self.sessions_path)
        token = token or ("robpt=" + secrets.token_hex(20))
        db.setdefault("sessions", {})[token] = {
            "userId": user_id,
            "userHash": user_hash,
            "createdAt": utc_stamp(),
        }
        self._write(self.sessions_path, db)
        return token

    def get_session(self, token: Optional[str]) -> Optional[dict]:
        if not token:
            return None
        return self._read(self.sessions_path).get("sessions", {}).get(token)


@dataclass
class Response:
    body: bytes
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def raw(cls, body: bytes, status: int = 200, content_type: str = "application/octet-stream"):
        return cls(body, status, {"Content-Type": content_type})

    @classmethod
    def json(cls, payload: Any, status: int = 200):
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return cls(body, status, {"Content-Type": "application/json; charset=utf-8"})


@dataclass
class RequestContext:
    server: "ReceiverServer"
    http: BaseHTTPRequestHandler
    method: str
    path: str
    headers: dict[str, str]
    raw_body: bytes
    form: dict[str, str]
    query: dict[str, list[str]]
    route_prefix: str
    relative_path: str
    cookie: Optional[str]
    data_ciphertext: Optional[str]
    data_plaintext: Optional[str]
    data_json: Any
    encryption_key: str
    encryption_key_description: str

    @property
    def request_id(self) -> str:
        return self.form.get("rcToken", "")

    def api_json(self, payload: Any, status: int = 200) -> Response:
        return self.server.api_response(payload, self.encryption_key, status)


class ReceiverServer:
    def __init__(self):
        self.state = StateStore(STATE_ROOT)
        self.api_private = None
        if RESPONSE_MODE == "original":
            private_path = KEY_ROOT / "api_private.pem"
            if private_path.exists():
                self.api_private = serialization.load_pem_private_key(
                    private_path.read_bytes(), password=None
                )
            else:
                print("[WARN] original response mode: keys/api_private.pem is missing")
                print("       Run: python receiver.py --generate-api-key")

    def select_request_key(self, cookie: Optional[str]) -> tuple[str, str]:
        session = self.state.get_session(cookie)
        if session:
            return session["userHash"], f"userHash:userId={session['userId']}"
        return DEFAULT_NETWORK_HASH, "DEFAULT_NETWORK_HASH"

    def decrypt_request(self, ciphertext: str, cookie: Optional[str]) -> tuple[str, str, str]:
        key, description = self.select_request_key(cookie)
        plaintext = aes_decrypt_b64(ciphertext, key, DEFAULT_IV_128).decode("utf-8")
        return plaintext, key, description

    def api_response(self, payload: Any, encryption_key: str, status: int = 200) -> Response:
        if RESPONSE_MODE == "plain":
            return Response.json(payload, status)
        if RESPONSE_MODE != "original":
            raise RuntimeError(f"Unknown DPRO_RESPONSE_MODE={RESPONSE_MODE!r}")
        if self.api_private is None:
            raise RuntimeError("original mode requires keys/api_private.pem")

        text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        compressed = zlib.compress(text.encode("utf-8"))
        encrypted = aes_encrypt_b64(compressed, encryption_key, DEFAULT_IV_128)
        return Response(
            encrypted.encode("ascii"),
            status,
            {
                "Content-Type": "text/plain; charset=utf-8",
                "x-compress-encrypt": "cipher",
                "x-signature": rsa_sha256_signature_b64(text, self.api_private),
            },
        )

    def split_route(self, request_path: str) -> tuple[str, str]:
        path = request_path.split("?", 1)[0]
        for prefix in sorted(MOUNTS, key=len, reverse=True):
            if path == prefix or path.startswith(prefix + "/"):
                return prefix, path[len(prefix):].lstrip("/")
        return "", path.lstrip("/")

    def endpoint_path(self, prefix: str, relative: str) -> Path:
        parts = [p for p in relative.split("/") if p]
        if any(p in (".", "..") for p in parts):
            raise ValueError("path traversal rejected")
        root = MOUNTS[prefix]
        if not parts:
            return root / "_root.py"
        filename = parts[-1]
        if not filename.endswith(".py"):
            filename += ".py"
        return root.joinpath(*parts[:-1], filename)

    def ensure_endpoint(self, prefix: str, relative: str) -> Path:
        path = self.endpoint_path(prefix, relative)
        if path.exists() or not AUTO_CREATE_ENDPOINTS:
            return path

        path.parent.mkdir(parents=True, exist_ok=True)
        route = f"{prefix}/{relative}" if relative else prefix
        template = '''"""
Auto-created Dragon Project endpoint.
Route: __ROUTE__
Edit handle(ctx). The receiver reloads this file for every request.
"""

def handle(ctx):
    print("[STUB] __ROUTE__")
    print("request data:", ctx.data_plaintext)

    return ctx.api_json({
        "error": 0,
        "result": {}
    })
'''.replace("__ROUTE__", route)
        path.write_text(template, encoding="utf-8")
        print(f"[AUTO] created endpoint: {path}")
        return path

    def invoke_endpoint(self, ctx: RequestContext) -> Response:
        path = self.ensure_endpoint(ctx.route_prefix, ctx.relative_path)
        if not path.exists():
            return Response.json({"error": 404}, 404)

        module_name = "_dpro_" + hashlib.sha1(str(path).encode()).hexdigest()
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load endpoint {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if not hasattr(module, "handle"):
            raise RuntimeError(f"{path} has no handle(ctx)")
        result = module.handle(ctx)
        if isinstance(result, Response):
            return result
        if isinstance(result, (dict, list)):
            return ctx.api_json(result)
        raise TypeError(f"{path}: handler returned {type(result).__name__}")

    def serve_static(self, prefix: str, relative: str) -> Response:
        parts = [p for p in relative.split("/") if p]
        if any(p in (".", "..") for p in parts):
            return Response.json({"error": "path traversal"}, 400)
        path = MOUNTS[prefix].joinpath(*parts)
        if not path.is_file():
            return Response.raw(b"", 404)
        suffix = path.suffix.lower()
        content_type = "text/plain; charset=utf-8" if suffix in {".txt", ".csv", ".json"} else "application/octet-stream"
        return Response.raw(path.read_bytes(), 200, content_type)


class HTTPHandler(BaseHTTPRequestHandler):
    server_version = "DPROReceiver/1.0"

    def handle_request(self):
        app: ReceiverServer = self.server.app
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw_body = self.rfile.read(length)
        headers = {k: v for k, v in self.headers.items()}
        parsed = urllib.parse.urlsplit(self.path)
        form = parse_form(raw_body)
        cookie = get_cookie(headers, "robpt")

        ciphertext = form.get("data") or None
        plaintext = None
        data_json = None
        encryption_key, key_description = app.select_request_key(cookie)

        if ciphertext:
            try:
                plaintext, encryption_key, key_description = app.decrypt_request(ciphertext, cookie)
                try:
                    data_json = json.loads(plaintext)
                except Exception:
                    pass
            except Exception as exc:
                key_description = f"DECRYPT_FAILED: {type(exc).__name__}: {exc}"

        prefix, relative = app.split_route(parsed.path)
        if not prefix:
            prefix, relative = "/APP_HOST", parsed.path.lstrip("/")

        ctx = RequestContext(
            app, self, self.command, self.path, headers, raw_body, form,
            urllib.parse.parse_qs(parsed.query, keep_blank_values=True),
            prefix, relative, cookie, ciphertext, plaintext, data_json,
            encryption_key, key_description,
        )

        log_dir = LOG_ROOT / f"{utc_stamp()}_{self.command}_{safe_name(parsed.path.replace('/', '_'))}"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "request.body.bin").write_bytes(raw_body)
        (log_dir / "request.json").write_text(jd({
            "method": self.command,
            "path": self.path,
            "headers": headers,
            "query": ctx.query,
            "form": form,
            "cookie": cookie,
            "route_prefix": prefix,
            "relative_path": relative,
            "request_id": ctx.request_id,
            "encryption_key": key_description,
        }), encoding="utf-8")
        if ciphertext:
            (log_dir / "data.ciphertext.txt").write_text(ciphertext, encoding="ascii")
        if plaintext is not None:
            (log_dir / "data.plaintext.txt").write_text(plaintext, encoding="utf-8")
        if data_json is not None:
            (log_dir / "data.json").write_text(jd(data_json), encoding="utf-8")

        print("\n" + "=" * 100)
        print(f"[REQ] {self.command} {self.path}")
        print(f"[ROUTE] {prefix}/{relative}")
        print(f"[KEY] {key_description}")
        if form:
            print("[FORM]", jd(form))
        if plaintext is not None:
            print("[DATA]")
            print(plaintext)

        try:
            if prefix in ("/IMG_HOST", "/TABLE_HOST", "/CLAN_HOST"):
                response = app.serve_static(prefix, relative)
            else:
                response = app.invoke_endpoint(ctx)
        except Exception:
            traceback.print_exc()
            (log_dir / "exception.txt").write_text(traceback.format_exc(), encoding="utf-8")
            response = Response.json({"error": 500, "message": "handler exception"}, 500)

        (log_dir / "response.body.bin").write_bytes(response.body)
        (log_dir / "response.json").write_text(jd({
            "status": response.status,
            "headers": response.headers,
            "body_length": len(response.body),
        }), encoding="utf-8")
        try:
            (log_dir / "response.text.txt").write_text(response.body.decode("utf-8"), encoding="utf-8")
        except Exception:
            pass
        if len(response.body) > 256:
            try:
                decoded = zlib.decompress(response.body[256:]).decode("utf-8")
                (log_dir / "response.after_256_zlib.txt").write_text(decoded, encoding="utf-8")
            except Exception:
                pass

        print(f"[RES] HTTP {response.status} / {len(response.body)} bytes")
        print("=" * 100)

        self.send_response(response.status)
        for key, value in response.headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(response.body)))
        self.end_headers()
        self.wfile.write(response.body)

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def do_HEAD(self):
        self.handle_request()

    def log_message(self, fmt, *args):
        pass


def generate_api_key():
    private_path = KEY_ROOT / "api_private.pem"
    public_path = KEY_ROOT / "api_public.der.base64.txt"
    if private_path.exists():
        print("Already exists:", private_path)
        return
    generate_rsa_keypair(private_path, public_path)
    print("Generated:", private_path)
    print("Patch Cipher.PUBLIC_KEY_STRING with:")
    print(public_path.read_text(encoding="ascii"))


def main():
    if "--generate-api-key" in sys.argv:
        generate_api_key()
        return

    print("Dragon Project local receiver")
    print(f"Listening: http://{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"Response mode: {RESPONSE_MODE}")
    for prefix, path in MOUNTS.items():
        print(f"{prefix:<12} -> {path}")
    print("Unknown APP_HOST endpoints become ./APP_HOST/<path>/<endpoint>.py")
    print(f"Logs: {LOG_ROOT}")
    print("\nREADY\n")

    app = ReceiverServer()
    httpd = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), HTTPHandler)
    httpd.app = app
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
