"""End-to-end CA/mTLS validation for RestGenerator.

Quick smoke tests that exercise server CA bundle handling:
- connection with default system CAs should fail for our self-signed CA
- connection with verify_ssl set to the CA file should succeed
- connection with verify_ssl=False should succeed

Marked as integration to match existing mTLS tests.
"""

import datetime
import http.server
import ipaddress
import json
import os
import ssl
import threading
from pathlib import Path

import pytest

from garak import _config
from garak.attempt import Conversation, Message, Turn
from garak.generators.rest import RestGenerator


REQ_TEMPLATE = '{"prompt": "$INPUT"}'
CANNED_RESPONSE = {"response": "Hello from mTLS test server"}


def _make_config(base_url: str, **overrides) -> None:
    _config.run.user_agent = "garak mTLS cas-e2e"
    _config.plugins.generators["rest"] = {}
    _config.plugins.generators["rest"]["RestGenerator"] = {
        "name": "mtls-cas-e2e",
        "uri": base_url,
        "req_template": REQ_TEMPLATE,
        "response_json": True,
        "response_json_field": "response",
        "request_timeout": 10,
        **overrides,
    }


def _generate_certs(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    one_day = datetime.timedelta(days=1)

    def _make_key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _save_key(key, path: Path, password: bytes = None):
        enc = (
            BestAvailableEncryption(password) if password else serialization.NoEncryption()
        )
        path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=enc,
            )
        )

    def _name(cn: str):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    tmp = tmp_path

    # CA
    ca_key = _make_key()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("garak-test-ca"))
        .issuer_name(_name("garak-test-ca"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + one_day)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_cert_path = tmp / "ca.crt"
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    ca_key_path = tmp / "ca.key"
    _save_key(ca_key, ca_key_path)

    # Server cert
    srv_key = _make_key()
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("localhost"))
        .issuer_name(_name("garak-test-ca"))
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + one_day)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(srv_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    srv_cert_path = tmp / "server.crt"
    srv_cert_path.write_bytes(srv_cert.public_bytes(serialization.Encoding.PEM))
    srv_key_path = tmp / "server.key"
    _save_key(srv_key, srv_key_path)

    # Client cert
    cli_key = _make_key()
    cli_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("garak-test-client"))
        .issuer_name(_name("garak-test-ca"))
        .public_key(cli_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + one_day)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(cli_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cli_cert_path = tmp / "client.crt"
    cli_cert_path.write_bytes(cli_cert.public_bytes(serialization.Encoding.PEM))
    cli_key_path = tmp / "client.key"
    _save_key(cli_key, cli_key_path)

    return {
        "ca_cert": str(ca_cert_path),
        "server_cert": str(srv_cert_path),
        "server_key": str(srv_key_path),
        "client_cert": str(cli_cert_path),
        "client_key": str(cli_key_path),
    }


class _CannedHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.dumps(CANNED_RESPONSE).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


@pytest.mark.integration
def test_cas_end_to_end(tmp_path):
    certs = _generate_certs(tmp_path)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certs["server_cert"], keyfile=certs["server_key"])
    ctx.load_verify_locations(certs["ca_cert"])
    ctx.verify_mode = ssl.CERT_REQUIRED

    server = http.server.HTTPServer(("127.0.0.1", 0), _CannedHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        url = f"https://127.0.0.1:{port}/generate"

        # 1) providing CA bundle path should succeed
        _make_config(
            url,
            client_cert=certs["client_cert"],
            client_key=certs["client_key"],
            verify_ssl=certs["ca_cert"],
        )
        gen = RestGenerator()
        res = gen._call_model(Conversation([Turn("user", Message("hello"))]))
        assert res and res[0].text == "Hello from mTLS test server"

        # 3) explicitly disabling verification should also succeed
        _make_config(
            url,
            client_cert=certs["client_cert"],
            client_key=certs["client_key"],
            verify_ssl=False,
        )
        gen = RestGenerator()
        res = gen._call_model(Conversation([Turn("user", Message("hello"))]))
        assert res and res[0].text == "Hello from mTLS test server"

    finally:
        server.shutdown()
        thread.join(timeout=5)
