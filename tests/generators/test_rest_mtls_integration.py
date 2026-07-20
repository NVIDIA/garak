"""Self-contained pytest integration tests for mTLS support in RestGenerator.

Generates real CA, server, and client certs in-process using `cryptography`,
spins up a threaded HTTPS server requiring client certs, and tests every
supported mTLS scenario without Docker or external services.

Run:
    conda run -n garak python -m pytest tests/generators/test_rest_mtls_integration.py -v -m integration
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
from garak.exception import BadGeneratorException
from garak.generators.rest import RestGenerator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REQ_TEMPLATE = '{"prompt": "$INPUT"}'
CANNED_RESPONSE = {"response": "Hello from mTLS test server"}

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_config(base_url: str, **overrides) -> None:
    """Populate _config so that RestGenerator() picks up the right settings."""
    _config.run.user_agent = "garak mTLS integration test"
    _config.plugins.generators["rest"] = {}
    _config.plugins.generators["rest"]["RestGenerator"] = {
        "name": "mtls-smoke-test",
        "uri": base_url,
        "req_template": REQ_TEMPLATE,
        "response_json": True,
        "response_json_field": "response",
        "request_timeout": 10,
        **overrides,
    }


# ---------------------------------------------------------------------------
# Cert-generation fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def mtls_certs(tmp_path_factory):
    """Generate a CA, server cert, and client cert (plain + encrypted) into a
    temp directory using the `cryptography` library."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
    from cryptography.x509.oid import NameOID

    tmp = tmp_path_factory.mktemp("certs")
    now = datetime.datetime.now(datetime.timezone.utc)
    one_day = datetime.timedelta(days=1)

    def _make_key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _save_key(key, path: Path, password: bytes = None):
        enc = (
            BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
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

    # ── CA ──────────────────────────────────────────────────────────────────
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

    # ── Server cert ─────────────────────────────────────────────────────────
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
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
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

    # ── Client cert ─────────────────────────────────────────────────────────
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

    # ── Encrypted client key ─────────────────────────────────────────────────
    cli_enc_key_path = tmp / "client_enc.key"
    _save_key(cli_key, cli_enc_key_path, password=b"smoketest123")

    # ── Combined PEM (cert + key) ────────────────────────────────────────────
    combined_path = tmp / "client_combined.pem"
    combined_path.write_bytes(cli_cert_path.read_bytes() + cli_key_path.read_bytes())

    # ── ECDSA client cert (P-256, signed by RSA CA) ──────────────────────────
    ecdsa_cli_key = ec.generate_private_key(ec.SECP256R1())
    ecdsa_cli_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("garak-test-client-ecdsa"))
        .issuer_name(_name("garak-test-ca"))
        .public_key(ecdsa_cli_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + one_day)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ecdsa_cli_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ecdsa_cli_cert_path = tmp / "client_ecdsa.crt"
    ecdsa_cli_cert_path.write_bytes(
        ecdsa_cli_cert.public_bytes(serialization.Encoding.PEM)
    )
    ecdsa_cli_key_path = tmp / "client_ecdsa.key"
    _save_key(ecdsa_cli_key, ecdsa_cli_key_path)

    return {
        "ca_cert": str(ca_cert_path),
        "server_cert": str(srv_cert_path),
        "server_key": str(srv_key_path),
        "client_cert": str(cli_cert_path),
        "client_key": str(cli_key_path),
        "client_enc_key": str(cli_enc_key_path),
        "combined_pem": str(combined_path),
        "ecdsa_client_cert": str(ecdsa_cli_cert_path),
        "ecdsa_client_key": str(ecdsa_cli_key_path),
    }


# ---------------------------------------------------------------------------
# mTLS server fixture
# ---------------------------------------------------------------------------


class _CannedHandler(http.server.BaseHTTPRequestHandler):
    """Simple handler that returns a canned JSON body for any POST."""

    def do_POST(self):
        body = json.dumps(CANNED_RESPONSE).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # suppress access log noise
        pass


@pytest.fixture(scope="module")
def mtls_server(mtls_certs):
    """Start a real mTLS HTTPS server on 127.0.0.1 (random port) in a daemon
    thread and yield (server, port).  Calls server.shutdown() on teardown."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(mtls_certs["server_cert"], keyfile=mtls_certs["server_key"])
    ctx.load_verify_locations(mtls_certs["ca_cert"])
    ctx.verify_mode = ssl.CERT_REQUIRED  # require client cert

    server = http.server.HTTPServer(("127.0.0.1", 0), _CannedHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield server, port

    server.shutdown()
    thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Shared prompt
# ---------------------------------------------------------------------------

PROMPT = Conversation([Turn("user", Message("hello"))])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_mtls_cert_and_key(mtls_certs, mtls_server):
    """cert + key + CA bundle → successful response."""
    server, port = mtls_server
    url = f"https://127.0.0.1:{port}/generate"

    _make_config(
        url,
        client_cert=mtls_certs["client_cert"],
        client_key=mtls_certs["client_key"],
        verify_ssl=mtls_certs["ca_cert"],
    )
    gen = RestGenerator()
    result = gen._call_model(PROMPT)
    assert result is not None and len(result) > 0
    assert result[0].text == "Hello from mTLS test server"


@pytest.mark.integration
def test_mtls_cert_only_combined_pem(mtls_certs, mtls_server):
    """Combined PEM (cert+key in one file) with no client_key → success."""
    server, port = mtls_server
    url = f"https://127.0.0.1:{port}/generate"

    _make_config(
        url,
        client_cert=mtls_certs["combined_pem"],
        # no client_key — key is embedded in combined PEM
        verify_ssl=mtls_certs["ca_cert"],
    )
    gen = RestGenerator()
    result = gen._call_model(PROMPT)
    assert result is not None and len(result) > 0
    assert result[0].text == "Hello from mTLS test server"


@pytest.mark.integration
def test_mtls_no_certs_rejected(mtls_certs, mtls_server):
    """No client certs → server rejects the connection (SSL error)."""
    server, port = mtls_server
    url = f"https://127.0.0.1:{port}/generate"

    _make_config(
        url,
        verify_ssl=mtls_certs["ca_cert"],
        # no client_cert / client_key
    )
    gen = RestGenerator()
    with pytest.raises(Exception):
        gen._call_model(PROMPT)


@pytest.mark.integration
def test_mtls_no_ca_bundle_rejected(mtls_certs, mtls_server):
    """Client cert provided but no CA bundle → SSL verification fails
    because the self-signed CA is not in the system trust store."""
    server, port = mtls_server
    url = f"https://127.0.0.1:{port}/generate"

    _make_config(
        url,
        client_cert=mtls_certs["client_cert"],
        client_key=mtls_certs["client_key"],
        # verify_ssl defaults to True (system CAs) — our test CA is not there
    )
    gen = RestGenerator()
    with pytest.raises(Exception):
        gen._call_model(PROMPT)


@pytest.mark.integration
def test_mtls_verify_ssl_false(mtls_certs, mtls_server):
    """verify_ssl=False skips server cert validation → success."""
    server, port = mtls_server
    url = f"https://127.0.0.1:{port}/generate"

    _make_config(
        url,
        client_cert=mtls_certs["client_cert"],
        client_key=mtls_certs["client_key"],
        verify_ssl=False,
    )
    gen = RestGenerator()
    result = gen._call_model(PROMPT)
    assert result is not None and len(result) > 0
    assert result[0].text == "Hello from mTLS test server"


@pytest.mark.integration
def test_mtls_encrypted_key_with_passphrase(mtls_certs, mtls_server):
    """Encrypted client key + passphrase from env var → success."""
    server, port = mtls_server
    url = f"https://127.0.0.1:{port}/generate"

    os.environ["MTLS_SMOKE_PASSPHRASE"] = "smoketest123"
    try:
        _make_config(
            url,
            client_cert=mtls_certs["client_cert"],
            client_key=mtls_certs["client_enc_key"],
            client_key_passphrase_env_var="MTLS_SMOKE_PASSPHRASE",
            verify_ssl=mtls_certs["ca_cert"],
        )
        gen = RestGenerator()
        result = gen._call_model(PROMPT)
        assert result is not None and len(result) > 0
        assert result[0].text == "Hello from mTLS test server"
    finally:
        os.environ.pop("MTLS_SMOKE_PASSPHRASE", None)


@pytest.mark.integration
def test_mtls_http_uri_rejected(mtls_certs):
    """http:// URI with client_cert → BadGeneratorException raised in __init__."""
    _make_config(
        "http://127.0.0.1:9999/generate",  # http, not https
        client_cert=mtls_certs["client_cert"],
        client_key=mtls_certs["client_key"],
    )
    with pytest.raises(BadGeneratorException, match="mTLS requires an HTTPS URI"):
        RestGenerator()


@pytest.mark.integration
def test_mtls_pickle_roundtrip_with_server(mtls_certs, mtls_server):
    """__getstate__ / __setstate__ roundtrip + live request against real server."""
    server, port = mtls_server
    url = f"https://127.0.0.1:{port}/generate"

    _make_config(
        url,
        client_cert=mtls_certs["client_cert"],
        client_key=mtls_certs["client_key"],
        verify_ssl=mtls_certs["ca_cert"],
    )
    gen = RestGenerator()
    assert gen._mtls_session is not None, "mTLS session must be live before pickling"

    # --- simulate pickle (getstate) ---
    state = gen.__getstate__()
    assert state["_mtls_session"] is None, "_mtls_session must be None in pickled state"

    # --- simulate unpickle (setstate) ---
    gen.__setstate__(state)
    assert (
        gen._mtls_session is not None
    ), "_mtls_session must be reconstructed after __setstate__"

    # make a real request with the reconstructed generator
    result = gen._call_model(PROMPT)
    assert result is not None and len(result) > 0
    assert result[0].text == "Hello from mTLS test server"


@pytest.mark.integration
def test_mtls_ecdsa_client_cert(mtls_certs, mtls_server):
    """P-256 ECDSA client cert + key (signed by RSA CA) → successful response."""
    server, port = mtls_server
    url = f"https://127.0.0.1:{port}/generate"

    _make_config(
        url,
        client_cert=mtls_certs["ecdsa_client_cert"],
        client_key=mtls_certs["ecdsa_client_key"],
        verify_ssl=mtls_certs["ca_cert"],
    )
    gen = RestGenerator()
    result = gen._call_model(PROMPT)
    assert result is not None and len(result) > 0
    assert result[0].text == "Hello from mTLS test server"


@pytest.mark.integration
def test_mtls_pickle_roundtrip_encrypted_key(mtls_certs, mtls_server):
    """Encrypted key passphrase must survive getstate/setstate and reconstruct
    an SSLContext capable of completing the mTLS handshake against the live server."""
    server, port = mtls_server
    url = f"https://127.0.0.1:{port}/generate"

    os.environ["MTLS_SMOKE_PASSPHRASE"] = "smoketest123"
    try:
        _make_config(
            url,
            client_cert=mtls_certs["client_cert"],
            client_key=mtls_certs["client_enc_key"],
            client_key_passphrase_env_var="MTLS_SMOKE_PASSPHRASE",
            verify_ssl=mtls_certs["ca_cert"],
        )
        gen = RestGenerator()
        assert (
            gen._mtls_session is not None
        ), "mTLS session must be live before pickling"

        # simulate pickle → subprocess
        state = gen.__getstate__()
        assert (
            state["client_key_passphrase"] is None
        ), "client_key_passphrase must be None in pickled state"

        # reconstruct in new context (simulates multiprocessing fork)
        gen.__setstate__(state)
        assert gen._mtls_session is not None, (
            "_mtls_session must be reconstructed after __setstate__ "
            "via _load_unsafe()"
        )

        # real request — if passphrase was lost during pickling, load_cert_chain
        # would have failed and the session would not be usable
        result = gen._call_model(PROMPT)
        assert result is not None and len(result) > 0
        assert result[0].text == "Hello from mTLS test server"
    finally:
        os.environ.pop("MTLS_SMOKE_PASSPHRASE", None)
