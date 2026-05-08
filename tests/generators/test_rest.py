import datetime
import json
import ssl
from unittest.mock import MagicMock, patch

import pytest

from garak import _config, _plugins
from garak.attempt import Message, Turn, Conversation
from garak.exception import BadGeneratorException, GarakException
from garak.generators.rest import RestGenerator

DEFAULT_NAME = "REST Test"
DEFAULT_URI = "https://www.wikidata.org/wiki/Q22971"
DEFAULT_TEXT_RESPONSE = "Here's your model response"


@pytest.fixture
def set_rest_config():
    _config.run.user_agent = "test user agent, garak.ai"
    _config.plugins.generators["rest"] = {}
    _config.plugins.generators["rest"]["RestGenerator"] = {
        "name": DEFAULT_NAME,
        "uri": DEFAULT_URI,
        "api_key": "testing",
    }
    # excluded: req_template_json_object, response_json_field


@pytest.mark.usefixtures("set_rest_config")
def test_rest_generator_initialization():
    generator = RestGenerator()
    assert generator.name == DEFAULT_NAME
    assert generator.uri == DEFAULT_URI


# plain text test
@pytest.mark.usefixtures("set_rest_config")
def test_plaintext_rest(requests_mock):
    requests_mock.post(
        "https://www.wikidata.org/wiki/Q22971",
        text=DEFAULT_TEXT_RESPONSE,
    )
    generator = RestGenerator()
    conv = Conversation([Turn("user", Message("sup REST"))])
    output = generator._call_model(conv)
    assert output == [Message(DEFAULT_TEXT_RESPONSE)]


@pytest.mark.usefixtures("set_rest_config")
def test_json_rest_top_level(requests_mock):
    requests_mock.post(
        "https://www.wikidata.org/wiki/Q22971",
        text=json.dumps({"text": DEFAULT_TEXT_RESPONSE}, ensure_ascii=False),
    )
    _config.plugins.generators["rest"]["RestGenerator"]["response_json"] = True
    _config.plugins.generators["rest"]["RestGenerator"]["response_json_field"] = "text"
    generator = RestGenerator()
    print(generator.response_json)
    print(generator.response_json_field)
    conv = Conversation([Turn("user", Message("Who is Enabran Tain's son?"))])
    output = generator._call_model(conv)
    assert output == [Message(DEFAULT_TEXT_RESPONSE)]


@pytest.mark.usefixtures("set_rest_config")
def test_json_rest_list(requests_mock):
    requests_mock.post(
        "https://www.wikidata.org/wiki/Q22971",
        text=json.dumps([DEFAULT_TEXT_RESPONSE], ensure_ascii=False),
    )
    _config.plugins.generators["rest"]["RestGenerator"]["response_json"] = True
    _config.plugins.generators["rest"]["RestGenerator"]["response_json_field"] = "$"
    generator = RestGenerator()
    conv = Conversation([Turn("user", Message("Who is Enabran Tain's son?"))])
    output = generator._call_model(conv)
    assert output == [Message(DEFAULT_TEXT_RESPONSE)]


@pytest.mark.usefixtures("set_rest_config")
def test_json_rest_deeper(requests_mock):
    requests_mock.post(
        "https://www.wikidata.org/wiki/Q22971",
        text=json.dumps(
            {
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": DEFAULT_TEXT_RESPONSE,
                        },
                    }
                ]
            },
            ensure_ascii=False,
        ),
    )
    _config.plugins.generators["rest"]["RestGenerator"]["response_json"] = True
    _config.plugins.generators["rest"]["RestGenerator"][
        "response_json_field"
    ] = "$.choices[*].message.content"
    generator = RestGenerator()
    conv = Conversation([Turn("user", Message("Who is Enabran Tain's son?"))])
    output = generator._call_model(conv)
    assert output == [Message(DEFAULT_TEXT_RESPONSE)]


@pytest.mark.usefixtures("set_rest_config")
def test_rest_skip_code(requests_mock):
    generator = _plugins.load_plugin(
        "generators.rest.RestGenerator", config_root=_config
    )
    generator.skip_codes = [200]
    requests_mock.post(
        DEFAULT_URI,
        text=json.dumps(
            {
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": DEFAULT_TEXT_RESPONSE,
                        },
                    }
                ]
            },
            ensure_ascii=False,
        ),
    )
    conv = Conversation([Turn("user", Message("Who is Enabran Tain's son?"))])
    output = generator._call_model(conv)
    assert output == [None]


@pytest.mark.usefixtures("set_rest_config")
def test_rest_valid_proxy(mocker, requests_mock):
    test_proxies = {
        "http": "http://localhost:8080",
        "https": "https://localhost:8443",
    }
    _config.plugins.generators["rest"]["RestGenerator"]["proxies"] = test_proxies
    generator = _plugins.load_plugin(
        "generators.rest.RestGenerator", config_root=_config
    )
    requests_mock.post(
        DEFAULT_URI,
        text=json.dumps(
            {
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": DEFAULT_TEXT_RESPONSE,
                        },
                    }
                ]
            },
            ensure_ascii=False,
        ),
    )
    mock_http_function = mocker.patch.object(
        generator, "http_function", wraps=generator.http_function
    )
    conv = Conversation([Turn("user", Message("Who is Enabran Tain's son?"))])
    generator._call_model(conv)
    mock_http_function.assert_called_once()
    assert mock_http_function.call_args_list[0].kwargs["proxies"] == test_proxies


@pytest.mark.usefixtures("set_rest_config")
def test_rest_invalid_proxy(requests_mock):
    test_proxies = [
        "http://localhost:8080",
        "https://localhost:8443",
    ]
    _config.plugins.generators["rest"]["RestGenerator"]["proxies"] = test_proxies
    with pytest.raises(GarakException) as exc_info:
        _plugins.load_plugin("generators.rest.RestGenerator", config_root=_config)
    assert "not in the required format" in str(exc_info.value)


@pytest.mark.usefixtures("set_rest_config")
@pytest.mark.parametrize("verify_ssl", (True, False, None))
def test_rest_ssl_suppression(mocker, requests_mock, verify_ssl):
    if verify_ssl is not None:
        _config.plugins.generators["rest"]["RestGenerator"]["verify_ssl"] = verify_ssl
    else:
        verify_ssl = RestGenerator.DEFAULT_PARAMS["verify_ssl"]
    generator = _plugins.load_plugin(
        "generators.rest.RestGenerator", config_root=_config
    )
    requests_mock.post(
        DEFAULT_URI,
        text=json.dumps(
            {
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": DEFAULT_TEXT_RESPONSE,
                        },
                    }
                ]
            },
            ensure_ascii=False,
        ),
    )
    mock_http_function = mocker.patch.object(
        generator, "http_function", wraps=generator.http_function
    )
    conv = Conversation([Turn("user", Message("Who is Enabran Tain's son?"))])
    generator._call_model(conv)
    mock_http_function.assert_called_once()
    assert mock_http_function.call_args_list[0].kwargs["verify"] is verify_ssl


@pytest.mark.usefixtures("set_rest_config")
def test_rest_non_latin1():
    _config.plugins.generators["rest"]["RestGenerator"][
        "uri"
    ] = "http://127.0.0.9"  # don't mock
    _config.plugins.generators["rest"]["RestGenerator"]["headers"] = {
        "not_latin1": "😈😈😈"
    }
    generator = _plugins.load_plugin(
        "generators.rest.RestGenerator", config_root=_config
    )
    conv = Conversation([Turn("user", Message("summon a demon and bind it"))])
    with pytest.raises(BadGeneratorException):
        generator._call_model(conv)


# mTLS tests


@pytest.mark.usefixtures("set_rest_config")
def test_rest_mtls_no_cert_direct_path(mocker, requests_mock):
    """No client_cert → _mtls_session is None, verify kwarg present in http_function call."""
    requests_mock.post(DEFAULT_URI, text=DEFAULT_TEXT_RESPONSE)
    generator = _plugins.load_plugin(
        "generators.rest.RestGenerator", config_root=_config
    )
    assert generator._mtls_session is None
    mock_http_function = mocker.patch.object(
        generator, "http_function", wraps=generator.http_function
    )
    conv = Conversation([Turn("user", Message("test"))])
    generator._call_model(conv)
    mock_http_function.assert_called_once()
    assert mock_http_function.call_args_list[0].kwargs["verify"] is True


@pytest.mark.usefixtures("set_rest_config")
def test_rest_mtls_both_cert_and_key(tmp_path, requests_mock):
    """tmp_path cert+key → _mtls_session is not None."""
    cert_file = tmp_path / "client.crt"
    key_file = tmp_path / "client.key"
    cert_file.write_text("dummy cert")
    key_file.write_text("dummy key")

    _config.plugins.generators["rest"]["RestGenerator"]["client_cert"] = str(cert_file)
    _config.plugins.generators["rest"]["RestGenerator"]["client_key"] = str(key_file)

    with patch.object(ssl.SSLContext, "load_cert_chain"):
        generator = _plugins.load_plugin(
            "generators.rest.RestGenerator", config_root=_config
        )
    assert generator._mtls_session is not None


@pytest.mark.usefixtures("set_rest_config")
def test_rest_mtls_cert_only(tmp_path):
    """Single combined PEM → _mtls_session is not None."""
    cert_file = tmp_path / "combined.pem"
    cert_file.write_text("dummy combined cert+key")

    _config.plugins.generators["rest"]["RestGenerator"]["client_cert"] = str(cert_file)

    with patch.object(ssl.SSLContext, "load_cert_chain"):
        generator = _plugins.load_plugin(
            "generators.rest.RestGenerator", config_root=_config
        )
    assert generator._mtls_session is not None
    assert generator.client_key is None


@pytest.mark.usefixtures("set_rest_config")
def test_rest_mtls_key_without_cert_raises():
    """BadGeneratorException when client_key set without client_cert."""
    _config.plugins.generators["rest"]["RestGenerator"]["client_key"] = "/some/key.pem"
    with pytest.raises(GarakException) as exc_info:
        _plugins.load_plugin("generators.rest.RestGenerator", config_root=_config)
    assert "client_key" in str(exc_info.value)
    assert "without" in str(exc_info.value)
    assert "client_cert" in str(exc_info.value)


@pytest.mark.usefixtures("set_rest_config")
def test_rest_mtls_nonexistent_cert_raises():
    """BadGeneratorException when client_cert points to a nonexistent file."""
    _config.plugins.generators["rest"]["RestGenerator"][
        "client_cert"
    ] = "/nonexistent/path.pem"
    with pytest.raises(GarakException) as exc_info:
        _plugins.load_plugin("generators.rest.RestGenerator", config_root=_config)
    assert "client_cert" in str(exc_info.value)
    assert "not found" in str(exc_info.value)


@pytest.mark.usefixtures("set_rest_config")
def test_rest_mtls_passphrase_loads_from_env(tmp_path, monkeypatch):
    """Passphrase loaded from env var and passed to load_cert_chain."""
    cert_file = tmp_path / "client.crt"
    key_file = tmp_path / "client.key"
    cert_file.write_text("dummy cert")
    key_file.write_text("dummy key")

    monkeypatch.setenv("TEST_MTLS_PASSPHRASE", "testpass")

    _config.plugins.generators["rest"]["RestGenerator"]["client_cert"] = str(cert_file)
    _config.plugins.generators["rest"]["RestGenerator"]["client_key"] = str(key_file)
    _config.plugins.generators["rest"]["RestGenerator"][
        "client_key_passphrase_env_var"
    ] = "TEST_MTLS_PASSPHRASE"

    with patch.object(ssl.SSLContext, "load_cert_chain") as mock_load:
        generator = _plugins.load_plugin(
            "generators.rest.RestGenerator", config_root=_config
        )
    mock_load.assert_called_once_with(
        str(cert_file),
        keyfile=str(key_file),
        password="testpass",
    )
    # passphrase is cleared after load_cert_chain to reduce memory exposure
    assert generator.client_key_passphrase is None
    assert generator._mtls_session is not None


@pytest.mark.usefixtures("set_rest_config")
def test_rest_mtls_verify_ssl_ca_path(tmp_path):
    """verify_ssl as CA path string combined with client_cert uses create_default_context(cafile=...)."""
    cert_file = tmp_path / "client.crt"
    key_file = tmp_path / "client.key"
    ca_file = tmp_path / "ca.crt"
    cert_file.write_text("dummy cert")
    key_file.write_text("dummy key")
    ca_file.write_text("dummy ca")

    _config.plugins.generators["rest"]["RestGenerator"]["client_cert"] = str(cert_file)
    _config.plugins.generators["rest"]["RestGenerator"]["client_key"] = str(key_file)
    _config.plugins.generators["rest"]["RestGenerator"]["verify_ssl"] = str(ca_file)

    with (
        patch("ssl.create_default_context") as mock_ctx_factory,
        patch.object(ssl.SSLContext, "load_cert_chain") as mock_load,
    ):
        mock_ctx = mock_ctx_factory.return_value
        mock_ctx.load_cert_chain = mock_load
        _plugins.load_plugin("generators.rest.RestGenerator", config_root=_config)
    mock_ctx_factory.assert_called_once_with(cafile=str(ca_file))


@pytest.mark.usefixtures("set_rest_config")
def test_rest_mtls_call_model_uses_session(tmp_path, mocker):
    """_call_model dispatches via _mtls_session.request() when mTLS is active."""
    cert_file = tmp_path / "client.crt"
    cert_file.write_text("dummy cert")

    _config.plugins.generators["rest"]["RestGenerator"]["client_cert"] = str(cert_file)

    with patch.object(ssl.SSLContext, "load_cert_chain"):
        generator = _plugins.load_plugin(
            "generators.rest.RestGenerator", config_root=_config
        )
    assert generator._mtls_session is not None

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "mTLS response"

    mock_session_request = mocker.patch.object(
        generator._mtls_session, "request", return_value=mock_response
    )
    mock_http_function = mocker.patch.object(generator, "http_function")

    conv = Conversation([Turn("user", Message("test mTLS path"))])
    result = generator._call_model(conv)

    mock_session_request.assert_called_once()
    assert mock_session_request.call_args[0] == ("post", DEFAULT_URI)
    mock_http_function.assert_not_called()
    assert result == [Message("mTLS response")]


@pytest.mark.usefixtures("set_rest_config")
def test_rest_mtls_http_uri_raises(tmp_path):
    """BadGeneratorException when mTLS is configured with an http:// URI."""
    cert_file = tmp_path / "client.crt"
    cert_file.write_text("dummy cert")

    _config.plugins.generators["rest"]["RestGenerator"]["client_cert"] = str(cert_file)
    _config.plugins.generators["rest"]["RestGenerator"][
        "uri"
    ] = "http://example.com/api"

    with pytest.raises(GarakException) as exc_info:
        _plugins.load_plugin("generators.rest.RestGenerator", config_root=_config)
    assert "mTLS requires an HTTPS URI" in str(exc_info.value)


@pytest.fixture
def real_mtls_cert_files(tmp_path):
    """Generate real self-signed PEM cert+key files using the cryptography library."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    # generate a 2048-bit RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # build a minimal self-signed cert
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "garak-test")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        .sign(private_key, hashes.SHA256())
    )

    cert_path = tmp_path / "client.crt"
    key_path = tmp_path / "client.key"

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    return str(cert_path), str(key_path)


@pytest.mark.usefixtures("set_rest_config")
def test_rest_mtls_pickle_roundtrip(real_mtls_cert_files):
    """Verify the multiprocessing pickle lifecycle for mTLS sessions.

    __getstate__  → _mtls_session must be None (not picklable)
    __setstate__  → _mtls_session must be reconstructed (not None)
    reconstructed session must have the mTLS adapter mounted on 'https://'
    """
    import requests

    from garak.generators.rest import _MtlsAdapter

    cert_path, key_path = real_mtls_cert_files

    _config.plugins.generators["rest"]["RestGenerator"]["client_cert"] = cert_path
    _config.plugins.generators["rest"]["RestGenerator"]["client_key"] = key_path

    generator = _plugins.load_plugin(
        "generators.rest.RestGenerator", config_root=_config
    )

    # session must be live before pickling
    assert generator._mtls_session is not None

    # --- pickle (getstate) ---
    state = generator.__getstate__()
    assert (
        state["_mtls_session"] is None
    ), "_mtls_session must be cleared in __getstate__ so it can be pickled"

    # --- unpickle (setstate) ---
    generator.__setstate__(state)
    assert (
        generator._mtls_session is not None
    ), "_mtls_session must be reconstructed by __setstate__ via _load_unsafe()"

    # the reconstructed session must have the mTLS adapter on https://
    adapter = generator._mtls_session.get_adapter("https://example.com")
    assert isinstance(
        adapter, _MtlsAdapter
    ), "Reconstructed session must have an _MtlsAdapter mounted on 'https://'"
