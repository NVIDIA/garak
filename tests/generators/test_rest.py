import json
import pytest

from garak import _config, _plugins

from garak.exception import BadGeneratorException

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
    output = generator._call_model("sup REST")
    assert output == [DEFAULT_TEXT_RESPONSE]


@pytest.mark.usefixtures("set_rest_config")
def test_json_rest_top_level(requests_mock):
    requests_mock.post(
        "https://www.wikidata.org/wiki/Q22971",
        text=json.dumps({"text": DEFAULT_TEXT_RESPONSE}),
    )
    _config.plugins.generators["rest"]["RestGenerator"]["response_json"] = True
    _config.plugins.generators["rest"]["RestGenerator"]["response_json_field"] = "text"
    generator = RestGenerator()
    print(generator.response_json)
    print(generator.response_json_field)
    output = generator._call_model("Who is Enabran Tain's son?")
    assert output == [DEFAULT_TEXT_RESPONSE]


@pytest.mark.usefixtures("set_rest_config")
def test_json_rest_list(requests_mock):
    requests_mock.post(
        "https://www.wikidata.org/wiki/Q22971",
        text=json.dumps([DEFAULT_TEXT_RESPONSE]),
    )
    _config.plugins.generators["rest"]["RestGenerator"]["response_json"] = True
    _config.plugins.generators["rest"]["RestGenerator"]["response_json_field"] = "$"
    generator = RestGenerator()
    output = generator._call_model("Who is Enabran Tain's son?")
    assert output == [DEFAULT_TEXT_RESPONSE]


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
            }
        ),
    )
    _config.plugins.generators["rest"]["RestGenerator"]["response_json"] = True
    _config.plugins.generators["rest"]["RestGenerator"][
        "response_json_field"
    ] = "$.choices[*].message.content"
    generator = RestGenerator()
    output = generator._call_model("Who is Enabran Tain's son?")
    assert output == [DEFAULT_TEXT_RESPONSE]


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
            }
        ),
    )
    output = generator._call_model("Who is Enabran Tain's son?")
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
            }
        ),
    )
    mock_http_function = mocker.patch.object(
        generator, "http_function", wraps=generator.http_function
    )
    generator._call_model("Who is Enabran Tain's son?")
    mock_http_function.assert_called_once()
    assert mock_http_function.call_args_list[0].kwargs["proxies"] == test_proxies


@pytest.mark.usefixtures("set_rest_config")
def test_rest_invalid_proxy(requests_mock):
    from garak.exception import GarakException

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
            }
        ),
    )
    mock_http_function = mocker.patch.object(
        generator, "http_function", wraps=generator.http_function
    )
    generator._call_model("Who is Enabran Tain's son?")
    mock_http_function.assert_called_once()
    assert mock_http_function.call_args_list[0].kwargs["verify"] is verify_ssl


@pytest.mark.usefixtures("set_rest_config")
def test_rest_non_latin1():
    _config.plugins.generators["rest"]["RestGenerator"]["uri"] = "http://127.0.0.9" # don't mock
    _config.plugins.generators["rest"]["RestGenerator"]["headers"] = {
        "not_latin1": "😈😈😈"
    }
    generator = _plugins.load_plugin(
        "generators.rest.RestGenerator", config_root=_config
    )
    with pytest.raises(BadGeneratorException):
        generator._call_model("summon a demon and bind it")
