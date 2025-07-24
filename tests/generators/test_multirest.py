import pytest
from garak.generators.rest import MultiRestGenerator
from garak import _config, _plugins

EXAMPLE_BURP_XML = {"burpfile": "./garak/data/rest/multirest.xml"}

EXAMPLE_CONFIG = {
    "rest": {
        "MultiRestGenerator": {
            "manual": {
                "first_stage": {
                    "name": "request service",
                    "uri": "https://example.ai/llm",
                    "method": "POST",
                    "headers": {
                        "X-Authorization": "$KEY",
                    },
                    "req_template_json_object": {"text": "$INPUT"},
                    "response_json": "true",
                    "response_template_json_object": {"id": "$1$77777$1$"},
                },
                "second_stage": {
                    "name": "response service",
                    "uri": "https://example.ai/llm?id=$1$id$1$",
                    "method": "GET",
                    "headers": {
                        "X-Authorization": "1231321",
                    },
                    "response_json": "true",
                    "response_template_json_object": {
                        "message": "$OUT$Hello World!$OUT$"
                    },
                },
            }
        }
    }
}


@pytest.fixture
def mr_gen_burpfile_config():
    _config.plugins.generators["rest"] = {}
    _config.plugins.generators["rest"]["MultiRestGenerator"] = EXAMPLE_CONFIG["rest"][
        "MultiRestGenerator"
    ]
    generator = MultiRestGenerator()
    return generator


@pytest.fixture
def mr_gen_burpfile():
    _config.plugins.generators["rest"] = {}
    _config.plugins.generators["rest"]["MultiRestGenerator"] = EXAMPLE_BURP_XML
    generator = MultiRestGenerator()
    return generator


# Test run function using burpfile
@pytest.mark.usefixtures("mr_gen_burpfile")
def test_run_extracts_output(mr_gen_burpfile, requests_mock):
    mr_gen_burpfile.reqresp_pairs = mr_gen_burpfile.get_reqrep_fromburp()

    url = "https://example.com/score"
    requests_mock.post(
        url,
        headers={"Content-Type": "application/json"},
        status_code=200,
        text='{"id": "999999"}',
    )
    url2 = "https://example.com/score?id=999999"
    requests_mock.get(
        url2,
        headers={"Content-Type": "application/json"},
        status_code=400,
        text='{"message": "error details"}',
    )

    output = mr_gen_burpfile.run("Hello")
    assert output == "error details"


# Test run function using the config
@pytest.mark.usefixtures("mr_gen_burpfile_config")
def test_run_with_config_and_mock(mr_gen_burpfile_config, requests_mock):
    url = "https://example.ai/llm"
    requests_mock.post(
        url,
        headers={"Content-Type": "application/json"},
        status_code=200,
        text='{"id": "999999"}',
    )
    url2 = "https://example.ai/llm?id=999999"
    requests_mock.get(
        url2,
        headers={"Content-Type": "application/json"},
        status_code=400,
        json={"message": "error details"},
    )

    output = mr_gen_burpfile_config.run("Hello")
    assert output == "error details"
