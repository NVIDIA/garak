import pytest
from garak.generators.multirest import MultiRestGenerator

BURP_XML_PATH = "./tools/rest/multirest.xml"

@pytest.fixture
def mr_gen(tmp_path):
    generator = MultiRestGenerator()
    generator.burpfile = BURP_XML_PATH
    return generator

def test_extract_output_from_json():
    gen = MultiRestGenerator()
    template = {"message": "$OUTPUT"}
    real = {"message": "error details"}
    outputs = gen.extract_output_from_json(template, real)
    assert outputs == ["error details"]

def test_run_extracts_output(mr_gen, requests_mock):
    # Prepare the generator with the test XML
    mr_gen.reqresp_pairs = mr_gen.get_reqrep_fromburp(BURP_XML_PATH)

    # Mock the endpoint for both test cases
    url = "https://example.com/score"
    # First response: 200 OK
    requests_mock.post(url, [
        {
            "status_code": 200,
            "json": {"id": "999999"}
        },
    ])
    url2 = "https://example.com/score?id=999999"
    requests_mock.get(url2, status_code=400, json={"message": "error details"})

    # Run the generator for the first request (should not extract $OUTPUT)
    output = mr_gen.run("Hello")
    # The second request in the XML expects $OUTPUT to be extracted
    assert output == "error details"


def test_substitute_placeholders(mr_gen):
    mr_gen = MultiRestGenerator()
    mr_gen.variables = {"1": "foo"}
    text = '{"data":"$1$Hello$1$"}'
    result = mr_gen.substitute_placeholders(text)
    assert result == '{"data":"foo"}'

def test_response_mismatch_raises(mr_gen, requests_mock):
    mr_gen.reqresp_pairs = [{
        "request": {
            "method": "GET",
            "headers": {"Host": "example.com"},
            "endpoint": "/fail",
            "body": ""
        },
        "response": {
            "body": '{"expected":"value"}',
            "headers": {}
        }
    }]
    url = "https://example.com/fail"
    requests_mock.get(url, json={"unexpected": "different"})
    with pytest.raises(ValueError):
        mr_gen.run("prompt")

def test_substitute_placeholders_no_vars(mr_gen):
    mr_gen.variables = {}
    text = '{"data":"$1$Hello$1$"}'
    result = mr_gen.substitute_placeholders(text)
    assert result == '{"data":"$1$Hello$1$"}'

def test_extract_vars_from_headers(mr_gen):
    packet = {
        "headers": {"X-Token": "$1$tokenval$1$"},
        "body": ""
    }
    vars_found = mr_gen.extract_vars_from_packet(packet)
    assert vars_found == {"1": "tokenval"}

def test_non_json_response(mr_gen, requests_mock):
    packet = {
        "method": "GET",
        "headers": {"Host": "example.com"},
        "endpoint": "/plain",
        "body": ""
    }
    url = "https://example.com/plain"
    requests_mock.get(url, text="plain text response")
    resp = mr_gen.make_request(packet)
    assert resp.text == "plain text response"

def test_get_request_with_placeholder(mr_gen, requests_mock):
    mr_gen.variables = {"1": "abc123"}
    packet = {
        "method": "GET",
        "headers": {"Host": "example.com"},
        "endpoint": "/score?id=$1$foo$1$",
        "body": ""
    }
    url = "https://example.com/score?id=abc123"
    requests_mock.get(url, text="ok")
    req_packet = mr_gen.substitute_in_packet(packet)
    resp = mr_gen.make_request(req_packet)
    assert resp.text == "ok"