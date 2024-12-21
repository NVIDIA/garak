import pytest
import requests
import transformers
import garak.generators.huggingface
from garak._config import GarakSubConfig


@pytest.fixture
def hf_generator_config():
    gen_config = {
        "huggingface": {
            "api_key": "fake",
            "hf_args": {
                "device": "cpu",
                "torch_dtype": "float32",
            },
        }
    }
    config_root = GarakSubConfig()
    setattr(config_root, "generators", gen_config)
    return config_root


@pytest.fixture
def hf_mock_response(hf_endpoint_mocks):
    import json

    mock_resp_data = hf_endpoint_mocks["hf_inference"]
    mock_resp = requests.Response()
    mock_resp.status_code = mock_resp_data["code"]
    mock_resp._content = json.dumps(mock_resp_data["json"]).encode("UTF-8")
    return mock_resp


def test_pipeline(hf_generator_config):
    generations = 10
    g = garak.generators.huggingface.Pipeline("gpt2", config_root=hf_generator_config)
    assert g.name == "gpt2"
    assert isinstance(g.generator, transformers.pipelines.text_generation.Pipeline)
    assert isinstance(g.generator.model, transformers.PreTrainedModel)
    assert isinstance(g.generator.tokenizer, transformers.PreTrainedTokenizerBase)
    assert isinstance(g.max_tokens, int)
    g.max_tokens = 99
    assert g.max_tokens == 99
    g.temperature = 0.1
    assert g.temperature == 0.1
    output = g.generate("", generations_this_call=generations)
    assert len(output) == generations  # verify generation count matched call
    for item in output:
        assert isinstance(item, str)


def test_pipeline_chat(mocker, hf_generator_config):
    # uses a ~350M model with chat support
    g = garak.generators.huggingface.Pipeline(
        "microsoft/DialoGPT-small", config_root=hf_generator_config
    )
    mock_format = mocker.patch.object(
        g, "_format_chat_prompt", wraps=g._format_chat_prompt
    )
    output = g.generate("Hello world!")
    mock_format.assert_called_once()
    assert len(output) == 1
    for item in output:
        assert isinstance(item, str)


def test_inference(mocker, hf_mock_response, hf_generator_config):
    model_name = "gpt2"
    mock_request = mocker.patch.object(
        requests, "request", return_value=hf_mock_response
    )

    g = garak.generators.huggingface.InferenceAPI(
        model_name, config_root=hf_generator_config
    )
    assert g.name == model_name
    assert model_name in g.uri

    hf_generator_config.generators["huggingface"]["name"] = model_name
    g = garak.generators.huggingface.InferenceAPI(config_root=hf_generator_config)
    assert g.name == model_name
    assert model_name in g.uri
    assert isinstance(g.max_tokens, int)
    g.max_tokens = 99
    assert g.max_tokens == 99
    g.temperature = 0.1
    assert g.temperature == 0.1
    output = g.generate("")
    mock_request.assert_called_once()
    assert len(output) == 1  # 1 generation by default
    for item in output:
        assert isinstance(item, str)


def test_endpoint(mocker, hf_mock_response, hf_generator_config):
    model_name = "https://localhost:8000/gpt2"
    mock_request = mocker.patch.object(requests, "post", return_value=hf_mock_response)

    g = garak.generators.huggingface.InferenceEndpoint(
        model_name, config_root=hf_generator_config
    )
    assert g.name == model_name
    assert g.uri == model_name

    hf_generator_config.generators["huggingface"]["name"] = model_name
    g = garak.generators.huggingface.InferenceEndpoint(config_root=hf_generator_config)
    assert g.name == model_name
    assert g.uri == model_name
    assert isinstance(g.max_tokens, int)
    g.max_tokens = 99
    assert g.max_tokens == 99
    g.temperature = 0.1
    assert g.temperature == 0.1
    output = g.generate("")
    mock_request.assert_called_once()
    assert len(output) == 1  # 1 generation by default
    for item in output:
        assert isinstance(item, str)


def test_model(hf_generator_config):
    g = garak.generators.huggingface.Model("gpt2", config_root=hf_generator_config)
    assert g.name == "gpt2"
    assert isinstance(g, garak.generators.huggingface.Model)
    assert isinstance(g.model, transformers.PreTrainedModel)
    assert isinstance(g.tokenizer, transformers.PreTrainedTokenizerBase)
    assert isinstance(g.max_tokens, int)
    g.max_tokens = 99
    assert g.max_tokens == 99
    g.temperature = 0.1
    assert g.temperature == 0.1
    output = g.generate("")
    assert len(output) == 1  # expect 1 generation by default
    for item in output:
        assert item is None  # gpt2 is known raise exception returning `None`


def test_model_chat(mocker, hf_generator_config):
    # uses a ~350M model with chat support
    g = garak.generators.huggingface.Model(
        "microsoft/DialoGPT-small", config_root=hf_generator_config
    )
    mock_format = mocker.patch.object(
        g, "_format_chat_prompt", wraps=g._format_chat_prompt
    )
    output = g.generate("Hello world!")
    mock_format.assert_called_once()
    assert len(output) == 1
    for item in output:
        assert isinstance(item, str)


def test_select_hf_device():
    from garak.generators.huggingface import HFCompatible
    import torch

    class mockHF(HFCompatible):
        def __init__(self, key, value):
            self.hf_args = {key: value}
            pass

    m = mockHF("device", -1)
    with pytest.raises(ValueError) as exc_info:
        device = m._select_hf_device()
    assert "CUDA device numbering starts" in str(exc_info.value)

    m = mockHF("device", "cpu")
    device = m._select_hf_device()
    assert device == torch.device("cpu")

    m = mockHF("device_map", "auto")
    device = m._select_hf_device()
    assert isinstance(device, torch.device)
