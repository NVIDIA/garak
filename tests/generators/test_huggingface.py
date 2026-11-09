from types import SimpleNamespace

import pytest
import requests
import transformers

from garak.attempt import Message, Turn, Conversation
from garak._config import GarakSubConfig
from garak.exception import BadGeneratorException
import garak.generators.huggingface


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
    print(hf_generator_config)
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
    conv = Conversation([Turn("user", Message(""))])
    output = g.generate(conv, generations_this_call=generations)
    assert len(output) == generations  # verify generation count matched call
    for item in output:
        assert isinstance(item, Message)


def test_pipeline_chat(mocker, hf_generator_config):
    # uses a ~350M model with chat support
    g = garak.generators.huggingface.Pipeline(
        "microsoft/DialoGPT-small", config_root=hf_generator_config
    )
    mock_format = mocker.patch.object(
        g, "_conversation_to_list", wraps=g._conversation_to_list
    )
    conv = Conversation([Turn("user", Message("Hello world!"))])
    output = g.generate(conv)
    mock_format.assert_called_once()
    assert len(output) == 1
    for item in output:
        assert isinstance(item, Message)


def test_pipeline_text_to_audio(mocker, hf_generator_config):
    """A configured audio pipeline returns a WAV Message."""

    import numpy as np
    import torch

    class AudioPipeline:
        model = SimpleNamespace(config=SimpleNamespace())

        def __call__(self, text):
            assert text == "speak this", "pipeline must receive the message text"
            return {
                "audio": np.zeros((1, 32), dtype=np.float32),
                "sampling_rate": 16_000,
            }

    pipeline = mocker.patch(
        "transformers.pipeline", autospec=True, return_value=AudioPipeline()
    )
    mocker.patch.object(
        garak.generators.huggingface.Pipeline,
        "_select_hf_device",
        return_value=torch.device("cpu"),
    )
    hf_generator_config.generators["huggingface"]["Pipeline"] = {
        "pipeline_task": "text-to-audio",
        "hf_args": {"revision": "test-revision"},
    }

    generator = garak.generators.huggingface.Pipeline(
        "test/audio", config_root=hf_generator_config
    )
    output = generator.generate(Conversation([Turn("user", Message("speak this"))]))[0]

    assert (
        pipeline.call_args.args[0] == "text-to-audio"
    ), "configured pipeline task must be passed to Transformers"
    assert (
        "truncation" not in pipeline.call_args.kwargs
    ), "text-only pipeline arguments must not leak into audio loading"
    assert (
        "do_sample" not in pipeline.call_args.kwargs
    ), "text-generation defaults must not leak into audio loading"
    assert (
        pipeline.call_args.kwargs["revision"] == "test-revision"
    ), "model revision must follow the standard Hugging Face configuration"
    assert output is not None, "successful synthesis must return a Message"
    assert output.data_type == (
        "audio/wav",
        None,
    ), "audio synthesis must identify its output format"
    assert output.data.startswith(b"RIFF"), "audio synthesis must produce a WAV"
    assert (
        output.notes["sample_rate"] == 16_000
    ), "effective sample rate must be retained as provenance"
    assert (
        output.notes["revision"] == "test-revision"
    ), "configured model revision must be retained as provenance"


def test_inference(mocker, hf_mock_response, hf_generator_config):
    target_name = "gpt2"
    mock_request = mocker.patch.object(
        requests, "request", return_value=hf_mock_response
    )

    g = garak.generators.huggingface.InferenceAPI(
        target_name, config_root=hf_generator_config
    )
    assert g.name == target_name
    assert target_name in g.uri

    hf_generator_config.generators["huggingface"]["name"] = target_name
    g = garak.generators.huggingface.InferenceAPI(config_root=hf_generator_config)
    assert g.name == target_name
    assert target_name in g.uri
    assert isinstance(g.max_tokens, int)
    g.max_tokens = 99
    assert g.max_tokens == 99
    g.temperature = 0.1
    assert g.temperature == 0.1
    conv = Conversation([Turn("user", Message(""))])
    output = g.generate(conv)
    mock_request.assert_called_once()
    assert len(output) == 1  # 1 generation by default
    for item in output:
        assert isinstance(item, Message)


def test_inference_model_not_found(mocker, hf_generator_config):
    target_name = "Qwen/Qwen2.5-7B-Instruct"
    mock_resp = requests.Response()
    mock_resp.status_code = 404
    mock_resp._content = b"Not Found"
    mocker.patch.object(requests, "request", return_value=mock_resp)

    g = garak.generators.huggingface.InferenceAPI(
        target_name, config_root=hf_generator_config
    )
    conv = Conversation([Turn("user", Message(""))])
    with pytest.raises(BadGeneratorException, match=target_name):
        g.generate(conv)


def test_endpoint(mocker, hf_mock_response, hf_generator_config):
    target_name = "https://localhost:8000/gpt2"
    mock_request = mocker.patch.object(requests, "post", return_value=hf_mock_response)

    g = garak.generators.huggingface.InferenceEndpoint(
        target_name, config_root=hf_generator_config
    )
    assert g.name == target_name
    assert g.uri == target_name

    hf_generator_config.generators["huggingface"]["name"] = target_name
    g = garak.generators.huggingface.InferenceEndpoint(config_root=hf_generator_config)
    assert g.name == target_name
    assert g.uri == target_name
    assert isinstance(g.max_tokens, int)
    g.max_tokens = 99
    assert g.max_tokens == 99
    g.temperature = 0.1
    assert g.temperature == 0.1
    conv = Conversation([Turn("user", Message(""))])
    output = g.generate(conv)
    mock_request.assert_called_once()
    assert len(output) == 1  # 1 generation by default
    for item in output:
        assert isinstance(item, Message)


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
    conv = Conversation([Turn("user", Message(""))])
    output = g.generate(conv)
    assert len(output) == 1  # expect 1 generation by default
    for item in output:
        assert item is None  # gpt2 is known raise exception returning `None`


def test_model_chat(mocker, hf_generator_config):
    # uses a ~350M model with chat support
    g = garak.generators.huggingface.Model(
        "microsoft/DialoGPT-small", config_root=hf_generator_config
    )
    mock_format = mocker.patch.object(
        g, "_conversation_to_list", wraps=g._conversation_to_list
    )
    conv = Conversation([Turn("user", Message("Hello world!"))])
    output = g.generate(conv)
    mock_format.assert_called_once()
    assert len(output) == 1
    for item in output:
        assert isinstance(item, Message)


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
