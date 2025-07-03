import pytest
import torch
from PIL import Image, ImageDraw
from unittest.mock import patch, MagicMock

from garak.attempt import Conversation, Turn, Message
from garak._config import GarakSubConfig
from garak.generators.huggingface import LLaVA
from garak.exception import ModelNameMissingError

# ─── Constants ─────────────────────────────────────────────────────────

SUPPORTED_MODELS = LLaVA.supported_models

IMG_WIDTH, IMG_HEIGHT = 300, 200
RECT_COORDS = ((50, 50), (200, 150))
ELLIPSE_COORDS = ((150, 50), (250, 150))


# ─── Helpers & Fixtures ────────────────────────────────────────────────


@pytest.fixture
def llava_config():
    """Minimal config forcing CPU for tests."""
    cfg = GarakSubConfig()
    cfg.generators = {
        "huggingface": {"hf_args": {"device": "cpu", "torch_dtype": "float32"}}
    }
    return cfg


@pytest.fixture
def llava_test_image(tmp_path):
    img = Image.new("RGB", (IMG_WIDTH, IMG_HEIGHT), color=(240, 240, 240))
    draw = ImageDraw.Draw(img)
    draw.rectangle(RECT_COORDS, fill=(255, 0, 0))
    draw.ellipse(ELLIPSE_COORDS, fill=(0, 0, 255))
    p = tmp_path / "test.png"
    img.save(p)
    return str(p)


@pytest.fixture(autouse=True)
def mock_hf_when_cpu(monkeypatch):
    """
    mock out all HF model/processor loads
    and device selection so tests run entirely on CPU.
    """
    # fake device selection
    fake_dev = torch.device("cpu")
    monkeypatch.setattr(
        "garak.resources.api.huggingface.HFCompatible._select_hf_device",
        lambda self: fake_dev,
    )
    # fake processor/model loading
    monkeypatch.setattr(
        "transformers.LlavaNextProcessor.from_pretrained",
        lambda name: MagicMock(name="Processor"),
    )
    monkeypatch.setattr(
        "transformers.LlavaNextForConditionalGeneration.from_pretrained",
        lambda name, **kw: MagicMock(name="Model"),
    )



# ─── Tests ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("model_name", SUPPORTED_MODELS)
def test_llava_instantiation_and_device(llava_config, model_name):
    llava = LLaVA(name=model_name, config_root=llava_config)
    assert llava.name == model_name
    assert hasattr(llava, "processor")
    assert hasattr(llava, "model")
    assert isinstance(llava.device, torch.device)
    assert llava.device.type == "cpu"


@pytest.mark.parametrize("model_name", SUPPORTED_MODELS)
def test_llava_generate_returns_decoded_text(
    llava_config, llava_test_image, model_name
):
    # Prepare mocks: override the decode and generate on the fake objects
    fake_proc = LLaVA.processor if False else MagicMock()
    fake_proc.decode.return_value = "decoded output"
    fake_model = MagicMock()
    fake_model.generate.return_value = torch.tensor([[0, 1, 2]])
    # Patch into the instance
    llava = LLaVA(name=model_name, config_root=llava_config)
    llava.processor = fake_proc
    llava.model = fake_model

    conv = Conversation([Turn("user", Message(text="foo", data_path=llava_test_image))])
    out = llava.generate(conv)
    assert isinstance(out, list) and out == [Message("decoded output")]



def test_llava_error_on_missing_image(llava_config):
    llava = LLaVA(name=SUPPORTED_MODELS[0], config_root=llava_config)
    conv = Conversation(
        [Turn("user", Message(text="foo", data_path="/nonexistent.png"))]
    )
    with pytest.raises(FileNotFoundError):
        llava.generate(conv)



def test_llava_unsupported_model(llava_config):
    """Test that instantiating with an unsupported model name raises ModelNameMissingError."""
    with pytest.raises(ModelNameMissingError) as excinfo:
        LLaVA(name="not-a-supported-model", config_root=llava_config)
    # Verify the error message contains useful information
    assert "not-a-supported-model" in str(excinfo.value)


def test_llava_missing_model_name(llava_config):
    """Test that instantiating with an empty model name raises ModelNameMissingError."""
    with pytest.raises(ModelNameMissingError):
        LLaVA(name="", config_root=llava_config)


def test_llava_supported_models_list():
    """Verify that all supported models are properly defined."""
    assert len(SUPPORTED_MODELS) > 0
    for model in SUPPORTED_MODELS:
        assert model.startswith("llava-hf/")
