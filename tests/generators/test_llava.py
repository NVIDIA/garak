import os
import pytest
import torch
from pathlib import Path
from PIL import Image, ImageDraw
from unittest.mock import patch, MagicMock

from garak._config import GarakSubConfig
from garak.generators.huggingface import LLaVA
from garak.exception import ModelNameMissingError

# ─── Constants ─────────────────────────────────────────────────────────

SUPPORTED_MODELS = [
    "llava-hf/llava-v1.6-34b-hf",
    "llava-hf/llava-v1.6-vicuna-13b-hf",
    "llava-hf/llava-v1.6-vicuna-7b-hf",
    "llava-hf/llava-v1.6-mistral-7b-hf",
]

IMG_WIDTH, IMG_HEIGHT = 300, 200
RECT_COORDS = ((50, 50), (200, 150))
ELLIPSE_COORDS = ((150, 50), (250, 150))


# ─── Helpers & Fixtures ────────────────────────────────────────────────

@pytest.fixture
def llava_config():
    """Minimal config forcing CPU for tests."""
    cfg = GarakSubConfig()
    cfg.generators = {
        "huggingface": {
            "hf_args": {"device": "cpu", "torch_dtype": "float32"}
        }
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
    If no CUDA, mock out all HF model/processor loads
    and device selection so tests run entirely on CPU.
    """
    if not torch.cuda.is_available():
        # fake device selection
        fake_dev = torch.device("cpu")
        monkeypatch.setattr(
            "garak.resources.api.huggingface.HFCompatible._select_hf_device",
            lambda self: fake_dev
        )
        # fake processor/model loading
        monkeypatch.setattr(
            "transformers.LlavaNextProcessor.from_pretrained",
            lambda name: MagicMock(name="Processor")
        )
        monkeypatch.setattr(
            "transformers.LlavaNextForConditionalGeneration.from_pretrained",
            lambda name, **kw: MagicMock(name="Model")
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
def test_llava_generate_returns_decoded_text(llava_config, llava_test_image, model_name):
    # Prepare mocks: override the decode and generate on the fake objects
    fake_proc = LLaVA.processor if False else MagicMock()
    fake_proc.decode.return_value = "decoded output"
    fake_model = MagicMock()
    fake_model.generate.return_value = torch.tensor([[0, 1, 2]])
    # Patch into the instance
    llava = LLaVA(name=model_name, config_root=llava_config)
    llava.processor = fake_proc
    llava.model = fake_model

    out = llava.generate({"text": "foo", "image": llava_test_image})
    assert isinstance(out, list) and out == ["decoded output"]

def test_llava_error_on_missing_image(llava_config):
    llava = LLaVA(name=SUPPORTED_MODELS[0], config_root=llava_config)
    with pytest.raises(FileNotFoundError):
        llava.generate({"text": "foo", "image": "/nonexistent.png"})

def test_llava_unsupported_model(llava_config):
    with pytest.raises(ModelNameMissingError):
        LLaVA(name="not-a-supported-model", config_root=llava_config)
