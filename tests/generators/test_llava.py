import pytest
import torch
from unittest.mock import patch, MagicMock

from garak.attempt import Conversation, Turn, Message
from garak._config import GarakSubConfig
from garak.exception import GarakException, TargetNameMissingError

try:
    from PIL import Image, ImageDraw
    from garak.generators.huggingface import LLaVA

except:
    pytest.skip(
        "couldn't import LLaVA and deps, skipping llava tests", allow_module_level=True
    )


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


@pytest.mark.parametrize("target_name", SUPPORTED_MODELS)
def test_llava_instantiation_and_device(llava_config, target_name):
    llava = LLaVA(name=target_name, config_root=llava_config)
    assert llava.name == target_name
    assert hasattr(llava, "processor")
    assert hasattr(llava, "model")
    assert isinstance(llava.device, torch.device)
    assert llava.device.type == "cpu"


@pytest.mark.parametrize("target_name", SUPPORTED_MODELS)
def test_llava_generate_returns_decoded_text(
    llava_config, llava_test_image, target_name
):
    # Prepare mocks: override the decode and generate on the fake objects
    fake_proc = LLaVA.processor if False else MagicMock()
    fake_proc.decode.return_value = "decoded output"
    fake_model = MagicMock()
    fake_model.generate.return_value = torch.tensor([[0, 1, 2]])
    # Patch into the instance
    llava = LLaVA(name=target_name, config_root=llava_config)
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
    """Test that instantiating with an unsupported model name raises TargetNameMissingError."""
    with pytest.raises(TargetNameMissingError) as excinfo:
        LLaVA(name="not-a-supported-model", config_root=llava_config)
    # Verify the error message contains useful information
    assert "not-a-supported-model" in str(excinfo.value)


def test_llava_missing_target_name(llava_config):
    """Test that instantiating with an empty model name raises TargetNameMissingError."""
    with pytest.raises(TargetNameMissingError):
        LLaVA(name="", config_root=llava_config)


def test_llava_supported_models_list():
    """Verify that all supported models are properly defined."""
    assert len(SUPPORTED_MODELS) > 0
    for model in SUPPORTED_MODELS:
        assert model.startswith("llava-hf/")


def _model_mock(hf_device_map):
    """Fake model whose `.to` is observable; `hf_device_map` mimics accelerate
    dispatch (a dict) or no dispatch (None)."""
    model = MagicMock(name="Model")
    model.to = MagicMock(name="to")
    model.hf_device_map = hf_device_map
    return model


@pytest.mark.parametrize(
    "hf_device_map, should_move", [({"": "cpu"}, False), (None, True)]
)
def test_llava_model_move_respects_device_map(
    llava_config, monkeypatch, hf_device_map, should_move
):
    """__init__ must not call `model.to()` when accelerate dispatched the
    model (`hf_device_map` set) — that raises on offloaded models — but must move
    it when accelerate did not place it."""
    model = _model_mock(hf_device_map)
    monkeypatch.setattr(
        "transformers.LlavaNextForConditionalGeneration.from_pretrained",
        lambda name, **kw: model,
    )
    llava = LLaVA(name=SUPPORTED_MODELS[0], config_root=llava_config)
    if should_move:
        model.to.assert_called_once_with(llava.device)
    else:
        model.to.assert_not_called()


def test_llava_error_on_text_only_prompt(llava_config):
    """Text-only prompt (`data_path is None`) raises a GarakException correctly."""
    llava = LLaVA(name=SUPPORTED_MODELS[0], config_root=llava_config)
    with pytest.raises(GarakException):
        llava.generate(Conversation([Turn("user", Message(text="foo"))]))


def test_llava_generate_runs_when_model_dispatched_across_devices(
    llava_config, llava_test_image, tmp_path
):
    """A model split across devices by accelerate raises on `.to()` (which is why
    __init__ guards the move), yet generate() still runs: the processor output is a
    BatchFeature, so `.to(self.device)` is an ordinary tensor move and accelerate's
    hooks realign inputs per submodule at forward time."""
    accelerate = pytest.importorskip("accelerate")
    import torch.nn as nn
    from types import SimpleNamespace
    from transformers.feature_extraction_utils import BatchFeature

    class TinyVLM(nn.Module):
        def __init__(self):
            super().__init__()
            self.embed = nn.Embedding(16, 8)
            self.head = nn.Linear(8, 16)
            self.generation_config = SimpleNamespace(max_new_tokens=None)

        def generate(self, **inputs):
            return self.head(self.embed(inputs["input_ids"])).argmax(dim=-1)

    # cpu + disk split -> multi-entry hf_device_map with offloaded params on `meta`
    model = accelerate.dispatch_model(
        TinyVLM().eval(),
        device_map={"embed": "cpu", "head": "disk"},
        offload_dir=str(tmp_path / "offload"),
    )
    assert len(model.hf_device_map) > 1
    # the move __init__ guards against: this dispatched model cannot be `.to()`-moved
    with pytest.raises(RuntimeError):
        model.to(torch.device("cpu"))

    processor = MagicMock()
    processor.return_value = BatchFeature({"input_ids": torch.tensor([[1, 2, 3]])})
    processor.decode.return_value = "across-device output"

    llava = LLaVA(name=SUPPORTED_MODELS[0], config_root=llava_config)
    llava.model = model
    llava.processor = processor
    llava.device = torch.device("cpu")

    conv = Conversation([Turn("user", Message(text="x", data_path=llava_test_image))])
    # generate() completes even though `.to()` on this same model would have raised
    assert llava.generate(conv) == [Message("across-device output")]
