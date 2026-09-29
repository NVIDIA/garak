import pytest
import torch
import transformers

from garak.resources.api.huggingface import HFCompatible


class MockHF(HFCompatible):
    def __init__(self, hf_args):
        self.name = "gpt2"
        self.device = torch.device("cpu")
        self.hf_args = dict(hf_args)


@pytest.mark.parametrize(
    "constructor",
    [
        transformers.pipeline,
        transformers.AutoConfig.from_pretrained,
        transformers.AutoModelForCausalLM.from_pretrained,
    ],
)
@pytest.mark.parametrize(
    "hf_args, expected",
    [
        ({"torch_dtype": "float16"}, torch.float16),
        ({"dtype": "bfloat16"}, torch.bfloat16),
        ({"torch_dtype": "float16", "dtype": "float32"}, torch.float32),
        ({"dtype": "auto"}, "auto"),
    ],
)
def test_gather_hf_params_dtype(constructor, hf_args, expected):
    args = MockHF(hf_args)._gather_hf_params(hf_constructor=constructor)
    assert (
        args.get("dtype") == expected
    ), "dtype should resolve from either name, dtype winning"
    assert (
        "torch_dtype" not in args
    ), "only the current name, dtype, should be forwarded"
