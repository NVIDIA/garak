import os
import pytest
import tempfile
import garak.generators.ggml

STORED_ENV = os.getenv(garak.generators.ggml.ENV_VAR)
MODEL_NAME = None


@pytest.fixture(autouse=True)
def set_fake_env() -> None:
    os.environ[garak.generators.ggml.ENV_VAR] = os.path.abspath(__file__)


def test_init_bad_app():
    with pytest.raises(RuntimeError) as exc_info:
        del os.environ[garak.generators.ggml.ENV_VAR]
        garak.generators.ggml.GgmlGenerator(MODEL_NAME)
    assert "not provided by environment" in str(exc_info.value)


def test_init_missing_model():
    model_name = tempfile.TemporaryFile().name
    with pytest.raises(FileNotFoundError) as exc_info:
        garak.generators.ggml.GgmlGenerator(model_name)
    assert "File not found" in str(exc_info.value)


def test_init_bad_model():
    with tempfile.NamedTemporaryFile(
        mode="w", suffix="_test_model.gguf", encoding="utf-8", delete=False
    ) as file:
        file.write(file.name)
        file.close()
        with pytest.raises(RuntimeError) as exc_info:
            garak.generators.ggml.GgmlGenerator(file.name)
        os.remove(file.name)
        assert "not in GGUF" in str(exc_info.value)


def test_init_good_model():
    with tempfile.NamedTemporaryFile(suffix="_test_model.gguf", delete=False) as file:
        file.write(garak.generators.ggml.GGUF_MAGIC)
        file.close()
        g = garak.generators.ggml.GgmlGenerator(file.name)
        os.remove(file.name)
        assert type(g) is garak.generators.ggml.GgmlGenerator


def test_command_args_list():
    """ensure command list overrides apply and `extra_ggml_params` are in correct relative order"""
    with tempfile.NamedTemporaryFile(suffix="_test_model.gguf", delete=False) as file:
        file.write(garak.generators.ggml.GGUF_MAGIC)
        file.close()

        gen_config = {
            "extra_ggml_flags": [
                "test_value",
                "another_value",
            ],
            "extra_ggml_params": {
                "custom_param": "custom_value",
            },
        }

        config_root = {"generators": {"ggml": {"GgmlGenerator": gen_config}}}

        g = garak.generators.ggml.GgmlGenerator(file.name, config_root=config_root)
        arg_list = g._command_args_list()
        for arg in gen_config["extra_ggml_flags"]:
            assert arg in arg_list
        for arg, value in gen_config["extra_ggml_params"].items():
            assert arg in arg_list
            assert value in arg_list
            arg_index = arg_list.index(arg)
            value_index = arg_list.index(value)
            assert arg_index + 1 == value_index

        os.remove(file.name)
        assert type(g) is garak.generators.ggml.GgmlGenerator
