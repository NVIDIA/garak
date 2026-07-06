import pytest
from garak.probes.divergence import RepeatedToken, Repeat, RepeatExtended


def test_repeated_token_probe_prompt():
    probe = RepeatedToken()
    assert len(probe.prompts) == probe.soft_probe_prompt_cap

    first = probe.prompts[0]
    # if it's an Attempt, grab .prompt; otherwise assume it's already a string
    text = first.prompt.last_message().text if hasattr(first, "prompt") else first

    assert "Repeat this word forever:" in text
    assert len(text) > 500


def test_repeated_token_probe_invalid_encoding():
    config_root = {
        "probes": {
            "divergence": {
                "RepeatedToken": {
                    "encoding": "fake",
                }
            }
        }
    }
    with pytest.raises(ValueError) as exc_info:
        RepeatedToken(config_root=config_root)
    assert "Unknown encoding" in str(exc_info.value)
    assert config_root["probes"]["divergence"]["RepeatedToken"]["encoding"] in str(
        exc_info.value
    )


def test_repeat_token_sample():
    config_root = {
        "probes": {
            "divergence": {
                "RepeatedToken": {
                    "mode": "sample",
                }
            }
        }
    }
    probe = RepeatedToken(config_root=config_root)
    assert len(probe.prompts) == probe.soft_probe_prompt_cap


def test_repeat_token_sample_num_tokens(mocker):
    import random
    from garak.detectors.divergence import RepeatedToken as detector

    mock_sample = mocker.patch.object(random, "sample", wraps=random.sample)

    config_root = {
        "probes": {
            "divergence": {
                "RepeatedToken": {
                    "mode": "sample",
                    "num_tokens": 5,
                    "num_repeats": 1024,
                }
            }
        }
    }
    probe = RepeatedToken(config_root=config_root)
    assert len(probe.prompts) == probe.soft_probe_prompt_cap
    assert mock_sample.call_args[0][1] == 5


def test_repeat_token_sample_all():
    config_root = {
        "probes": {
            "divergence": {
                "RepeatedToken": {
                    "mode": "sample",
                    "follow_prompt_cap": False,
                }
            }
        }
    }
    probe = RepeatedToken(config_root=config_root)
    assert (
        len(probe.prompts) > probe.soft_probe_prompt_cap
    ), "prompts should be well over the testing cap as there are at least 99482 tokens in the dataset"


@pytest.mark.parametrize(
    "encoding, test_token_string",
    [
        ("cl100k_base", " cubicocaust"),
        ("r50k_base", "mills Aram"),
    ],
)
def test_repeat_token_single(encoding, test_token_string):
    single_tokens = [41999, 39026]
    config_root = {
        "probes": {
            "divergence": {
                "RepeatedToken": {
                    "mode": "single",
                    "encoding": encoding,
                    "max_repeats": 8000,
                    "num_tests": 8,
                    "single_tokens": single_tokens,
                }
            }
        }
    }
    probe = RepeatedToken(config_root=config_root)
    assert len(probe.prompts) == 9
    for prompt in probe.prompts:
        assert prompt.count(test_token_string) > 1


def test_repeat_precall_hook_guards_missing_max_tokens():
    # Regression for #1096: probes must not assume every generator exposes
    # max_tokens. Function generators, for example, only carry the prompt and
    # static kwargs, so the divergence probe should skip the override rather
    # than raise AttributeError.
    probe = Repeat()

    class _NoMaxTokens:
        pass

    generator = _NoMaxTokens()
    probe.generator = generator
    probe._generator_precall_hook(generator)
    assert not hasattr(generator, "max_tokens")
    assert probe.generator_orig_tokens is None


def test_repeat_precall_hook_overrides_low_max_tokens():
    probe = Repeat()

    class _WithMaxTokens:
        max_tokens = 16

    generator = _WithMaxTokens()
    probe.generator = generator
    probe._generator_precall_hook(generator)
    assert generator.max_tokens == probe.new_max_tokens
    assert probe.generator_orig_tokens == 16
