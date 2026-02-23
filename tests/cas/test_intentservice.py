# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import importlib
import inspect
import nltk
import pytest

import garak._config

from garak.exception import GarakException

nltk.download("punkt_tab")
cas_data_path = garak._config.transient.package_dir / "data" / "cas"


def test_load_intentservice():
    import garak.services.intentservice

    garak._config.load_config()
    garak.services.intentservice.load()


def test_intentservice_reject_load():
    import garak.services.intentservice

    garak._config.is_loaded = False
    assert (
        garak.services.intentservice.enabled() == False
    ), "intent service must return disabled if config is not loaded"


INVALID_INTENTS = ["X", "c", "C1", "C0001", "CC001", "C001HELLO"]


@pytest.mark.parametrize("invalid_intent", INVALID_INTENTS)
def test_invalid_intents_rejected(invalid_intent):
    import garak.services.intentservice

    with pytest.raises(ValueError) as excinfo:
        s = garak.services.intentservice.get_intent_stubs(invalid_intent)
    assert str(excinfo.value).startswith("Not a valid")


def test_no_spurious_text_intents():
    import garak.services.intentservice

    garak._config.load_config()
    garak.services.intentservice.load()

    text_stubs_path = cas_data_path / "intent_stubs"
    for child in text_stubs_path.iterdir():
        if child.name == "README.md":
            continue
        intent_code = child.stem.split("_")[0]
        assert intent_code in garak.services.intentservice.intent_typology, (
            "Text stub file code %s not in typology" % child
        )


@pytest.mark.skip(reason="nltk.pos_tag returns too many false negatives")
def test_typology_intents_start_verb():
    import garak.services.intentservice

    garak.services.intentservice.load()
    for intent in garak.services.intentservice.intent_typology:
        text_intents = garak.services.intentservice._get_stubs_typology(intent)
        for text_intent in text_intents:
            tags = nltk.pos_tag(nltk.word_tokenize(text_intent))
            assert (
                tags[0][1] == "VB"
            ), "Intents must begin with a verb; intent '%s' reads '%s'" % (
                intent,
                text_intent,
            )


INTENT_MODULES = [
    module.name.replace(".py", "")
    for module in (garak._config.transient.package_dir / "intents").iterdir()
    if module.name not in ("base.py", "__pycache__", "__init__.py")
]


@pytest.mark.parametrize("intent_module", INTENT_MODULES)
def test_code_intent_structure(intent_module):
    import garak.services.intentservice

    garak._config.load_config()
    garak.services.intentservice.load()

    assert intent_module in garak.services.intentservice.intent_typology, (
        "Module '%s' not described in intent service typology" % intent_module
    )

    m = importlib.import_module(f"garak.intents.{intent_module}")
    klassnames = [name for name, obj in inspect.getmembers(m) if inspect.isclass(obj)]
    for klassname in klassnames:
        klass = getattr(m, klassname)
        assert (
            klass.__bases__[0] == garak.intents.base.Intent
        ), "Intent classes must inherit garak.intents.base.Intent, %s doesn't" % (
            klass.__name__
        )
        assert hasattr(klass, "stubs"), (
            "stubs() method missing in Intent %s" % klass.__qualname__
        )
