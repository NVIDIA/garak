# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from garak.langproviders.local import LocalHFTranslator


def test_local_hf_translator_falls_back_to_passthru_when_model_unavailable(monkeypatch):
    def _raise_network_error(*args, **kwargs):
        raise OSError("Network is unreachable")

    monkeypatch.setattr(
        "transformers.MarianMTModel.from_pretrained",
        _raise_network_error,
    )

    translator = LocalHFTranslator(
        config_root={
            "langproviders": {
                "local": {
                    "language": "de,en",
                    "model_type": "local",
                    "model_name": "Helsinki-NLP/opus-mt-{}",
                }
            }
        }
    )

    assert translator._offline_passthru is True
    assert translator._translate("hallo welt") == "hallo welt"
