# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest


@pytest.fixture(scope="package", autouse=True)
def cleanup_model_cache(request):
    """Remove cached huggingface models after language tests"""

    import os

    def clear_hf_cached():
        from huggingface_hub import scan_cache_dir
        import shutil

        models = [
            "facebook/m2m100_418M".lower(),
            "Helsinki-NLP/opus-mt-en-jap".lower(),
            "Helsinki-NLP/opus-mt-jap-en".lower(),
            "Helsinki-NLP/opus-mt-en-ja".lower(),
            "Helsinki-NLP/opus-mt-ja-en".lower(),
            "Helsinki-NLP/opus-mt-fr-en".lower(),
            "Helsinki-NLP/opus-mt-en-fr".lower(),
        ]
        for repo in scan_cache_dir().repos:
            if repo.repo_id.lower() in models:
                if repo.repo_path.exists():
                    shutil.rmtree(repo.repo_path)

    if os.getenv("CI", None) is not None:  # github sets this to True
        request.addfinalizer(clear_hf_cached)


@pytest.fixture(autouse=True)
def clear_langprovider_state(request):
    """Reset langprovider for each test"""

    def clear_langprovider_state():
        import gc
        import importlib
        from garak import langservice, _config

        for _, v in langservice.langproviders.items():
            del v
        langservice.langproviders = {}
        # reset defaults for langprovider _config
        importlib.reload(_config)
        gc.collect()

    request.addfinalizer(clear_langprovider_state)


def enable_gpu_testing():
    # enable GPU testing in dev env
    # should this just be an env variable check to allows faster local testing?
    import torch

    device = (
        "cuda"
        if torch.cuda.is_available()
        else "mps" if torch.backends.mps.is_available() else "cpu"
    )

    if device == "mps":
        import psutil

        if psutil.virtual_memory().total < (16 * 1024**3):
            device = "cpu"  # fallback when less than 16GB of unified memory

    from garak.langproviders.local import LocalHFTranslator

    LocalHFTranslator.DEFAULT_PARAMS["hf_args"]["device"] = device


enable_gpu_testing()
