# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import inspect
import logging
import os

from typing import Callable


class HFCompatible:
    """Mixin class providing private utility methods for using Huggingface
    transformers within garak"""

    def _set_hf_context_len(self, config):
        if hasattr(config, "n_ctx"):
            if isinstance(config.n_ctx, int):
                self.context_len = config.n_ctx

    def _gather_hf_params(self, hf_constructor: Callable):
        """ "Identify arguments that impact huggingface transformers resources and behavior"""
        import torch

        # this may be a bit too naive as it will pass any parameter valid for the hf_constructor signature
        # this falls over when passed some `from_pretrained` methods as the callable model params are not always explicit
        params = (
            self.hf_args
            if hasattr(self, "hf_args") and isinstance(self.hf_args, dict)
            else {}
        )
        if params is not None and not "device" in params and hasattr(self, "device"):
            # consider setting self.device in all cases or if self.device is not found raise error `_select_hf_device` must be called
            params["device"] = self.device

        args = {}

        params_to_process = inspect.signature(hf_constructor).parameters

        if "model" in params_to_process:
            args["model"] = self.name
            # expand for
            params_to_process = {"do_sample": True} | params_to_process
        else:
            # callable is for a Pretrained class also map standard `pipeline` params
            from transformers import pipeline

            params_to_process = (
                {"low_cpu_mem_usage": True}
                | params_to_process
                | inspect.signature(pipeline).parameters
            )

        for k in params_to_process:
            if k == "model":
                continue  # special case `model` comes from `name` in the generator
            if k in params:
                val = params[k]
                if k == "torch_dtype" and hasattr(torch, val):
                    args[k] = getattr(
                        torch, val
                    )  # some model type specific classes do not yet support direct string representation
                    continue
                if (
                    k == "device"
                    and "device_map" in params_to_process
                    and "device_map" in params
                ):
                    # per transformers convention hold `device_map` before `device`
                    continue
                args[k] = params[k]

        if (
            not "device_map" in args
            and "device_map" in params_to_process
            and "device" in params_to_process
            and "device" in args
        ):
            del args["device"]
            args["device_map"] = self.device

        # trust_remote_code reset to default disabled unless unlocked in garak HF item config
        if (
            "trust_remote_code" in params_to_process
            and "trust_remote_code" not in params
        ):
            args["trust_remote_code"] = False

        return args

    def _gather_generation_params(self):
        from transformers import GenerationConfig

        generation_params = {}
        for generation_param in GenerationConfig._get_default_generation_params():
            if generation_param in self.hf_args.keys():
                generation_params[generation_param] = self.hf_args[generation_param]
        return generation_params

    def _select_hf_device(self):
        """Determine the most efficient device for tensor load, hold any existing `device` already selected"""
        import torch

        selected_device = None
        if self.hf_args.get("device", None) is not None:
            if isinstance(self.hf_args["device"], int):
                # this assumes that indexed only devices selections means `cuda`
                if self.hf_args["device"] < 0:
                    msg = f"device {self.hf_args['device']} requested but CUDA device numbering starts at zero. Use 'device: cpu' to request CPU."
                    logging.critical(msg)
                    raise ValueError(msg)
                selected_device = torch.device("cuda:" + str(self.hf_args["device"]))
            else:
                selected_device = torch.device(self.hf_args["device"])

        if selected_device is None:
            selected_device = torch.device(
                "cuda"
                if torch.cuda.is_available()
                else "mps" if torch.backends.mps.is_available() else "cpu"
            )

        if isinstance(selected_device, torch.device) and selected_device.type == "mps":
            os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"
            logging.debug("Enabled MPS fallback environment variable")

        logging.debug(
            "Using %s, based on torch environment evaluation", selected_device
        )
        return selected_device


def _hf_hub_status_code(exc: BaseException) -> int | None:
    """Extract an HTTP status code from an exception or its cause chain.

    `transformers` re-raises Hub fetch failures as plain `OSError`
    (`raise OSError(...) from e`), so the status lives on the chained
    `HfHubHTTPError.response.status_code`, not on the `OSError` itself.
    """
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        status = getattr(getattr(exc, "response", None), "status_code", None)
        if isinstance(status, int):
            return status
        status = getattr(exc, "status_code", None)
        if isinstance(status, int):
            return status
        exc = exc.__cause__ if exc.__cause__ is not None else exc.__context__
    return None


def hf_hub_backoff_giveup(exc: BaseException) -> bool:
    """`backoff` giveup predicate for Hugging Face Hub fetches.

    Returns False (keep retrying) for transient Hub conditions - HTTP 429
    and 5xx, connection drops, timeouts - and True (raise immediately) for
    anything else, e.g. unknown repos, bad revisions, gated repos, and auth
    failures. See https://github.com/NVIDIA/garak/issues/1479.
    """
    import re

    status = _hf_hub_status_code(exc)
    if status is not None:
        return not (status == 429 or 500 <= status <= 599)
    try:
        import requests

        _connection_errors = (requests.ConnectionError, requests.Timeout)
    except ImportError:  # pragma: no cover - requests is a hard dependency
        _connection_errors = ()
    if isinstance(exc, (ConnectionError, TimeoutError) + _connection_errors):
        return False
    # last resort: the wrapped message usually quotes the Hub status line,
    # e.g. "503 Server Error: Service Temporarily Unavailable for url: ..."
    if re.search(r"\b(429|5\d\d)\b", str(exc)):
        return False
    return True
