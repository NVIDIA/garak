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
