"""ggml generator support

This generator works with ggml models in gguf format like llama.cpp.

Put the path to your ggml executable (e.g. "/home/leon/llama.cpp/main") in
an environment variable named GGML_MAIN_PATH, and pass the path to the
model you want to run either using --model_name on the command line
or as the constructor parameter when instantiating LLaMaGgmlGenerator.

Compatibility or other problems? Please let us know!
 https://github.com/NVIDIA/garak/issues
"""

import logging
import os
import re
import subprocess
from typing import List, Union

from garak import _config
from garak.attempt import Message, Conversation
from garak.generators.base import Generator

GGUF_MAGIC = bytes([0x47, 0x47, 0x55, 0x46])
ENV_VAR = "GGML_MAIN_PATH"


class GgmlGenerator(Generator):
    """Generator interface for ggml models in gguf format.

    Set the path to the model as the model name, and put the path to the ggml executable in environment variable GGML_MAIN_PATH.
    """

    # example to inherit `DEFAULT_PARAMS` from the base.Generator class
    DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
        "repeat_penalty": 1.1,
        "presence_penalty": 0.0,
        "frequency_penalty": 0.0,
        "top_k": 40,
        "top_p": 0.95,
        "temperature": 0.8,
        "exception_on_failure": True,
        "first_call": True,
        "key_env_var": ENV_VAR,
        "extra_ggml_flags": ["-no-cnv"],
        "extra_ggml_params": dict(),
    }

    generator_family_name = "ggml"

    def _command_args_list(self):
        command_list = []
        params = {
            "-m": self.name,
            "-n": self.max_tokens,
            "--repeat-penalty": self.repeat_penalty,
            "--presence-penalty": self.presence_penalty,
            "--frequency-penalty": self.frequency_penalty,
            "--top-k": self.top_k,
            "--top-p": self.top_p,
            "--temp": self.temperature,
            "-s": self.seed,
        } | self.extra_ggml_params
        # test all params for None type
        for key, value in params.items():
            if value is not None:
                command_list.append(key)
                command_list.append(value)
        if isinstance(self.extra_ggml_flags, list):
            command_list.extend(self.extra_ggml_flags)
        return command_list

    def __init__(self, name="", config_root=_config):
        self.name = name
        self._load_config(config_root)

        if not hasattr(self, "path_to_ggml_main") or self.path_to_ggml_main is None:
            self.path_to_ggml_main = os.getenv(self.key_env_var)
        if self.path_to_ggml_main is None:
            raise RuntimeError(
                f"Executable not provided by environment {self.key_env_var}"
            )
        if not os.path.isfile(self.path_to_ggml_main):
            raise FileNotFoundError(
                f"Path provided is not a file: {self.path_to_ggml_main}"
            )

        # this value cannot be `None`, 0 is consistent and `-1` would produce random seeds
        if self.seed is None:
            self.seed = 0

        # model is a file, validate exists and sanity check file header for supported format
        if not os.path.isfile(self.name):
            raise FileNotFoundError(
                f"File not found, unable to load model: {self.name}"
            )
        else:
            with open(self.name, "rb") as model_file:
                magic_num = model_file.read(len(GGUF_MAGIC))
                if magic_num != GGUF_MAGIC:
                    raise RuntimeError(f"{self.name} is not in GGUF format")

        super().__init__(self.name, config_root=config_root)

    def _validate_env_var(self):
        pass  # suppress default behavior for api_key

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        # should this be expanded to process all Conversation messages?
        if generations_this_call != 1:
            logging.warning(
                "GgmlGenerator._call_model invokes with generations_this_call=%s but only 1 supported",
                generations_this_call,
            )
        command = [
            self.path_to_ggml_main,
            "-p",
            prompt.last_message().text,
        ]
        # test all params for None type
        command.extend(self._command_args_list())
        command = [str(param) for param in command]
        if _config.system.verbose > 1:
            print("GGML invoked with", command)
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=self.exception_on_failure,
            )
            output = result.stdout.decode("utf-8")
            output = re.sub("^" + re.escape(prompt.lstrip()), "", output.lstrip())
            self.first_call = False
            return [Message(output)]
        except subprocess.CalledProcessError as err:
            # if this is the first call attempt, raise the exception to indicate
            # the generator is mis-configured
            print(err.stderr.decode("utf-8"))
            logging.error(err.stderr.decode("utf-8"))
            if self.first_call:
                raise err
            return [None]
        except Exception as err:
            logging.error(err)
            return [None]


DEFAULT_CLASS = "GgmlGenerator"
