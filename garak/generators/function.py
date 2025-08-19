"""function-based generator

Call a given function to use as a generator; specify this as either the
model name on the command line, or as the parameter to the constructor.

This generator is designed to be used programmatically, rather than
invoked from the CLI. An example usage might be:

.. code-block:: python

   import mymodule
   import garak.generators.function

   g = garak.generators.function.Single(name="mymodule#myfunction")

The target function is expected to take a string, and return a string.
Other arguments passed by garak are forwarded to the target function.

Note that one can import the intended target module into scope and then
invoke a garak run via garak's cli module, using something like:

.. code-block:: python

   import garak
   import garak.cli
   import mymodule

   garak.cli.main("--model_type function --model_name mymodule#function_name --probes encoding.InjectBase32".split())

"""

import importlib
from typing import List, Union

from garak import _config
from garak.attempt import Message, Conversation
from garak.generators.base import Generator


# should this class simply not allow yaml based config or would be valid to support kwargs as a key?
# ---
#   generators:
#     function:
#       Single:
#         name: my.private.module.class#custom_generator
#         kwargs:
#           special_param: param_value
#           special_other_param: other_value
#
# converting to call all like:
#
#  self.kwargs = { "special_param": param_value, "special_other_param": other_value }
#  custom_generator(prompt, **kwargs)
class Single(Generator):
    """Pass a function to call as a generator.
    The function must have the signature ``function(prompt:str, **kwargs)->List[Union(str, None)]``
    and is specified in the format ``module#function`` with the CLI or in the config file.
    The parameter ``name`` is reserved.
    """

    DEFAULT_PARAMS = {
        "kwargs": {},
    }
    doc_uri = "https://github.com/NVIDIA/garak/issues/137"
    generator_family_name = "function"
    supports_multiple_generations = False

    def __init__(
        self,
        name="",
        config_root=_config,
        **kwargs,
    ):
        if len(kwargs) > 0:
            self.kwargs = kwargs.copy()
        self.name = name  # if the user's function requires `name` it would have been extracted from kwargs and will not be passed later
        self._load_config(config_root)

        gen_module_name, gen_function_name = self.name.split("#")

        gen_module = importlib.import_module(
            gen_module_name
        )  # limits ability to test this for general instantiation
        self.generator = getattr(gen_module, gen_function_name)
        import inspect

        if "name" in inspect.signature(self.generator).parameters:
            raise ValueError(
                'Incompatible function signature: "name" is incompatible with this Generator'
            )

        super().__init__(self.name, config_root=config_root)

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        resp_list = self.generator(prompt.last_message().text, **self.kwargs)
        return [Message(resp) for resp in resp_list] if resp_list else [None]


class Multiple(Single):
    """Pass a function to call as a generator.
    The function must have the signature ``function(prompt:str, generations:int, **kwargs)->List[Union(str, None)]``
    and is specified in the format ``module#function`` with the CLI or in the config file.
    The parameter ``name`` is reserved.
    """

    supports_multiple_generations = True

    def _call_model(
        self, prompt: Conversation, generations_this_call: int = 1
    ) -> List[Union[Message, None]]:
        resp_list = self.generator(
            prompt.last_message().text, generations_this_call, **self.kwargs
        )
        return (
            [Message(resp) for resp in resp_list]
            if resp_list
            else [None] * generations_this_call
        )


DEFAULT_CLASS = "Single"
