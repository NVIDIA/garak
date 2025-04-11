Let's build a generator!
########################

Let's build a garak generator. In garak, generators provide abstraction between the main code base and a dialogue system. That system is often an LLM, but can be anything that accepts and returns text (or text plus some other modality).

In this example, we're going to build a module for interfacing with the LLMs hosted by `Replicate <https://replicate.com/>`_, using the Replicate API (`docs <https://replicate.com/docs/get-started/python>`_). We'll assume that we're working in a file called ``replicate.py``.

Inheritance
***********

All generators in garak must descend from ``garak.generators.base.Generator``. So, new generators start out like:

.. code-block:: python

    from garak.generators.base import Generator

    class ReplicateGenerator(Generator):
        """
        Interface for public endpoints of models hosted in Replicate (replicate.com).
        """
        pass

Class docstrings are mandatory in garak, enforced by a test that's required to pass before merging. And they're just sensible practice anyway. So we add a brief docstring here too.

It's important that generators always inheirt from ``garak.generators.base.Generator``. Not only does this often save a lot of work - using the logic in base's ``generate()`` is helpful - plugin listing also checks the parents of each class in each plugin when choosing to show a plugin as available. If there's a class in a module in ``garak/generators/`` that doesn't inherit from Generator, then it won't be listed as available.


Setting the default generator
*****************************

Before we go ahead and code up the generator, we need to tell garak which generator to use by default in this class. This helps save users from always having to specify a model name. We do this in a default class module variable:

.. code-block:: python

    DEFAULT_CLASS = "ReplicateGenerator"

When this generator module is selected using ``--model_type replicate``, with ``replicate`` being the name of the Python module we're working in, the generator loader (in ``garak/generators/__init__.py``) will search for the ``DEFAULT_CLASS`` constant and use its value to determine which class to instantiate.

Configuration
*************

Like many garak plugins, generators are configurable. This is achieved by the base class inheriting from ``Configurable``. So, the first code we see in a generator class looks like this:

.. code-block:: python

        ENV_VAR = "REPLICATE_API_TOKEN"
        DEFAULT_PARAMS = Generator.DEFAULT_PARAMS | {
            "temperature": 1.0,
            "top_p": 1.0,
            "repetition_penalty": 1.0,
        }

Here, we set reserved name ``ENV_VAR`` to the name of the environment variable to look in for an API key. This API key can also be specified by configuration, instead of environment variable, so this step is optional. If you're coding a generator that doesn't need an API key, you can skip this.

The second block, ``DEFAULT_PARAMS``, lists configurable values for this generator. These are values that aren't static and that makes for users to be able to adjust. It is defined by merging with the base generator's configurable parameters. The contents are a dictionary, where keys are parameter names and the values are default values. The parameter names will become variables within this generator object at instantiation -- and they're also the names of configuration variables that garak will look for in its YAML configs.

In this case, we set a few default inference parameters that reflect how the model is invoked; we'll set ``temperature``, ``top_p``, and ``repetition_penalty``. Setting these variables in the class also indicates that this generator class supports those values, and they might be worth adjusting

Descriptive params
******************

The next things we need to define in this new class are the core generator parameters, that describe a bit about how this generator behaves and what default values it should have. 

In the class, we'll set the ``generator_family_name`` to ``Replicate``. This can be the same for every generator in a module, or can vary a bit, but it should be a descriptive name that reflects what this class is for - the generator family name is printed to garak users at run time. Finally, because Replicate endpoints aren't guaranteed to support a single request for multiple generations at a time, we set ``supports_multiple_generations`` false. This is also the default value, so technically we don't have to do it, but it's OK to be explicit here.

We end up with this:

.. code-block:: python

    Class ReplicateGenerator(Generator):
        """
        Interface for public endpoints of models hosted in Replicate (replicate.com).
        Expects API key in REPLICATE_API_TOKEN environment variable.
        """

        generator_family_name = "Replicate"
        supports_multiple_generations = False


Constructor
***********

Garak supports both a model type and a model name. Model type refers to the name of the class that will be used. Model name is an optional parameter that provides further detail. In the case of Replicate, they offer a selection of models which can be requested, each referred to by a name, such as ``meta/llama-2-70b-chat``. We'll use the model name to track this information. It's collected on the command line as the parameter to ``--model_name``, and passed to a generator constructor in the sole mandatory positional argument, ``name``.

Sometimes, we can leave the generator constructor alone and just inherit from ``base.Generator``. In the case of replicate, though, we want to check that there's a Replicate API key in place, and fail early if it's missing. Replicate calls require a user to add an API key, and garak won't be able to do a run without that key - so the polite thing to do is fail as early as we can. Generator load seems like a fine place to do that. The parent class' constructor already manages tracking this value and storing it in ``self.name``.

Thinking more about user experience - when is a good time to quit because of a missing key? If we quit quietly before the module loads, it might be unclear to the user why. So, we first print a progress message about trying to load ``ReplicateGenerator``, and then afterwards check the key. This message printing is handled by the parent class.

So, in the constructor, we first call the parent constructor using ``super().__init__()``, and then do a check for the API key. If the key is missing, we should print a clear message to the user, showing them what the key might look like, and where it should go. And we draw attention to that helpful message with a clear emoji.


.. code-block:: python

    import os


.. code-block:: python

        def __init__(self, name, config_root=_config):
            super().__init__(name, config_root=config_root)

            if self.api_key is not None:
                # ensure the token is in the expected runtime env var
                os.environ[self.ENV_VAR] = self.api_key
            self.replicate = importlib.import_module("replicate")

The configuration machinery will handle populating ``self.api_key``. Here, the code overrides the local environment variable in case we obtained ``api_key`` from somewhere else (e.g. a YAML config). We'll also import a copy of the ``replicate`` module in this instance, for local access. This is done because a garak run can involve multiple generator instances.

If a generator needs more complex environment variable loading and detection, or needs a different key populated from the ``ENV_VAR``, it should implement ``_validate_env_var()``. Examples of this can be found in the codebase.

Populating a different value than api_key:

.. code-block:: python

        def _validate_env_var(self): 
            if self.uri is None and hasattr(self, "key_env_var"): 
                self.uri = os.getenv(self.key_env_var) 
            if not self._validate_uri(self.uri): 
                raise ValueError("Invalid API endpoint URI") 

(from garak/generators/langchain_serve.py)


Populating from additional environment vars -- notice the call to super()._validate_env_var() at the end is important to still set self.api_key:

.. code-block:: python

        def _validate_env_var(self): 
            if self.org_id is None: 
                if not hasattr(self, "org_env_var"): 
                    self.org_env_var = self.ORG_ENV_VAR 
                self.org_id = os.getenv(self.org_env_var, None) 

            if self.org_id is None: 
                raise APIKeyMissingError( 
                    f'Put your org ID in the {self.org_env_var} environment variable (this was empty)\n \ 
                    e.g.: export {self.org_env_var}="xxxx8yyyy/org-name"\n \ 
                    Check "view code" on https://llm.ngc.nvidia.com/playground to see the ID' 
                ) 

            return super()._validate_env_var() 

(garak/generators/nemo.py)


Finally, if the key check passed, let's try to load up the Replicate API using the ``replicate`` module and the user-supplied key. We don't want to do speculative loading in garak - everything should be imported as late as reasonable, to keep user experience fast.

How one handles this can vary. It's done this way here because replicate holds a ``Client()`` object, and the import there may not support if more than one ``ReplicateGenerator`` needed to exist at the same time using different API keys. This is a quirk of the replicate library's design. 

So in this case, we import the ``replicate`` API module after the initial validation. Finally, to give the module some persistence, it's loaded at the level of our generator module, instead of just in this method. We add this to the end of ``__init__()``:

.. code-block:: python

            self.replicate = importlib.import_module("replicate")

Finally, don't forget to import ``importlib`` at the top!

.. code-block:: python

    import importlib


Calling the model
*****************

The core part of getting a result out of LLMs represented using the Replicate API is to submit a text prompt, and capture a single response to that. Within garak, functionality is handled by ``Generator``'s private ``_call_model()`` method - and so that's what we will overload in the ``ReplicateGenerator`` class.

The call is to the ``replicate`` module's ``run()`` method, which takes first the name of the particular hosted model requested - which we're tracking in ``self.name`` - and a dictionary parameter named ``input``. Relevant params are ``prompt`` for the input text; ``max_length`` for the upper limit on output generation size; ``temperature``, ``top_k`` and ``repetition_penalty`` to shape output text; and ``seed`` for random seed. We can access the instance of the ``replicate`` API module we created in the ``ReplicateGenerator`` constructor.

Let's start the ``_call_model`` method like this:

.. code-block:: python

        def _call_model(self, prompt: str, generations_this_call: int = 1):
            response_iterator = self.replicate.run(
                self.name,
                input={
                    "prompt": prompt,
                    "max_length": self.max_tokens,
                    "temperature": self.temperature,
                    "top_p": self.top_p,
                    "repetition_penalty": self.repetition_penalty,
                    "seed": self.seed,
                },
            )


Replicate allows streaming responses, and so results are returned piecemeal, token by token, using an iterator. This means that we need to stitch the response back together again. Finally, ``_call_model()`` has to return a list, so we wrap this result in a list.

.. code-block:: python

            return ["".join(response_iterator)]


Exception handling
******************

Many things can go wrong when trying to get inference out of LLMs. Things that can go wrong with web-hosted services, such as Replicate, include running out of funds, or the model going down, or hitting a rate limit. These are sometimes presented to the coder in the form of exceptions.

Backoff
=======

We need to work out a strategy of what to do when these exceptions are raised. Fortunately, the Replicate API module is fairly well-coded, and handles a lot of the recoverable failure cases itself. However, transient exceptions shouldn't stop a garak run - runs can take days, and aborting a run with an uncaught exception after dozens of hours is probably less desirable. So we should handle them

The ``backoff`` module offers a decorator that controls behaviour in response to specified exceptions being raised. We can use this to implement Fibonacci backoff on ``_call_model()`` if a Replicate exception is raised. The decorator looks like this, and goes right above our method:

.. code-block:: python

        @backoff.on_exception(
            backoff.fibo, replicate.exceptions.ReplicateError, max_value=70
        )
        def _call_model(self, prompt: str, generations_this_call: int = 1):

The ``max_value`` param means to never wait more than 70 seconds. API modules like Replicate's often use the ``logging`` module to give more detailed info, which is stored in ``garak.log``, if one wants to troubleshoot.

One housekeeping point: because we lazy-import ``replicate``, the requested backoff exception ``replicate.exceptions.ReplicateError`` doesn't exist at compile time, and looks like a syntax error to Python. So, we need to add one top-level import to the module:


.. code-block:: python

    import replicate.exceptions

Generator failure
=================

If the request really can't be served - maybe the prompt is longer than the context window and there's no specific handling in this case - then ``_call_model`` can return a ``None``. In the case of models that support multiple generations, ``_call_model`` should return a list of outputs and, optionally, ``None``s, with one list entry per requested generation.

Testing
=======

Now that the pieces for our generator are in place - a subclass of ``garak.generators.base.Generator``, with some customisation in the constructor, and an overridden ``_call_model()`` method, plus a ``DEFAULT_CLASS`` given at module level - we can start to test.

A good first step is to fire up the Python interpreter and try to import the module. Garak supports a specific range of tested Python versions (listed in `pyproject.toml <https://github.com/NVIDIA/garak/blob/main/pyproject.toml>`_, under the ``classifiers`` descriptor), so remember to use the right Python version for testing.

.. code-block:: bash

    $ conda activate garak
    $ python
    $ python
    Python 3.11.9 (main, Apr 19 2024, 16:48:06) [GCC 11.2.0] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import garak.generators.replicate
    >>> 

If all goes well, no errors will appear. If some turn up, try and address those.

The next step is to instantiate the class. Let's try with that ``meta/llama-2-70b-chat`` model.

.. code-block:: bash

    >>> g = garak.generators.replicate.ReplicateGenerator("meta/llama-2-70b-chat")
    Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
    File "/home/lderczynski/dev/garak/garak/generators/replicate.py", line 44, in __init__
        super().__init__(name, generations=generations, config_root=config_root)
    File "/home/lderczynski/dev/garak/garak/generators/base.py", line 43, in __init__
        self._load_config(config_root)
    File "/home/lderczynski/dev/garak/garak/configurable.py", line 60, in _load_config
        self._validate_env_var()
    File "/home/lderczynski/dev/garak/garak/configurable.py", line 116, in _validate_env_var
        raise APIKeyMissingError(
    garak.exception.APIKeyMissingError: 🛑 Put the Replicate API key in the REPLICATE_API_TOKEN environment variable (this was empty)
                            e.g.: export REPLICATE_API_TOKEN="XXXXXXX"

Oh, that's right! No API key. This stack trace is an example of how the ``Configurable`` interface (superclass in Python) handles the ``ENV_VAR`` load for the generator without the developer having to do it manually. Looks like the validation exception is working as intended. Let's set up that value (maybe quit the interpreter, add it using the helpful suggestion in the exception method, and load up Python again).

.. code-block:: bash

    $ export REPLICATE_API_TOKEN="r8-not-a-real-token"
    $ python
    Python 3.11.9 (main, Apr 19 2024, 16:48:06) [GCC 11.2.0] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import garak.generators.replicate
    >>> g = garak.generators.replicate.ReplicateGenerator("meta/llama-2-70b-chat")
    🦜 loading generator: Replicate: meta/llama-2-70b-chat
    >>> 

Excellent! Now let's try a test generation (remember to do the export of the API token using a real token):

.. code-block:: bash

    $ python
    Python 3.11.9 (main, Apr 19 2024, 16:48:06) [GCC 11.2.0] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import garak.generators.replicate
    >>> g = garak.generators.replicate.ReplicateGenerator("meta/llama-2-70b-chat")
    🦜 loading generator: Replicate: meta/llama-2-70b-chat
    >>> g.generate("test prompt", generations_this_call=1)
    [" Sure, I'm happy to help! Can you please provide an actual prompt or question you'd like me to assist with? I'll do my best to provide a helpful and informative response while adhering to the guidelines you've outlined."]
    >>>

Well, this looks promising.

The next step is to try some integration tests - executing garak from the command line, accessing this generator. There are some pointers in :doc:`contributing`. You might need to execute garak by specifying it as a Python module, running the command from the garak root code directory. Things to test are:

* Does the new generator appear in ``python -m garak --list_generators``?
* Does the generator work with a test probe, via ``python -m garak -m replicate -n meta/llama-2-70b-chat -p test.Blank``?
* Do the garak tests pass? ``python -m pytest tests/``

Add some of your own tests if there are edge-case behaviours, general validation, or other things in ``__init__()``, ``_call_model()``, and other new methods that can be checked. Plugin-specific tests should go into a new file, ``tests/generators/test_[modulename].py``.

If you want to see the full, live code for the Replicate garak generator, it's here: `garak/generators/replicate.py <https://github.com/NVIDIA/garak/blob/main/garak/generators/replicate.py>`_ .

Done!
=====

Congratulations - you've written a garak plugin!

If it's all tested and working, then it's time to send the code. You should first run ``black`` to format your code in the standard that the garak repository expects (Python 3.10 style, 88 columns). Then, push your work to your github fork, and finally, send us a pull request - and we'll take it from there!


Advanced: Modalities
====================

This tutorial covered a tool that takes text as input and produces text as output. Garak supports multimodality - the kinds of format that a generator supports are covered in a modality dictionary, with two keys, in and out. The default is:

.. code-block::

    modality: dict = {"in": {"text"}, "out": {"text"}}

For an example of a multimodal model, check out LLaVa in `garak.generators.huggingface <https://github.com/NVIDIA/garak/blob/main/garak/generators/huggingface.py>`_ . 