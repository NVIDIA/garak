garak.generators.base
=====================

In garak, ``Generator``s wrap any text-to-text+ system that garak will examine. This could be a raw LLM, a chatbot endpoint, or even a non-LLM dialog system. This base class defines the basic structure of garak's generators. All generators inherit from garak.generators.base.Generator.

Attributes:

* name - The name of the specific generator class. This is optionally also set in the constructor.
* description - An optional description of the generator.
* max_tokens - The maximum number of tokens to generate.
* temperature - Optionally, a temperature param to pass to the underlying model.
* top_k - Optionally, a temperature param to pass to the underlying model.
* top_p - Optionally, a temperature param to pass to the underlying model.
* active - Whether or not the class is active. Usually true, unless a generator is disabled for some particular reason.
* generator_family_name - Generators each belong to a family, describing a group. This is often related to the module name - for example, ``openai.py`` contains classes for working with OpenAI models, whose generator_family_name is "openai".
* context_len - The number of tokens in the model context window, or None
* modality - A dictionary with two keys, "in" and "out", each holding a set of the modalities supported by the generator. "in" refers to prompt expectations, and "out" refers to output. For example, a text-to-text+image model would have modality: ``dict = {"in": {"text"}, "out": {"text", "image"}}``.
* supports_multiple_generations - Whether or not the generator can natively return multiple outputs from a prompt in a single function call. When set to False, the ``generate()`` method will make repeated calls, one output at a time, until the requested number of generations (in ``generations``) is reached.
* skip_seq_start, skip_start_end - If both asserted, content between these two will be pruned before being returned. Useful for removing chain-of-thought, for example

Functions:

#. **__init___()**: Class constructor. Call this from generators after doing local init. It does things like populating name variables, notifying generator startup to the user, and logging generator construction.

#. **generate*()**: This method is mediating access to the underlying model or dialogue system. The ``generate()`` orchestrates all interaction with the dialogue service/model. It takes a prompt and, optionally, a number of output generations (``generations_this_call``). It returns a list of responses of length up to the number of output generations, with each member a prompt response (e.g. text). Since ``generate()`` involves a reasonable amount of logic, it is preferable to not override this function, and rather work with the hooks and sub-methods provided.

The general flow in ``generate()`` is as follows:

  #. Call the ``_pre_generate_hook()``.
  #. Work out how many generations we're doing this call (passed via ``generations_this_call``).
  #. If only one generation is requested, return the output of ``_call_model`` with 1 generation specified.
  #. If the underlying model supports multiple generations, return the output of ``_call_model`` invoked with the full count of generations.
  #. Otherwise, we need to assemble the outputs over multiple calls. There are two options here.
    #. Is garak running with ``parallel_attempts > 1`` configured? In that case, start a multiprocessing pool with as many workers as the value of ``parallel_attempts``, and have each one of these work on building the required number of generations, in any order.
    #. Otherwise, call ``_call_model()`` repeatedly to collect the requested number of generations.
  #. Call the ``_post_generate_hook()`` (a no-op by default)
  #. If skip sequence start and end are both defined, call ``_prune_skip_sequences()``
  #. Return the resulting list of prompt responses.


#. **_call_model()**: This method handles direct interaction with the model. It takes a prompt and an optional number of generations this call, and returns a list of prompt responses (e.g. strings) and ``None``s. Models may return ``None`` in the case the underlying system failed unrecoverably. This is the method to write model interaction code in. If the class' supports_multiple_generations is false, _call_model does not need to accept values of ``generations_this_call`` other than ``1``.

#. **_pre_generate_hook()**: An optional hook called before generation, useful if the class needs to do some setup or housekeeping before generation.

#. **_verify_model_result**: Validation of model output types, useful in debugging. If this fails, the generator doesn't match the expectations in the rest of garak.

#. **_post_generate_hook()**: An optional hook called after generation, useful if the class needs to do some modification of output.

#. **_prune_skip_sequences()**: Called if both ``skip_seq_start`` and ``skip_seq_end`` are defined. Strip out any response content between the start and end markers.



.. automodule:: garak.generators.base
   :members:
   :undoc-members:
   :show-inheritance:   

