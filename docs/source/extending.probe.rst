Writing a Probe
###############

Probes are, in some ways, the essence of garak's functionality -- they serve as the abstraction that encapsulates attacks against AI models and systems.
In this example, we're going to go over the key points of how to develop a new probe.

Inheritance
***********

All probes will inherit from ``garak.probes.base.Probe``, exposed at package level via ``garak.probes``.

.. code-block:: python

    import garak.probes

    class MyNewProbe(garak.probes.Probe):
        """Probe to do something naughty to a language model"""
        ...

We require class docstrings in garak and enforce this requirement via a test required before merging.

Probes must always inherit from ``garak.probes.base.Probe``.
This allows probes to work nicely with ``Generator`` and ``Attempt`` objects in addition to ensuring that any ``Buff``\ s that one might want to apply to a probe are going to work appropriately.

The ``probe`` method of ``Probe`` objects is where the core logic of a probe lies.
Ideally, one would need only to populate the ``prompts`` attribute of a ``Probe`` and let the ``probe`` method do the heavy lifting.
However, if this logic is insufficient for a custom probe, this is where the majority of the work (and potential issues) tends to lie.

.. code-block:: python

    def probe(self, generator) -> Iterable[garak.attempt.Attempt]:
        """attempt to exploit the target generator, returning a list of results"""
        logging.debug("probe execute: %s", self)

        self.generator = generator

        # build list of attempts
        attempts_todo: Iterable[garak.attempt.Attempt] = []
        prompts = list(self.prompts)
        for seq, prompt in enumerate(prompts):
            attempts_todo.append(self._mint_attempt(prompt, seq))

        # buff hook
        if len(_config.buffmanager.buffs) > 0:
            attempts_todo = self._buff_hook(attempts_todo)

        # iterate through attempts
        attempts_completed = self._execute_all(attempts_todo)

        logging.debug(
            "probe return: %s with %s attempts", self, len(attempts_completed)
        )

        return attempts_completed

Configuring and Describing Probes
*********************************

Probes are built upon the ``Configurable`` base class and are themselves configurable.
We largely ignore parameters like ``ENV_VAR`` and ``DEFAULT_PARAMS`` in ``Probe`` classes, but if your probe requires an environment variable or you want to set some default parameters, it is done first in the class.

More often, we'll be looking at descriptive attributes of the probe.
From the base class:

.. code-block:: python

    # docs uri for a description of the probe (perhaps a paper)
    doc_uri: str = ""
    # language this is for, in BCP47 format; * for all langs
    lang: Union[str, None] = None
    # should this probe be included by default?
    active: bool = True
    # MISP-format taxonomy categories
    tags: Iterable[str] = []
    # what the probe is trying to do, phrased as an imperative
    goal: str = ""
    # Deprecated -- the detectors that should be run for this probe. always.Fail is chosen as default to send a signal if this isn't overridden.
    recommended_detector: Iterable[str] = ["always.Fail"]
    # default detector to run, if the primary/extended way of doing it is to be used (should be a string formatted like recommended_detector)
    primary_detector: Union[str, None] = None
    # optional extended detectors
    extended_detectors: Iterable[str] = []
    # can attempts from this probe be parallelised?
    parallelisable_attempts: bool = True
    # Keeps state of whether a buff is loaded that requires a call to untransform model outputs
    post_buff_hook: bool = False
    # support mainstream any-to-any large models
    # legal element for str list `modality['in']`: 'text', 'image', 'audio', 'video', '3d'
    # refer to Table 1 in https://arxiv.org/abs/2401.13601
    # we focus on LLM input for probe
    modality: dict = {"in": {"text"}}

That's a lot of attributes before we get into ones you may need to add!
Many of these are decent defaults, though there are a few that we absolutely want to include in any new probe

* ``doc_uri``: What is a good reference for the probe you're implementing? An academic paper, blog post, or social media post (in descending order of preference) goes here.
* ``active``: Should this probe be part of default scans?
* ``tags``: MISP-formatted taxonomy categories __e.g.__ ``["avid-effect:security:S0403", "owasp:llm01", "quality:Security:PromptStability", "payload:jailbreak"]``
* ``goal``: What is the probe trying to do? __e.g.__ ``"disregard the system prompt"``
* ``primary_detector``: What ``Detector`` should your probe use?

.. code-block:: python

    class MyNewProbe(garak.probes.Probe):
        """Probe to do something naughty to a language model"""

        primary_detector = "mitigation.MitigationBypass"
        tags = [
            "avid-effect:security:S0403",
            "owasp:llm01",
            "quality:Security:PromptStability",
            "payload:jailbreak",
        ]
        goal = "disregard the system prompt"
        doc_uri = "https://garak.ai"
        active = False
        ...


Testing
*******
Once the logic for our probe is written, you'll want to test it before opening a pull request.
Typically, a good place to start is by seeing if your probe can be imported!

.. code-block:: bash

    $ conda activate garak
    $ python
    $ python
    Python 3.11.5 (main, Sep 11 2023, 08:31:25) [Clang 14.0.6 ] on darwin
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import garak.probes.mynewprobe
    >>>

If you can run this with no error, you're ready to move on to the next phase of testing.
Otherwise, try to address the encountered errors.

Let's try running our new probe against a HuggingFace ``Pipeline`` using ``meta-llama/Llama-2-7b-chat-hf``, a notoriously tricky model to get to behave badly.

.. code-block:: bash

  $ garak -t huggingface -n meta-llama/Llama-2-7b-chat-hf -p mynewprobe.MyNewProbe

If it all runs well, you'll get a log and a hitlog file, which tell you how successful your new probe was!
If you encounter errors, go through and try to address them. You can look at the bottom of the `garak.log` file, whose path is printed in the output every time you call garak, to see what errors there are.

If you want to debug your probe interactively, try using something like ``p = garak._plugins.load_plugin("probes.mynewprobe.MyNewProbe")`` from a Python prompt to load the probe. The variable ``p`` will be assigned an instance of the probe (if instantiation was successful) and you can test a lot of the probe's intended functionality from here.


Finally, check a few properties:

* Does the new probe appear in ``python -m garak --list_probes``?
* Does the probe run? ``python -m garak -t test -p mynewprobe.MyNewProbe``
* Do the garak tests pass? ``python -m pytest tests/``

Done!
*****

Congratulations on writing a probe for garak!

If you've tested your probe and validated that it works, run ``black`` to format your code in accordance with garak code standards.
Once your code is properly tested and formatted, push your work to your github fork and open a pull request -- thanks for your contribution!
