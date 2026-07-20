How ``garak`` runs
==================

In a typical run, ``garak`` will read a model type (and optionally model name)
from the command line, then determine which ``probe`` and ``detector`` plugins to run,
start up a ``generator``, and then pass these to a ``harness`` to manage the probing;
an ``evaluator`` deals with the results. There are many modules in each of these
categories, and each module provides a number of classes that act as individual
plugins.

* `garak/probes/` - classes for generating interactions with LLMs
* `garak/detectors/` - classes for detecting an LLM is exhibiting a given failure mode
* `garak/evaluators/` - assessment reporting schemes
* `garak/generators/` - plugins for LLMs to be probed
* `garak/harnesses/` - classes for structuring testing
* `garak/buffs` - classes for augmenting / fuzzing attacks
* `data/` - ancillary data
* `resources/` - ancillary code

The default operating mode is to use the :class:`garak.harnesses.probewise` harness. Given a list of
probe module names and probe plugin names, the ``probewise`` harness instantiates
each probe, then for each probe reads its ``primary_detector`` and ``extended_detectors`` attributes to
get a list of ``detector`` s to run on the output.

Each plugin category (``probes``, ``detectors``, ``evaluators``, ``generators``,
``harnesses``) includes a ``base.py`` which defines the base classes usable by
plugins in that category. Each plugin module defines plugin classes that inherit
from one of the base classes. For example, :class:`garak.generators.openai.OpenAIGenerator`
descends from :class:`garak.generators.base.Generator`.

Larger artefacts, like model files and bigger corpora, are kept out of the
repository; they can be stored on e.g. Hugging Face Hub and loaded locally
by clients using ``garak``.
