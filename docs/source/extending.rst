Extending ``garak``
===================

``garak`` has a modular, extensible structure.
If there's a function you're missing in ``garak``, it is in many cases relatively simple to add that by adding a plugin.
Plugins in garak are typically single Python modules (i.e. a single Python file), added into the probes, detectors, generators, or buffs directories (packages).
``garak`` provides many tests which, while not complete, are extensive, and offer a good description of expectations new code should meet.
We hope that the messages within the tests are helpful to developers and guide you quickly to building good code that works well with the ``garak`` GenAI assessment kit.

Code structure
--------------

We have a page describing the :doc:`top-level concepts in garak <basic>`.
Rather than repeat that, take a look, so you have an idea about the code base!

Developing your own plugins
---------------------------

Plugins are generators, probes, detectors, buffs, harnesses, and evaluators. Each category of plugin gets its own directory in the source tree. The first four categories are where most of the new functionality is.

The recipe for writing a new plugin or plugin class isn't outlandish:

* Only start a new module if none of the current modules could fit
* Take a look at how other plugins do it
   * For an example Generator, check out :class:`garak.generators.replicate`
   * For an example Probe, check out :class:`garak.probes.malwaregen`
   * For an example Detector, check out :class:`garak.detectors.toxicity` or :class:`garak.detectors.specialwords`
   * For an example Buff, check out :class:`garak.buffs.lowercase`
* Start a new module inheriting from one of the base classes, e.g. :class:`garak.probes.base.Probe`
* Override as little as possible.


Guides to writing plugins
-------------------------

Here are our tutorials on plugin writing:

* :doc:`Building a garak generator <extending.generator>` -- step-by-step guide to building an interface for a real API-based model service
* :doc:`Building a garak probe <extending.probe>` -- A guide to writing your own custom probes

Testing during development
~~~~~~~~~~~~~~~~~~~~~~~~~~

You can test your code in a few ways:

* Start an interactive Python session
   * Instantiate the plugin, e.g. ``import garak._plugins`` then ``probe = garak._plugins.load_plugin("garak.probes.mymodule.MyProbe")``
   * Check out that the values and methods work as you'd expect
* Get ``garak`` to list all the plugins of the type you're writing, with ``--list_probes``, ``--list_detectors``, or ``--list_generators``: ```python3 -m garak --list_probes``
* Run a scan with test plugins
   * For probes, try a blank generator and always.Pass detector: ``python3 -m garak -m test.Blank -p mymodule -d always.Pass``
   * For detectors, try a blank generator and a blank probe: ``python3 -m garak -m test.Blank -p test.Blank -d mymodule``
   * For generators, try a blank probe and always.Pass detector: ``python3 -m garak -m mymodule -p test.Blank -d always.Pass``


garak supports pytest tests in garak/tests. You can run these with ``python -m pytest tests/`` from the root directory.
All the tests should pass for any code there's a pull request for, and all tests must pass in any PR before it can be merged.

Contributing
~~~~~~~~~~~~

Did you write something that makes ``garak`` better?
We love community contributions and are used to shepherding in useful work.
Take a look at our docs on :doc:`contributing <contributing>` your work to the project.
