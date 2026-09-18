Adding a configuration option
=============================

This page describes how to add a new core ``garak`` configuration value and expose it as a
command-line switch.

It covers changes to ``garak`` itself. If instead you want to make a *plugin* configurable,
you don't need any of this -- add the value to the plugin's ``DEFAULT_PARAMS`` and it becomes
settable from YAML and JSON automatically. See :doc:`configurable`.


Where configuration values live
-------------------------------

Core config is split into sections, each held as an object in ``garak._config``:

* ``system`` -- options that don't affect the security assessment
* ``run`` -- options that describe how a run is conducted
* ``plugins`` -- which plugins to use, and their configuration
* ``reporting`` -- how results are recorded and presented

There's also ``transient``, which holds values internal to a single execution, such as the run
ID and report filename. It isn't set by users and isn't covered here.

Each of the four user-facing sections has two things attached to it:

* **Defaults**, in ``garak/resources/garak.core.yaml``, under a top-level key of the same name.
* **A list of the option names the CLI may write into it**, in ``garak/_config.py``:
  ``system_params``, ``run_params``, ``plugins_params``, and ``reporting_params``.

Once argparse has parsed the command line, ``garak/cli.py`` walks the parsed arguments and
copies each one into whichever section's ``*_params`` list names it. **An argument that
appears in none of those lists is discarded**, and only mentioned at debug log level -- so an
option registered with argparse but not with a section parses without complaint and then
quietly has no effect. This is the easiest mistake to make here.

For the full precedence order between defaults, config files and the command line, see
:doc:`configurable`.


Adding an option to an existing section
---------------------------------------

Suppose we want ``--max_retries``, an integer, in the ``run`` section. That's three edits and
a test.

1. Add the default to core config
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In ``garak/resources/garak.core.yaml``, under the section the option belongs to:

.. code-block:: yaml

    run:
      seed:
      deprefix: true
      max_retries: 3

Every core option should have an entry here, even if the value is empty -- this file is the
canonical list of what garak understands.

2. Register the name with the section
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In ``garak/_config.py``, add the option name to the matching ``*_params`` string:

.. code-block:: python

    run_params = "seed deprefix eval_threshold generations interactive system_prompt spec max_retries".split()

This is the step that connects the switch to the config section. Without it the value never
reaches ``_config.run``.

3. Add the command-line switch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In ``garak/cli.py``, add an argument in the block for that section -- the argument definitions
are grouped by section, under ``## SYSTEM``, ``## RUN``, and so on. Take the default from the
config section rather than hard-coding it, so that core config, site config and run config all
still apply when the switch is absent:

.. code-block:: python

    parser.add_argument(
        "--max_retries",
        type=int,
        default=_config.run.max_retries,
        help="how many times to retry a failed generator request",
    )

Long option names are ``snake_case``. Add a short form only if the option is likely to be used
often; short forms are scarce.

4. Add a test
~~~~~~~~~~~~~

``tests/test_config.py`` works out which section an option belongs to from the ``*_params``
lists, so it can route your option as soon as step 2 is done -- but it only exercises options
that are listed explicitly. Add yours to:

* ``OPTIONS_PARAM``, as an ``(option, value)`` pair, if it takes a value; or
* ``OPTIONS_SOLO``, if it's an ``action="store_true"`` flag.

That covers it from both the command line and YAML, via ``test_cli_param_settings``,
``test_cli_solo_settings`` and ``test_yaml_param_settings``.

Checking it worked
~~~~~~~~~~~~~~~~~~

``--list_config`` dumps the resolved configuration without starting a run:

.. code-block:: console

    $ python -m garak --max_retries 5 --list_config

Your option should appear under the right section, with the value you passed. Run it again
without the switch, and you should see the default from ``garak.core.yaml``. If the value is
missing from both, step 2 is where to look.


Adding a new configuration section
----------------------------------

Adding a whole new section is rarer, and worth raising as an issue first. It needs four
changes, all following what the existing sections do:

* In ``garak/_config.py``, add an instance alongside ``system``, ``run``, ``plugins`` and
  ``reporting``. They're all instances of the same empty ``GarakSubConfig`` dataclass.
* In ``garak/_config.py``, add a matching ``<section>_params`` string.
* In ``_store_config()``, declare the new object ``global`` and populate it from the parsed
  settings with ``_set_settings()``, as the other sections are.
* In ``garak/cli.py``, add a branch to the loop that dispatches parsed arguments to sections.

The new section also needs a top-level key in ``garak/resources/garak.core.yaml``.


What you don't need to update
-----------------------------

``docs/source/cliref.rst`` is generated from ``python -m garak --help`` by the ``cliref``
target in ``docs/source/Makefile``, and is regenerated during release packaging. Don't edit it
by hand.
