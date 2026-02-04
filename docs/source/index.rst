Garak Reference Documentation
=============================

Garak is an LLM vulnerability scanner, `<https://garak.ai>`_.
It uses a huge range of probes to examine and query a large language model, simulating
attacks, and uses a range of detectors on the model's outputs to see if the model was
vulnerable to any of those attacks.

This is the code reference documentation, mostly useful for developers and people interested
in how garak works. There is a separate `User Guide <https://docs.garak.ai>`_ containing information
on running garak and interpreting results. If you want to use the tool and get results,
and you don't care about its internals, then you want the user guide. Take a look there! `<https://docs.garak.ai>`_

On the other hand, if you'd like a to get into the details or work out how
to contribute code, you're in the right place - welcome!

You can also join our `Discord <https://discord.gg/uVch4puUCs>`_
and follow us on `LinkedIn <https://www.linkedin.com/company/garakllm/>`_ & `X <https://www.twitter.com/garak_llm>`_!

Check out the :doc:`usage` section for further information, including :doc:`install`.

.. note::

   This project is under active development. We love writing and fixing docs, so
   let us know if there's anything wrong, confusing, or missing here --
   mail `docs@garak.ai <mailto:docs@garak.ai>`_ or drop us a note on `Discord <https://discord.gg/uVch4puUCs>`_.
   Thank you!


.. toctree::
   :caption: Using garak
   :maxdepth: 1
   :hidden:

   how
   install
   usage
   configurable
   cliref
   reporting
   translation
   ascii_smuggling
   faster
   FAQ <https://github.com/NVIDIA/garak/blob/main/FAQ.md>

.. toctree::
   :caption: Reference
   :maxdepth: 1
   :hidden:

   basic
   attempt
   buffs
   cli
   command
   detectors
   detector_metrics
   evaluators
   exception
   generators
   harnesses
   interactive
   langservice
   payloads
   probes
   report
   _config
   _plugins
   analyze


.. toctree::
   :caption: Extending and Contributing
   :maxdepth: 1
   :hidden:

   extending
   extending.generator
   extending.probe
   contributing
