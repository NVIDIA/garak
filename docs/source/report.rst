garak.report
============

``garak``'s reports connect to things interested in consuming info on
LLM vulnerabilities and failures, such as the AI Vulnerability Database.

``garak`` provides a CLI option to further structure this file for downstream consumption.
The open data schema of AI vulnerability Database (`AVID <https://avidml.org>`_) is used for this purpose.

The syntax for this is as follows:

.. code-block:: console

   python3 -m garak -r <path_to_file>

Examples
^^^^^^^^

As an example, let's load up a ``garak`` report from scanning ``gpt-3.5-turbo-0613``.

.. code-block:: console

   wget https://gist.githubusercontent.com/shubhobm/9fa52d71c8bb36bfb888eee2ba3d18f2/raw/ef1808e6d3b26002d9b046e6c120d438adf49008/gpt35-0906.report.jsonl
   python3 -m garak -r gpt35-0906.report.jsonl


This produces the following output.

.. code-block:: console

   📜 Converting garak reports gpt35-0906.report.jsonl
   📜 AVID reports generated at gpt35-0906.avid.jsonl

.. toctree::
   :maxdepth: 2

   garak.report
