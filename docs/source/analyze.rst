Run analysis
============

Processing run results is a core part of getting actionable information out of a ``garak`` run.
We provide a range of scripts and constructs under ``garak.analyze`` that assist in this.

Note that these tools expect the report JSONL format from the same version of garak.
For example, scripts in garak.analyze under v0.14.0 expect to receive data generated under garak 0.14.0.
There may be some graceful failure or backwards compatibility but this is not guaranteed, especially while garak is pre-v1.0.
Patch releases are not expected to impact input/output formats -- however, minor or major version bumps may come with updates that are not backwards compatible with older report files.

garak.analyze.aggregate_reports
-------------------------------

Aggregate multiple garak reports on the same generator. 
Useful for e.g. assembling a report that's been run one probe at a time.

Invoke and see usage via command line with ``python -m garak.analyze.aggregate_reports``


garak.analyze.analyze_log
-------------------------

Analyze a garak ``report.jsonl`` log file.
Print out summary stats, and which prompts led to failures.

Invoke and see usage via command line with ``python -m garak.analyze.analyze_log``

garak.analyze.calibration
-------------------------

Module for code around calibrating garak (i.e. calculating bases for relative/Z-scores)

.. automodule:: garak.analyze.calibration
   :members:
   :undoc-members:
   :show-inheritance:


garak.analyze.count_tokens
--------------------------

Count the number of characters sent and received based on prompts, outputs, and generations

Invoke and see usage via command line with ``python -m garak.analyze.count_tokens``


garak.analyze.get_tree
----------------------

If a TreeSearchProbe probe was used (:doc:`garak.probes.base`), display the tree of items explored during the run.

Invoke and see usage via command line with ``python -m garak.analyze.get_tree``



garak.analyze.misp
------------------

Reporting on category-level information; categories denoted internally in MISP format.

Invoke and see usage via command line with ``python -m garak.analyze.misp``




garak.analyze.perf_stats
------------------------

Calculate a ``garak`` calibration from a set of ``report.jsonl`` outputs.
For more details, see :doc:`reporting.calibration`

Invoke and see usage via command line with ``python -m garak.analyze.perf_stats``




garak.analyze.qual_review
-------------------------

Generate a qualitative review of a garak report, and highlight heavily failing probes in Markdown report.
Gives ten positive and ten negative examples from failing probes
Takes a ``report.jsonl``, and an optional ``bag.json`` (e.g. ``data/calibration/calibration.json`` by default) as input


Invoke and see usage via command line with ``python -m garak.analyze.qual_review``


garak.analyze.report_avid
-------------------------

Prints an AVID (`<https://avidml.org/>`_) report given a garak report in jsonl.

Invoke and see usage via command line with ``python -m garak.analyze.report_avid``


garak.analyze.report_digest
---------------------------


Invoke and see usage via command line with ``python -m garak.analyze.report_digest``

.. automodule:: garak.analyze.report_digest
   :members:
   :undoc-members:
   :show-inheritance:


garak.analyze.tbsa
------------------

Generate a single numeric score for a run using :doc:`tier-based score aggregation <analyze.tbsa>`.
Note that this score is lossy and difficult to make comparable -- it will change with different configs and across different garak versions.

Invoke and see usage via command line with ``python -m garak.analyze.tbsa``

Read full details: :doc:`analyze.tbsa`