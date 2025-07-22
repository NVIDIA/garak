Reporting
=========

By default, ``garak`` outputs:

* a JSONL file, with the name ``garak.<uuid>.report.jsonl``, that stores progress and outcomes from a scan
* an HTML report summarising scores
* a JSONL hit log, describing all the attempts from the run that were scored successful

Report JSONL
------------

The report JSON consists of JSON rows. Each row has an ``entry_type`` field.
Different entry types have different other fields.
Attempt-type entries have uuid and status fields.
Status can be 0 (not sent to target), 1 (with target response but not evaluated), or 2 (with response and evaluation).
Eval-type entries are added after each probe/detector pair completes, and list the results used to compute the score.

Report HTML
-----------

The report HTML presents core items from the run.
Runs are broken down into:

1. modules/taxonomy entries
2. probes within those categories
3. detectors for each probe

Results given are both absolute and relative.
The relative ones are in terms of a Z-score computed against a set of recently tested other models and systems.
For Z-scores, 0 is average, negative is worse, positive is better.
Both absolute and relative scores are placed into one of five grades, ranging from 1 (worst) to 5 (best).
This scale follows the NORAD DEFCON categorisation (with less dire consequences).
Bounds for these categories are developed over many runs.
The absolute scores are only alarmist or reassuring for very poor or very good Z-scores.
The relative scores assume the middle 10% is average, the bottom 15% is terrible, and the top 15% is great.

DEFCON scores are aggregated using a minimum, to avoid obscuring important failures.
