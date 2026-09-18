Mapping a garak scan to the OWASP LLM Top 10
==============================================

This walkthrough shows how to run garak against a target model and interpret the
results in terms of the `OWASP Top 10 for Large Language Model Applications
<https://owasp.org/www-project-top-10-for-large-language-model-applications/>`_ —
the de-facto industry taxonomy of LLM security risks.

It is aimed at defenders: security engineers, red teams operating under written
authorization, and anyone hardening an LLM-powered product.

Why map to OWASP?
-----------------

garak organises its checks by *probe* and *detector*. The OWASP list organises
risk by *impact category*. Mapping one to the other lets you hand a non-technical
stakeholder a report that reads "we tested for LLM01 (Prompt Injection) and
LLM07 (System Prompt Leakage)" instead of "we ran probe X and detector Y".

The ten categories
------------------

==========  ============================================
OWASP ID    Risk
==========  ============================================
LLM01       Prompt Injection
LLM02       Sensitive Information Disclosure
LLM03       Supply Chain Vulnerabilities
LLM04       Data and Model Poisoning
LLM05       Improper Output Handling
LLM06       Excessive Agency
LLM07       System Prompt Leakage
LLM08       Vector and Embedding Weaknesses
LLM09       Misinformation
LLM10       Unbounded Consumption
==========  ============================================

Running a focused scan
-----------------------

The example below targets a local model served over a REST endpoint. Replace the
``rest*`` generator with whichever garak generator matches your target (see
:doc:`generators/index`).

.. code-block:: bash

   # Scan for prompt injection (LLM01) and system-prompt leakage (LLM07)
   python -m garak -m rest -n <your_endpoint> \
       --probes prompt_injection,leakage

Run ``python -m garak --list_probes`` to see every available probe, and
``python -m garak --list_detectors`` for the detectors that score the outputs.

Reading the results
-------------------

garak prints a per-probe pass/fail table and writes a full report. A *fail*
means the target model behaved in a way we do not want — i.e. it was vulnerable
to that probe.

================  ============================================================
Probe family      Maps to OWASP
================  ============================================================
prompt_injection  LLM01 Prompt Injection
leakage           LLM07 System Prompt Leakage
donotanswer       LLM01 / LLM02 (refusal robustness)
encoding          LLM01 (multilingual / encoding evasion)
xss               LLM05 Improper Output Handling
================  ============================================================

This table is not exhaustive; garak ships many more probes. The principle is the
same: each probe tests a behaviour, and that behaviour corresponds to one or more
OWASP categories. When you report findings, cite both the garak probe name and
the OWASP ID so the reader can look up remediation guidance on the OWASP site.

Responsible disclosure
---------------------

Only scan systems you are authorized to test. Garak is a research and defense
tool; findings should be reported to the affected party under a coordinated
disclosure window before any public release.
