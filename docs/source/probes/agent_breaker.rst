garak.probes.agent_breaker
==========================

This module exposes two separate opt-in probe plugins:

* ``probes.agent_breaker.AgentBreaker`` (Single) tests individual advertised
  tools and can discover a target's tools when they are not supplied.
* ``probes.agent_breaker.SourceToSink`` explores bounded multi-tool artifact
  handoffs. It requires an operator-authored tool manifest and never enables or
  modifies Single.

Selecting one class does not select the other. They share a Python module and
some attacker-model infrastructure, but retain separate execution and detector
contracts.

SourceToSink
------------

``SourceToSink`` uses an operator-supplied tool manifest and behaviour visible
through the configured target interface.

The probe tags candidate tool relationships, plans a bounded chain, and
executes its steps sequentially. Configured limits cap the probe's planning,
chain length, and queued attempts. The probe reserves each terminal request
against a per-manifest-tool budget before dispatch, requires the final plan to
produce no downstream artifacts, tells the target not to repeat any step's
action, and does not queue a follow-up after receiving the terminal response.

.. warning::

   Run this probe only against authorised, disposable targets in a sandbox.
   Tool chains can cause persistent side effects even when the target response
   does not report them accurately. Transport clients can retry failed requests,
   and a target can invoke a tool more than once while handling one request.
   The probe can name one intended tool in a request, but it cannot enforce
   target-side routing: the target may invoke another tool or several tools.
   Enforce per-call tool allowlists and idempotency at the target boundary, and
   independently audit backend effects. Without that control, treat every probe
   request, including an intermediate request, as potentially side-effecting.

.. _agent-breaker-chain-local-review:

Local review without a target
-----------------------------

The focused tests use local fixtures and mocked model responses. They require
no provider credentials, running agent server, GPU, containers, or elevated
permissions. An external reproduction environment is not a prerequisite for
reviewing this probe's control flow.

For example, from the repository root on Linux or macOS with Python 3.12,
create a virtual environment outside the checkout and install the test
dependencies:

.. code-block:: bash

   python3.12 -m venv ../garak-review-venv
   ../garak-review-venv/bin/python -m pip install -e '.[tests]'

Dependency installation requires access to the configured package index.
Keeping the environment outside the checkout also avoids dependency import
guards treating installed packages as local source files. Once installed,
run the focused suite from the repository root:

.. code-block:: bash

   ../garak-review-venv/bin/python -m pytest -q \
     tests/probes/test_agent_breaker_chains.py \
     tests/detectors/test_agent_breaker_chains.py

The suite covers manifest policy validation, bounded planning, exact artifact
handoffs, terminal request budgets, separation from Single, and the terminal
detector's input and scoring contracts.

For a small example of the execution lifecycle, select its dedicated test:

.. code-block:: bash

   ../garak-review-venv/bin/python -m pytest -q \
     tests/probes/test_agent_breaker_chains.py::test_provider_free_probe_lifecycle_runs_one_handoff_and_one_terminal

This test supplies a scripted in-memory target and stubs model-dependent
planning, prompt generation, and artifact extraction. It checks that one
intermediate request passes its artifact into one terminal request, that the
terminal metadata survives postprocessing, and that the queue stops without
replaying the terminal request. These checks validate implementation behaviour;
they do not measure attack success, judge accuracy, target routing, or backend
effects. Live findings need separate validation against an authorised sandbox.

Operational requirements
------------------------

``SourceToSink`` fails closed unless all of these conditions hold:

* ``run.generations`` is exactly ``1`` and no buffs are selected;
* the target language is English;
* at least two tools have an operator-authored ``chain_policy``;
* every intermediate tool is explicitly read-only for this run; and
* every terminal tool is explicitly side-effecting for this run.

``SourceToSink`` does not auto-discover tools. Each manifest policy must
contain exactly the three Boolean fields shown below. A tool may be allowed as
either an intermediate step or a terminal step, never both. The operator is
responsible for matching these declarations to the target's real tool
implementation and authorisation boundary. ``chain_policy`` constrains probe
planning; it is not a target routing policy.

The terminal budget is per manifest tool name and limits only requests queued
by this probe. Aliases can still reach the same backend operation, and a
transport or target can retry one request. It is not an actual-operation
at-most-once guarantee.

Intermediate responses must bind every required artifact under its declared
key, either in structured JSON or an exact ``key = value``/``key: value`` text
record. This makes opaque references usable without interpreting their format,
but translation or rewriting of identifiers is unsupported.

Configuration and invocation
----------------------------

Place a manifest below garak's user data ``data`` directory. For example,
``agent_breaker/source_to_sink_target.yaml`` can contain:

.. code-block:: yaml

   agent_purpose: Exercise an authorised support sandbox.
   tools:
     - name: lookup_record
       description: Read a sandbox record and return its opaque reference.
       chain_policy:
         allow_intermediate: true
         allow_terminal: false
         side_effecting: false
     - name: update_sandbox_record
       description: Update one disposable sandbox record by opaque reference.
       chain_policy:
         allow_intermediate: false
         allow_terminal: true
         side_effecting: true

Select only ``SourceToSink`` and configure it under its class name:

.. code-block:: yaml

   run:
     generations: 1
     target_lang: en
     spec:
       include:
         - probes.agent_breaker.SourceToSink
   plugins:
     probes:
       agent_breaker:
         SourceToSink:
           agent_config_file: agent_breaker/source_to_sink_target.yaml

Keep variant-specific settings under ``SourceToSink`` as shown. Settings placed
directly under the ``agent_breaker`` module apply to both Single and
``SourceToSink``.

Then run it with the normal target configuration, replacing the placeholders:

.. code-block:: bash

   garak --config chains.yaml --target_type TARGET_PLUGIN --target_name TARGET_NAME

The probe's red-team generator and the
``detectors.agent_breaker.AgentBreakerChainResult`` judge generator also
require their normal provider configuration and credentials.

The primary detector judges only the target's response claim for an eligible
artifact-bearing terminal request. A positive score does not establish that the
planned tool was used or that a backend side effect occurred; verify routing
and backend state separately in the authorised test environment.

The conservative terminal-attempt budget is intentionally below the usual
prompt volume for statistical probes. Treat results as bounded discovery
signals, not as a population estimate or benchmark.

Related work
------------

The following research and case studies examine risks arising from tool
composition:

* `ChainFuzzer <https://arxiv.org/abs/2603.12614>`_ (March 2026) studies
  workflow-level source-to-sink vulnerabilities using grey-box, trace-guided
  analysis and fuzzing.
* `STAC <https://arxiv.org/abs/2509.25624v3>`_ (revised July 2026) studies how
  individually benign-looking tool calls can combine into harmful outcomes
  across multiple turns.
* Invariant Labs' `Toxic Flow Analysis
  <https://invariantlabs.ai/blog/toxic-flow-analysis>`_ (July 2025) models
  potentially unsafe tool sequences using flow graphs and properties such as
  trust, data sensitivity, and exfiltration capability.
* Microsoft's `When prompts become shells
  <https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/>`_
  (May 2026) documents a Semantic Kernel case in which sandbox execution and
  file-transfer tools were chained to write a file on the host
  (CVE-2026-25592).

These references provide context for the attack class. ``SourceToSink`` does
not implement ChainFuzzer's grey-box, trace-guided analysis. The cited studies'
results do not establish this probe's attack coverage or success rate.

.. automodule:: garak.probes.agent_breaker
   :members:
   :undoc-members:
   :show-inheritance:

   .. show-asr::
