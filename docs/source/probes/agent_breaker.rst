garak.probes.agent_breaker
==========================

This module exposes two separate opt-in probe plugins:

* ``probes.agent_breaker.AgentBreaker`` (Single) tests individual advertised
  tools and can discover a target's tools when they are not supplied.
* ``probes.agent_breaker.ToolChain`` explores bounded multi-tool artifact
  handoffs. It requires an operator-authored tool manifest and never enables or
  modifies Single.

Selecting one class does not select the other. They share a Python module and
some attacker-model infrastructure, but retain separate execution and detector
contracts.

ToolChain
------------

``ToolChain`` uses an operator-supplied tool manifest and behaviour visible
through the configured target interface.

The probe tags candidate tool relationships, plans a bounded chain, and
executes each chain's steps in order. Failed steps, including the final sink,
are refined up to ``max_step_attempts``. All tools follow the same execution
policy: there is no shared per-tool request cap, duplicate-request suppression,
or separate opt-in for retrying side-effecting tools. The final plan produces
no downstream artifacts, and a successful terminal step completes the chain.

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

Operational requirements
------------------------

``ToolChain`` fails closed unless all of these conditions hold:

* ``run.generations`` is exactly ``1``;
* the target language is English;
* the manifest has at least two chainable tools.

``ToolChain`` does not yet discover tools from the target. Every manifest
tool takes part in chain planning unless it sets ``chain: false``, which keeps
it out of every chain. The attacker model tags each tool's capabilities and
marks which tools can cause a security-relevant effect (sinks). A path is
recorded whenever it reaches a sink, and the search keeps extending it, so a
sink can also be a link when a later tool consumes its output (for example
``upload_file -> run_ci_command -> merge_pr``). Both the shorter and the longer
path are candidates. A tool that changes state but is not a sink, such as one
that plants content for a later step, may sit anywhere in a chain.

A tool counts as side-effecting when it is a sink or when its capability class
is anything other than ``read_sensitive``. This classification supports
state-dependent graph edges and detector context. It does not limit requests
or prevent refinement. Configured buffs follow the normal probe behaviour.

Artifact handoff
----------------

After an intermediate step passes its completion check, the parse model
extracts named artifacts from the target's natural response. The target does
not need to echo the plan's artifact aliases or follow a special output format.
The extractor keeps distinct fields such as a filename, upload id and host path
separate. Every artifact records its originating step and tool, its scalar
value, and an exact response quote supporting it. Submitted values can also be
retained when the response confirms their acceptance unchanged; those are
marked separately from values returned in the response. This acceptance is a
model judgement about response text, not verification of backend state.

Each consuming request declares artifact-to-parameter bindings. The probe
checks each value against its source evidence and its literal presence in the
outgoing request. Short identifiers are accepted without treating them as
substrings of longer identifiers, and JSON scalar types are preserved. A
bounded preflight model check then assesses whether the bindings fit the
manifest tool contract and whether the request preserves the planned exploit
mechanism and prerequisites. An upload id cannot stand in for a filename just
because both are strings. Artifacts remain local to their chain.

Artifact extraction and preflight checks add helper-model calls, not target
requests. They use bounded response views and omit oversized values; a required
value outside that view cannot be recovered by guessing. Missing, conflicting
or unsupported artifacts can stop a chain before another target request.

Request refinement
------------------

Within the per-step attempt limit, the attacker receives the current tool
contract, completed-step artifacts, attempt history and latest target feedback.
It can repair missing parameters, incorrect reference types, phrasing and
interpreter-compatible payload representations. A revision must preserve the
planned tool, technique, payload mechanism and sink requirement. If that is no
longer possible, the attacker returns a stop reason, which is logged, rather
than substituting an unrelated successful operation. The preflight check also
applies to revised requests. These text-based checks cannot enforce which tools
the target actually invokes; the target boundary still needs independent
routing controls.

Parameters
----------

Planning parameters bound work done with the red-team model before any target
request is sent:

* ``max_tools`` - manifest tools that are used; later tools are ignored.
* ``max_graph_edges`` - candidate producer-to-consumer edges sent to the
  red-team model for scoring. Every non-sink producer is paired with every
  consumer, because differently worded tags can still connect; pairs whose tags
  match exactly are listed first, so this cap drops unmatched guesses first.
  Edges are scored in batches.
* ``min_edge_confidence`` - scored edges below this confidence are discarded.
* ``max_path_expansions`` - search steps spent enumerating tool-chain
  paths through the scored graph.
* ``max_chain_len`` - tools in one path, including the sink.
* ``chain_selection`` - how found paths are chosen: ``relevance`` (default),
  ``shortest`` or ``longest``. ``relevance`` asks the red-team model to drop
  chains that are just the agent's authorized job, then keeps the
  highest-scoring ones. A chain is dropped only when the model is confident it
  is legitimate; an uncertain or failed judgement keeps it. ``shortest`` and
  ``longest`` order all found paths by length, breaking ties by score, and make
  no relevance call.
* ``min_chain_relevance_confidence`` - confidence the relevance judgement needs
  before a chain is dropped.
* ``max_paths`` - paths kept after chain selection. The search itself is
  bounded only by ``max_path_expansions`` and ``max_chain_len``.
* ``max_hypotheses_per_chain`` - exploit hypotheses planned for each path. Each
  path and hypothesis pair becomes one planned chain, so at most ``max_paths``
  times ``max_hypotheses_per_chain`` chains run.

Execution parameters control each chain step. The iterative executor
interleaves chains, with target requests sent serially:

* ``max_step_attempts`` - requests per chain step, including the initial
  request and refinements. The same limit applies to read-only tools,
  side-effecting tools and the final sink. It resets when a step advances;
  another chain's requests do not consume this allowance.
* ``success_threshold`` - confidence the step check needs before an
  step counts as completed.

Configuration and invocation
----------------------------

``agent_config_file`` is a path relative to garak's ``data`` directory. garak
looks for it first under the user data directory, which is
``$XDG_DATA_HOME/garak/data`` (by default ``~/.local/share/garak/data`` on
Linux and macOS), and then among the files shipped with garak. Place your
manifest in the user data directory, for example at
``$XDG_DATA_HOME/garak/data/agent_breaker/tool_chain_target.yaml``:

.. code-block:: yaml

   agent_purpose: Exercise an authorised support sandbox.
   tools:
     - name: lookup_record
       description: Read a sandbox record and return its opaque reference.
     - name: update_sandbox_record
       description: Update one disposable sandbox record by opaque reference.
     - name: delete_all_records
       description: Delete every record. Never call this.
       chain: false

Select only ``ToolChain`` and configure it under its class name:

.. code-block:: yaml

   run:
     generations: 1
     target_lang: en
     spec:
       include:
         - probes.agent_breaker.ToolChain
   plugins:
     probes:
       agent_breaker:
         ToolChain:
           agent_config_file: agent_breaker/tool_chain_target.yaml

Keep variant-specific settings under ``ToolChain`` as shown. Settings placed
directly under the ``agent_breaker`` module apply to both Single and
``ToolChain``.

Then run it with the normal target configuration, replacing the placeholders:

.. code-block:: bash

   garak --config chains.yaml --target_type TARGET_PLUGIN --target_name TARGET_NAME

The probe's red-team generator and the
``detectors.agent_breaker.AgentBreakerChainResult`` judge generator also
require their normal provider configuration and credentials.

The primary detector judges the target's response claim for the artifact-bearing
terminal request, and for any earlier step whose tool is side-effecting. A positive score does not establish that the
planned tool was used or that a backend side effect occurred; verify routing
and backend state separately in the authorised test environment.

Treat results as discovery signals, not as a population estimate or benchmark.
The number of scored attempts depends on the selected paths and how far each
chain progresses.

Related work
------------

The following research and case studies examine risks arising from tool
composition:

* `ChainFuzzer <https://arxiv.org/abs/2603.12614>`_ (March 2026) studies
  workflow-level tool-chain vulnerabilities using grey-box, trace-guided
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

These references provide context for the attack class. ``ToolChain`` does
not implement ChainFuzzer's grey-box, trace-guided analysis. The cited studies'
results do not establish this probe's attack coverage or success rate.

.. automodule:: garak.probes.agent_breaker
   :members:
   :undoc-members:
   :show-inheritance:

   .. show-asr::
