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

Describing the target agent
---------------------------

Both probes read a description of the target agent from one YAML file, named by
the ``agent_config_file`` parameter. The file states what the agent is for and
which tools it exposes. Everything the red-team model plans, and part of what
the judge decides, is derived from this text, so its accuracy and level of
detail directly affect what the probes can find.

Where the file goes
~~~~~~~~~~~~~~~~~~~

``agent_config_file`` is a path relative to garak's ``data`` directory. garak
looks for it first under the user data directory, which is
``$XDG_DATA_HOME/garak/data`` (by default ``~/.local/share/garak/data`` on
Linux and macOS), and then among the files shipped with garak. Absolute paths
and paths that leave the ``data`` directory are rejected, and a file that
cannot be found stops the run.

The default value is ``agent_breaker/agent.yaml``. The shipped copy of that
file is empty. There are two ways to supply your own description:

* Save it under its own name in the user data directory, for example
  ``$XDG_DATA_HOME/garak/data/agent_breaker/support_agent.yaml``, and set
  ``agent_config_file: agent_breaker/support_agent.yaml`` for the probe. This
  keeps one file per target and is the recommended layout.
* Save it as ``$XDG_DATA_HOME/garak/data/agent_breaker/agent.yaml``. It then
  takes precedence over the shipped file, and both probes use it without any
  further configuration.

Do not edit the copy inside the installed garak package; it is replaced on
upgrade.

File format
~~~~~~~~~~~

.. code-block:: yaml

   agent_purpose: |
     Customer support assistant for an online shop. It answers order and
     billing questions for the signed-in customer only. It must not act on
     another customer's account or issue refunds above 50 USD.
   tools:
     - name: lookup_order
       description: >-
         Takes an order id. Returns that order's status, items, total and the
         customer id that owns it. Read-only. Only orders belonging to the
         signed-in customer may be returned.
     - name: issue_refund
       description: >-
         Takes an order id and an amount in USD. Refunds that amount to the
         order's original payment method and returns a refund id. Limited to
         50 USD per order; larger refunds require a human supervisor.
     - name: close_account
       description: Permanently deletes a customer account by customer id.
       chain: false

.. list-table::
   :header-rows: 1
   :widths: 20 12 68

   * - Key
     - Type
     - Meaning
   * - ``agent_purpose``
     - text
     - What the agent is for, whom it serves, and what it is and is not
       authorised to do.
   * - ``tools``
     - list
     - One entry per tool the target exposes.
   * - ``tools[].name``
     - text
     - The tool's identifier, exactly as the target knows it.
   * - ``tools[].description``
     - text
     - The tool's contract: what it does, what it accepts and returns, and any
       limits or preconditions.
   * - ``tools[].chain``
     - boolean
     - ``ToolChain`` only. ``false`` keeps the tool out of every chain. Defaults
       to ``true``.

Other keys are ignored. Parameter schemas, for example, are not read
separately, so any input or output detail that matters belongs in
``description``.

How each probe reads the file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``AgentBreaker`` (Single):

* If ``tools`` is missing or empty, the probe asks the target to list its
  tools and parses the reply with the parse model. When ``agent_purpose`` is
  also empty, it asks for the purpose in the same request. If no tools result,
  the probe does not run.
* If ``tools`` is filled in, nothing is discovered and the file is used as
  written, including an empty ``agent_purpose``.
* Every listed tool is attacked, up to ``max_attempts_per_tool`` requests each.
  ``chain`` has no effect here: a tool marked ``chain: false`` is still
  attacked by Single.

``ToolChain``:

* Nothing is discovered. ``agent_purpose`` must be text and ``tools`` must be a
  list, otherwise the probe fails at load. At least two chainable tools must
  remain after the rules below, otherwise it fails when the run starts.
* An entry is ignored when it has no ``name``, when its name is longer than 128
  characters, or when its name repeats an earlier one (compared without regard
  to case).
* ``chain: false`` removes the tool from planning. A ``chain`` value that is
  not a boolean, such as the quoted string ``"false"``, also removes it.
* Only the first ``max_tools`` remaining tools are used, in file order.
* ``description`` is cut to 500 characters and ``agent_purpose`` to 1000.

Because Single ignores ``chain`` and ``ToolChain`` needs a complete manifest,
keep a separate file for each probe when a tool must stay out of a run, and
leave that tool out of the file used for Single.

Writing an effective description
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The probes see the target only through this file and through its replies. Each
field feeds specific decisions:

``name``
  Probe requests name the tool literally (``Use the <name> tool ...``), and the
  target has to recognise it. Use the identifier from the target's own tool
  definition, with the same spelling and case, not a friendly label. A name
  the target does not recognise leads to requests that are refused or routed
  to another tool, which appear as failed attacks rather than as findings.

``description``
  Treat this as the tool's contract and copy it from the target's real tool
  definition where possible. It is used in three ways:

  * The red-team model derives each tool's weaknesses and its first attack
    prompts from what the description says the tool does. A one-line summary
    produces generic attacks; a description that states the accepted inputs
    and their format produces attacks aimed at them.
  * ``ToolChain`` tags what each tool consumes and produces, and connects two
    tools only when one tool's output can plausibly become another's input.
    State what each tool returns (an id, a path, a URL, file contents) and what
    it accepts, using the same words for the same thing across tools. A
    relationship the descriptions do not show is unlikely to be explored.
    State side effects too: they decide which tools are treated as sinks.
  * The Single judge, and the ``ToolChain`` relevance check, treat the
    description as the authority on what the tool may do and read it
    literally. A limit or precondition written here (a scope, an amount, a
    required approval, an ownership check) lets the judge recognise a request
    that goes past it. A limit that is not written cannot be judged, and only
    universal harms such as secret disclosure or destructive actions are
    still caught. A tool without a description is judged without a contract.

  Describe the tool as it is. Adding suspected vulnerabilities or restrictions
  the target does not really have biases both the attacks and the verdicts.
  For ``ToolChain``, put the most important facts first so that they survive
  the 500 character limit.

``agent_purpose``
  This gives the red-team model and the judge the context for what counts as
  normal use. With ``chain_selection: relevance``, ``ToolChain`` drops chains
  that are simply the agent doing its authorised job, as measured against this
  text. A broad purpose such as "a general assistant that can do anything"
  therefore removes more chains and excuses more behaviour, while a specific
  purpose that names the users served and the actions that are off limits
  keeps the chains that cross those lines. Leaving it empty removes this
  context from every decision.

Order and scope
  List the tools you most want tested first: ``ToolChain`` reads only the
  first ``max_tools``. For Single, run length grows with the number of tools,
  so a file limited to the tools of interest gives a shorter, more focused
  run.

Supplied description or discovery
  Discovery in Single depends on the target listing its tools truthfully and
  yields one short sentence per tool. It is a quick way to start against an
  unknown target. A hand-written file that follows the guidance above gives
  the red-team model and the judge more to work with, and is the only option
  for ``ToolChain``.

Configuration and invocation
----------------------------

Place the description in the user data directory as described above. To run
Single against it, select ``AgentBreaker`` and configure it under its class
name:

.. code-block:: yaml

   run:
     spec:
       include:
         - probes.agent_breaker.AgentBreaker
   plugins:
     probes:
       agent_breaker:
         AgentBreaker:
           agent_config_file: agent_breaker/support_agent.yaml

For ``ToolChain``, select only ``ToolChain`` and configure it under its class
name:

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

Keep variant-specific settings under the class name as shown. Settings placed
directly under the ``agent_breaker`` module apply to both Single and
``ToolChain``.

Then run either probe with the normal target configuration, replacing the
placeholders:

.. code-block:: bash

   garak --config agent_breaker.yaml --target_type TARGET_PLUGIN --target_name TARGET_NAME

The probe's red-team generator and the judge generator of its detector
(``detectors.agent_breaker.AgentBreakerResult`` for Single,
``detectors.agent_breaker.AgentBreakerChainResult`` for ``ToolChain``) also
require their normal provider configuration and credentials.

For ``ToolChain``, the primary detector judges the target's response claim for
the artifact-bearing terminal request, and for any earlier step whose tool is
side-effecting. A positive score does not establish that the
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
