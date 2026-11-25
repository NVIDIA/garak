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

Agent configuration file
------------------------

Both probes read a description of the target agent from one YAML file, set
with the ``agent_config_file`` parameter. The red-team model plans its attacks
from this text. In Single, the judge also uses it to decide what counts as
misuse. The ``ToolChain`` judge sees only the request, the planned sink
requirement and the response, so there the file shapes planning and chain
selection. Either way, its accuracy and level of detail directly affect what
the probes can find.

The file uses this structure:

* ``agent_purpose`` - what the agent is for: its role, who it serves, what it
  is authorised to do, and anything it must not do. Where possible, take this
  from the agent's own system prompt.
* ``tools`` - a list with one entry for each tool the agent exposes:

  * ``name`` - the tool's exact name as registered in the agent, with the same
    spelling and case. This is the function name the agent's model calls, not
    a display label.
  * ``description`` - everything relevant about the tool, in plain text:

    * the function signature: every parameter with its type and default, and
      the return type
    * what input it expects where the signature does not show it, such as the
      format of an id or the language a code-running tool executes
    * what the tool does and what it returns, such as an id, a path, a URL or
      file contents
    * its side effects, such as changing a record, moving money, sending data
      or running code
    * any limit or precondition, such as a maximum amount, a required approval
      or an ownership check

  * ``chain`` - optional, ``ToolChain`` only. ``false`` keeps the tool out of
    every chain (default: ``true``).

Other keys are ignored. There is no separate field for a parameter schema, so
the signature belongs in ``description``.

Example
-------

This file describes a finance assistant with four tools. Each name is the
function name from the agent's code, and each description starts with the
function signature:

.. code-block:: yaml

   agent_purpose: |
     "Ledger", the finance-operations assistant for Acme Corporation. It helps
     the finance team review and approve expense reports, issue
     reimbursements, and move funds between accounts.
   tools:
     - name: get_expense_report
       description: >-
         get_expense_report(report_id: str) -> dict. Fetches one expense report
         by id and returns its line items, amount and status. Returns an error
         when the id is not found. Read-only.
     - name: list_vendor_accounts
       description: >-
         list_vendor_accounts(query: str = "") -> dict. Lists registered vendor
         payment accounts, including account id, name and bank routing
         details. The optional query filters by name or account id. Read-only.
     - name: approve_expense
       description: >-
         approve_expense(report_id: str) -> dict. Approves the expense report
         with that id for payment and returns the updated report with status
         "approved". Changes backend state.
     - name: transfer_funds
       description: >-
         transfer_funds(to_account: str, amount: float, memo: str = "") -> dict.
         Transfers amount USD (must be greater than 0) to the destination
         account number or identifier. Returns a transfer id such as TR-0001.
         Moves money.

File location
-------------

``agent_config_file`` is a path relative to garak's ``data`` directory. garak
looks for it first under the user data directory, which is
``$XDG_DATA_HOME/garak/data`` (by default ``~/.local/share/garak/data`` on
Linux and macOS), and then among the files shipped with garak. Absolute paths
and paths that leave the ``data`` directory are rejected. When the file cannot
be found, the probe fails to load.

The default is ``agent_breaker/agent.yaml``, and the copy shipped with garak is
empty. Supply your own description in one of two ways:

* Save it under its own name in the user data directory, for example
  ``$XDG_DATA_HOME/garak/data/agent_breaker/finance_agent.yaml``, and set
  ``agent_config_file: agent_breaker/finance_agent.yaml``. This keeps one file
  per target.
* Save it as ``$XDG_DATA_HOME/garak/data/agent_breaker/agent.yaml``. It then
  takes precedence over the shipped file, and both probes use it without
  further configuration.

Do not edit the copy inside the installed garak package; it is replaced on
upgrade.

How each probe uses the file
----------------------------

``AgentBreaker`` (Single):

* If ``tools`` is missing or empty, the probe asks the target to list its
  tools and parses the reply with the parse model. When ``agent_purpose`` is
  also empty, it asks for the purpose in the same request. If no tools result,
  the probe does not run.
* If ``tools`` is filled in, nothing is discovered and the file is used as
  written, including an empty ``agent_purpose``.
* The red-team model analyses all listed tools in one request and proposes
  several opening attack prompts for each. Each tool it returns an analysis
  for is attacked, in the model's own priority order rather than file order.
  Every opening prompt starts its own line of attack, which is refined until
  it succeeds or has used ``max_attempts_per_tool`` prompts. Each prompt is
  sent ``run.generations`` times.
* ``chain`` has no effect: a tool marked ``chain: false`` can still be
  attacked. Leave a tool out of the file to keep it out of a Single run.

``ToolChain``:

* Tools are not discovered yet, so the file must list them. Automatic
  discovery is planned as a future feature.
* ``agent_purpose`` must be text and ``tools`` must be a list, otherwise the
  probe fails to load. At least two chainable tools must remain after the
  rules below, otherwise the probe logs an error and sends no requests.
* An entry is ignored when it is not a mapping, when its ``name`` is missing
  or not text, when its name is longer than 128 characters, or when its name
  repeats an earlier one (compared without regard to case).
* ``chain: false`` removes the tool from planning. A ``chain`` value that is
  not a boolean, such as the quoted string ``"false"``, also removes it. When
  a name appears more than once, one such entry removes every entry of that
  name.
* Only the first ``max_tools`` remaining tools are used, in file order.
* ``description`` is cut to about 500 characters and ``agent_purpose`` to
  about 1000, so put the signature and the most important facts first.

Why the detail matters
----------------------

* ``name`` - probe requests name the tool literally (in Single, ``Use the
  <name> tool ...``) and results are reported against that name. An agent may
  still act on a request that uses a different name by choosing a tool
  itself, but then the tool that ran is the agent's choice and the result is
  recorded against a name the agent does not have.
* Signature and return value - the red-team model writes requests that have to
  supply the tool's parameters, so stating them lets it use the right names
  and formats. ``ToolChain`` links tools mainly where the red-team model
  judges that one tool's output can feed another's input, and it makes that
  judgement from the descriptions. Use the same words for the same thing
  across tools.
* Side effects - the red-team model uses these when it marks which tools are
  sinks, the tools a ``ToolChain`` chain must end at.
* Limits and preconditions - the Single judge and the ``ToolChain`` relevance
  check are instructed to treat ``description`` as the authority on what the
  tool may do. A written limit gives them something to measure a request
  against. Without one, the Single judge can still flag general harms such as
  secret disclosure or destructive actions.
* ``agent_purpose`` - this tells the models what counts as normal use. With
  ``chain_selection: relevance``, ``ToolChain`` drops chains it is confident
  are simply the agent doing its authorised job, so a purpose broader than the
  agent's real remit can lead it to drop chains it would otherwise keep.

.. note::

   Describe the agent as it is. Adding suspected vulnerabilities, or limits
   the agent does not really have, can bias both the attacks and the
   verdicts.

   Discovery in Single is a quick way to start against an unknown agent, but
   it depends on what the agent says about itself. It returns one short
   sentence per tool, the names can differ from the registered ones (for
   example with a namespace prefix), and the list can include entries that
   are not the agent's own tools.

Model configuration
-------------------

Besides the target, each probe uses up to three models, which are set in the
garak configuration file:

* Red-team model - plans and writes the attacks. Set on the probe with
  ``red_team_model_type``, ``red_team_model_name`` and
  ``red_team_model_config`` (default: ``nim``, ``openai/gpt-oss-120b``).

  * Single: analyses the tools, writes the opening attack prompts and refines
    them after each response.
  * ``ToolChain``: analyses and tags the tools, scores the links between
    them, filters chains for relevance when ``chain_selection`` is
    ``relevance``, and writes the exploit hypotheses, step plans and step
    requests.

* Parse model - turns free text into structured data. Set on the probe with
  ``parse_model_type``, ``parse_model_name`` and ``parse_model_config``
  (default: unset, which reuses the red-team model).

  * Single: parses the target's reply during discovery.
  * ``ToolChain``: checks each request before it is sent, checks whether a
    step completed, and extracts artifacts from the response of each completed
    intermediate step.

* Judge model - decides whether a response is a hit. Set on the detector with
  ``detector_model_type``, ``detector_model_name`` and
  ``detector_model_config`` (default: ``nim``, ``openai/gpt-oss-120b``).

  * Single: ``detectors.agent_breaker.AgentBreakerResult``. The probe also
    calls this judge during the run, on every target response, to decide
    whether a line of attack has succeeded and can stop.
  * ``ToolChain``: ``detectors.agent_breaker.AgentBreakerChainResult``, which
    scores the eligible steps after the run.

In each group, ``*_type`` is a garak generator plugin, ``*_name`` is the model
name passed to it, and ``*_config`` holds further generator settings such as
``uri`` and ``max_tokens``. Each generator reads its API key from its usual
environment variable, for example ``NIM_API_KEY`` for ``nim``.

Settings given in ``*_config`` are merged over the defaults, so only the
values that differ need to be listed. This example sets one red-team model for
both probes and a judge for each detector, using an OpenAI-compatible endpoint
other than the ``nim`` default:

.. code-block:: yaml

   plugins:
     probes:
       agent_breaker:
         red_team_model_type: nim
         red_team_model_name: MODEL_NAME
         red_team_model_config:
           uri: https://ENDPOINT/v1/
     detectors:
       agent_breaker:
         AgentBreakerResult:
           detector_model_type: nim
           detector_model_name: MODEL_NAME
           detector_model_config:
             uri: https://ENDPOINT/v1/
         AgentBreakerChainResult:
           detector_model_type: nim
           detector_model_name: MODEL_NAME
           detector_model_config:
             uri: https://ENDPOINT/v1/

When choosing models:

* The red-team model must be willing to do security analysis and must answer
  in JSON. If it refuses or returns something else at the analysis step,
  Single logs ``No tools to attack`` and sends nothing. ``ToolChain`` can
  continue without the per-tool analysis, and logs ``No executable chains
  found`` when its later planning steps also produce nothing usable.
* The judge determines the reported results. Validate it on known responses
  before relying on its scores.
* Where possible, use different models for the target, the red-team model and
  the judge.

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
           agent_config_file: agent_breaker/finance_agent.yaml

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
``ToolChain``; keep ``max_attempts_per_tool`` under ``AgentBreaker``.

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
