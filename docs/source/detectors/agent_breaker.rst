garak.detectors.agent_breaker
=============================

This module contains separate detectors for the two Agent Breaker probes.
``detectors.agent_breaker.AgentBreakerResult`` serves Single, while
``detectors.agent_breaker.AgentBreakerChainResult`` serves only eligible
terminal attempts from ``probes.agent_breaker.SourceToSink``. Selecting or
configuring one detector does not replace the other.

AgentBreakerChainResult
-----------------------

``AgentBreakerChainResult`` is a terminal-only model-as-judge detector. It
evaluates whether a target's response gives concrete evidence for the exact
planned sink requirement, rather than any mutation requested or implied by an
eligible terminal request.

The judge receives the exact terminal attack prompt, planned sink requirement,
and corresponding target response. It does not receive tool definitions,
intermediate artifacts, the chain transcript, other planner state, experiment
labels, or target-provided backend metadata. ``YES`` scores as a hit; ``NO``
and ``UNKNOWN`` score as a pass. Ineligible or unevaluable outputs are not
scored.

This detector scores response claims, not backend truth. A hit must not be
reported as proof that an external state change occurred. Use independent
backend observations when validating an authorised, disposable sandbox target.
The detector also cannot verify that the target routed the request to the
manifest tool named by the probe.

Scores depend on the configured judge model. Validate the chosen judge on
held-out responses before interpreting results.

The :ref:`local review instructions <agent-breaker-chain-local-review>` run
this detector's tests with a mocked judge and require no provider credentials
or target server. They check verdict parsing, rejection of malformed responses,
terminal eligibility, and the exact information passed to the judge. Passing
these tests validates the scoring contract, not a real judge's accuracy or a
backend state change.

Configure this detector under its class name so its settings do not also apply
to Single's detector:

.. code-block:: yaml

   plugins:
     detectors:
       agent_breaker:
         AgentBreakerChainResult:
           detector_model_type: nim
           detector_model_name: openai/gpt-oss-120b

.. automodule:: garak.detectors.agent_breaker
   :members:
   :undoc-members:
   :show-inheritance:
