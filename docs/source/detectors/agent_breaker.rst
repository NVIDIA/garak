garak.detectors.agent_breaker
=============================

This module contains separate detectors for the two Agent Breaker probes.
``detectors.agent_breaker.AgentBreakerResult`` serves Single, while
``detectors.agent_breaker.AgentBreakerChainResult`` serves only eligible
eligible attempts from ``probes.agent_breaker.ToolChain``. Selecting or
configuring one detector does not replace the other.

AgentBreakerChainResult
-----------------------

``AgentBreakerChainResult`` is a model-as-judge detector. It evaluates whether
a target's response gives concrete evidence for the exact planned sink
requirement, rather than any mutation requested or implied by an eligible
request. The terminal step is always eligible. An earlier step is eligible only
when its tool is side-effecting, because it may already cause the harm; other
earlier steps are not scored.

The judge receives the exact attack prompt, planned sink requirement,
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
