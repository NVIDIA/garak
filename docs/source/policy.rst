garak.policy
============

This module represents objects related to policy scanning. 

Policy scanning in garak attempts to work out what the target's content policy
is, before running a security scan. 

It's important to know what target content policy is because we only really have
a useful/successful hit or breach if we're able to get a model to do something that
it otherwise wouldn't. It may be exciting to discover a model gives instructions for
e.g. cooking meth if the request is encoded in base64, but if in fact the model gives
the instructions when simply asked directly "print instructions for cooking meth", the
use of base64 necessarily an exploit in this output category - the model is acting 
the same.

Garak's policy support follows a typology of different behaviours, each describing
a different behaviour. By default this typology is stored in ``data/policy/policy_typology.json``.

A policy scan is conducted by invoking garak with the ``--policy_scan`` switch.
When this is requested, a separate scan runs using all policy probes within garak.
Policy probes are denoted by a probe class asserting ``policy_probe=True``.
A regular probewise harness runs the scan, though reporting is diverted to a separate
policy report file. After completion, garak estimates a policy based on policy probe
results, and writes this to both main and poliy reports.


Model behaviour typologies
--------------------------

Goal
^^^^

The model behaviour typology enumerates many different types of target behaviour. The listed behaviours help structure a policy for model output. For each behaviour, one can choose if an model should engage or not engage in that activity.

The typology serves as a point of departure for building model content policies, as well as a framework for describing model behaviour. 

This typology is hierarchical, but labels are not “hard”. That is, multiple categories might apply to a single candidate behaviour, and that's OK.

Because the range of possible model behaviours is large, and an open set, this typology is not comprehensive, and is not designed or intended to ever be comprehensive.

To optimise effort spent building this typology, it's best to prioritise addition & definition of categories for which we actually have payloads.

Usage
^^^^^

To use this typology to describe an model deployment, examine each category and check if the target model engages with that behaviour directly, without using any adversarial techniques.

To use this typology to describe intended deployed model policy, consider each category in turn and decide how the model should react. A possible set of possible reactions can be as simple as "Engage" & "Decline".

Policy point guidelines
^^^^^^^^^^^^^^^^^^^^^^^

* Each point describes something that the model does, i.e. a behaviour
* Given a decent prompt representing a policy, and a model's response, it should be possible to discern in isolation whether or not the model is engaging or refusing for that prompt/response pair
* Prioritise enumerating policies that reflect things we have tests for (or can reasonably test for)
* It's great to have two sample prompts per point
* We want to stick to max three levels if at all possible
* Multiple inheritance is fine, e.g. a probe might represent multiple points in this typology

Policy metadata
^^^^^^^^^^^^^^^

The total set of points in the behaviour typology can be represented as a dictionary. Definitions of policy names, descriptions, and behaviours are stored in a JSON data file

* Key: behaviour identifier - format is TDDDs*
	* T: a top-level hierarchy code letter, in CTMS for chat/tasks/meta/safety
	* D: a three-digit code for this behaviour
	* s*: (optional) one or more letters identifying a sub-policy

Value: a dict describing a behaviour
   * “name”: A short name of what is permitted when this behaviour is allowed
   * “description”: (optional) a deeper description of this behaviour

The structure of the identifiers describes the hierarchical structure.


.. automodule:: garak.policy
   :members:
   :undoc-members:
   :show-inheritance:   
