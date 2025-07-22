Top-level concepts in ``garak``
===============================

What are we doing here, and how does it all fit together?
Our goal is to test the security of something that takes prompts
and returns text. ``garak`` has a few constructs used to simplify and
organise this process.


generators
----------
:doc:`generators` wrap a target LLM or dialogue system. They take a prompt
and return the output. The rest is abstracted away. Generator classes
deal with things like authentication, loading, connection management,
backoff, and all the behind-the-scenes things that need to happen
to get that prompt/response interaction working.

probes
------
:doc:`probes` tries to exploit a weakness and elicit a failure. The probe
manages all the interaction with the generator. It determines how
often to prompt, and what the content of the prompts is. Interaction
between probes and generators is mediated in an object called an attempt.

attempt
-------
An :doc:`attempt` represents one unique try at breaking the target. A probe wraps
up each of its adversarial interactions in an attempt object, and passes this
to the generator. The generator adds responses into the attempt and sends
the attempt back. This is logged in ``garak`` reporting which contains (among other
things) JSON dumps of attempts.

Once the probe is done with the attempt and the generator has added its
outputs, the outputs are examined for signs of failures. This is done in a
detector.

detectors
---------
:doc:`detectors` attempt to identify a single failure mode. This could be
for example some unsafe contact, or failure to refuse a request. Detectors
do this by examining outputs that are stored in a prompt, looking for a
certain phenomenon. This could be a lack of refusal, or continuation of a
string in a certain way, or decoding an encoded prompt, for example.


buffs
-----
:doc:`buffs` adjust prompts before they're sent to a generator. This could involve
translating them to another language, or adding paraphrases for probes that
have only a few, static prompts.


evaluators
----------
When detectors have added judgments to attempts, :doc:`evaluators` converts the results
to an object containing pass/fail data for a specific probe and detector pair.

harnesses
---------
The :doc:`harnesses` manage orchestration of a ``garak`` run. They select probes, then
detectors, and co-ordinate running probes, passing results to detectors, and
doing the final evaluation

.. automodule:: garak._plugins
   :members:
   :undoc-members:
   :show-inheritance:
   :no-index: