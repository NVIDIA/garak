garak.probes._tier
==================

Why are there ``Tier``\ s in garak? That's a good question -- why would there be tiers for anything? Implicit in this notion is the idea that an item of a higher tier is "better" for some metric. In gaming, tiers are often used to highlight characters/decks with higher win rates.

So what is a tier in garak? The flippant answer is that it's a convenient way to deal with the question "What probes should I run?" -- something new users and those who don't like to spin their GPU for extended periods of time often ask. It effectively establishes a hierarchy to say "If you can only run a small number of probes, these are the most important ones". But what makes a probe important? Well, unfortunately, the best answer to that question is a classic: it depends.

So in the absence of knowing what you care about, should you care about ```av_spam_scanning``? Almost certainly not, unless you're trying to test the efficacy of an antivirus or spam scanner you've put in front of your model. Should you care about ``malwaregen``? Do you care if your model/system will write malicious code?

Security, Prevalence, and Risk
------------------------------

``garak`` is a tool intended to test the *security* of a target LLM-powered system. This is not a trivial thing, but it gives us a first principle to work with: probes that indicate the ability to exploit a security risk should, ceteris paribus (Latin for "I read a statistics textbook once"), have a higher tier. This does not mean that probes which do not consider security are relegated to the bin, but rather that probes which indicate a potential security impact should be treated preferentially. Security here means with respect to confidentiality, integrity, and availability of the system and its data. Content safety (making models say rude things) is not an attribute of security. It can carry financial and reputational risks, but it is not a part of security.

When we think about prevalence, there are two key notions we need to deal with:

1. What is the prevalence of this attribute in models/systems under test (e.g. can it deal with Base64 encoded text)?
2. What is the prevalence of concomitant weaknesses that would make having some attribute lead to security failures?

The first is a double-edged sword: If an attribute is very prevalent (nearly all modern LLMs handle most Base64 encoded text fairly gracefully), then knowing that a model/system DOES NOT have that attribute is important. On the other hand, if an attribute is somewhat common, or performance is middling across nearly all models/systems, then it is not particularly useful to know the performance of a system there. These are, in essence, "tie breakers" when it comes to a tier.

The second question is more exciting, since it ties in with our first principle: probes that indicate the ability to exploit a security risk should have a higher tier. If the prevalence of concomitant weaknesses is high, that suggests the probe in question is more important. Testing whether your LLM-powered application can write an exploit for a templating language that has only ever been used on a VAX machine is not very useful. Testing whether it can facilitate server-side template injection in a popular templating language like Jinja or mako, on the other hand, is useful information. This gives us a second principle: If the probe deals with issues where a concomitant configuration is common, it should have a higher tier.

Adversarial Robustness and Alignment
------------------------------------

Whether or not one personally considers it important, significant amounts of time and effort go into aligning large language models. Adversarially structured prompts that break this alignment process can facilitate greater control over LLM output. If an LLM is outputting whatever a malicious user wants, it's providing a convenient path into attacker control of the system, assuming other weaknesses are present. This gives us principle three: Probes that evaluate adversarial robustness should have a higher tier.

Tiers with our Principles
-------------------------

Enumerating the three principles we've developed:

1. Probes that indicate a security risk should, in general, have a higher tier.
2. If the probe deals with issues where a concomitant configuration is common, it should have a higher tier.
3. Probes that evaluate adversarial robustness should have a higher tier.

The existing garak tier list has 4 tiers: 1 > 2 > 3 > 9/U. Looking at their existing definitions:

* Tier 1: Low pass rate or low z-score may be problematic.
* Tier 2: Low z-score may be problematic
* Tier 3: Context sensitive; low scores may affect suitable use cases
* Tier 9: Duplicated, deprecated, fluctuating, or non-adversarial probe.

This tier list is heavily focused on the evaluation of adversarial robustness and model-centered evaluation. If we center the tier list around systems and "you might get pwnd" instead, you end up with something more like:

* Tier 1: Sub 100% pass rate suggests the possibility of a current or future exploitable vulnerability in the deployed system
* Tier 2: Low pass rate or z-score suggests some risk to data or that attackers have undue control over the system and its resources.
* Tier 3: Highly contextual probes. Should be enabled only if you care about the specific property it is testing.
* Tier 9: Probes without any security impact, deprecated probes, probes with poor support.

The nice thing is that these are not incompatible tier lists -- most probes in Tier 1 under the current definition will fall cleanly into Tier 1 in the "system-centric" definition and so on. For "tie breaking" (Tier n in one list, Tier n-1 in another), we can consider prevalence -- how important for a hypothetical user is it to know about this thing; how prevalent is the related configuration?

This means that probe families like ``exploitation``, ``ansiescape``, and ``dan`` will generally fall into Tier 1, while those like ``encoding`` and ``lmrc`` will generally fall into Tier 3. Things like ``fileformats`` are Tier 3 because they are highly contextual (you need the model on the system and you need to care about the trustworthiness of the model file). Something like ``malwaregen`` is a good example of Tier 2 -- if the system will generate (and execute) code for you, it can be a problem, so a low z-score can be a problem, but it isn't really a dealbreaker. Similarly, ``leakreplay`` is a good example of a Tier 2 probe: you may not care about a model repeating copyrighted text verbatim, but if it does it more often than an average model, someone somewhere is possibly going to get mad.

.. automodule:: garak.probes._tier
   :members:
   :undoc-members:
   :show-inheritance:
