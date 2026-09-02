Tags and Taxonomies
===================

garak includes a number of tags on ``Probe`` objects that describe both *intents* and *techniques*.
Within garak, we define an *intent* to be, more-or-less, "what you want the model to do".
In contrast, a *technique* is an particular way of structuring a request intended to get the model to comply with provided instructions.

Tags are enumerated in ``garak/data/tags.misp.tsv``.
While garak supports tags for many frameworks, the inclusion of a taxonomy does not mean that every relevant attribute of a framework is fully covered.
Be certain that if you use garak for compliance checking related to one of these frameworks, you familiarize yourself with the framework itself and the parts that are *not* covered by garak.
Currently, garak supports the following frameworks via tags:

* OWASP LLM Top 10
* AVID Effects
* Language Model Risk Cards
* Common Weakness Enumeration
* Summon and Demon and Bind it
* EU AI Act

OWASP LLM Top 10
----------------
The `OWASP LLM Top 10`_ identifies prominent security risks affecting applications built with large language models, including prompt injection, insecure output handling, training data poisoning, excessive agency, sensitive information disclosure, and model theft.
It provides a practical application-security framework for identifying and communicating LLM-specific vulnerabilities and their mitigations across the development and deployment lifecycle.

.. _OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/

.. csv-filter:: Relevant Tags
    :delim: tab
    :widths: 20, 30, 50
    :align: left
    :file: ../../garak/data/tags.misp.tsv
    :include: {0: '^owasp:'}

AVID Effects
------------
The `AI Vulnerability Database`_ (AVID) is an open-source knowledge base and taxonomy for documenting observed failures and vulnerabilities in AI systems.
AVID organizes issues across areas such as security, ethics, and performance, helping practitioners classify findings consistently and relate them to known AI failure modes and other risk frameworks.

.. _AI Vulnerability Database: https://avidml.org/

.. csv-filter:: Relevant Tags
    :delim: tab
    :widths: 20, 30, 50
    :align: left
    :file: ../../garak/data/tags.misp.tsv
    :include: {0: '^avid-effect'}

Language Model Risk Cards
-------------------------
`Language Model Risk Cards`_ provide a structured way to document risks associated with a language model or its deployment context.
Each RiskCard describes how a risk can lead to harm, relates it to broader harm taxonomies, and can include representative prompt-and-output examples, making the framework useful for evaluating and communicating risks that may depend heavily on how a model is used.

.. _Language Model Risk Cards: https://arxiv.org/abs/2303.18190

.. csv-filter:: Relevant Tags
    :delim: tab
    :widths: 20, 30, 50
    :align: left
    :file: ../../garak/data/tags.misp.tsv
    :include: {0: '^risk-cards:'}

Common Weakness Enumeration
---------------------------
`Common Weakness Enumeration`_ (CWE) is a community-developed list of common software and hardware weakness types that **could** have security ramifications.
Although CWE is not specific to AI, it provides standardized identifiers and terminology for implementation-level security weaknesses, making it useful for classifying conventional software vulnerabilities found in AI applications, services, and supporting infrastructure.

.. _Common Weakness Enumeration: https://cwe.mitre.org/

.. csv-filter:: Relevant Tags
    :delim: tab
    :widths: 20, 30, 50
    :align: left
    :file: ../../garak/data/tags.misp.tsv
    :include: {0: '^cwe:'}

Summon a Demon and Bind It
--------------------------
`Summon a Demon and Bind It`_ presents an empirically grounded framework for understanding how practitioners red-team large language models.
Based on interviews with red-teamers, the research characterizes LLM red teaming as a limit-seeking, largely manual activity and identifies 12 attack strategies and 35 techniques, providing a useful basis for designing adversarial tests that probe model behavior and attempt to elicit failures or bypass safeguards.

.. _Summon a Demon and Bind It: https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0314658

.. csv-filter:: Relevant Tags
    :delim: tab
    :widths: 20, 30, 50
    :align: left
    :file: ../../garak/data/tags.misp.tsv
    :include: {0: '^demon:'}

EU AI Act
---------
The `EU AI Act`_ is a regulatory framework that establishes risk-based requirements for developing, providing, and deploying AI systems in the European Union.
It distinguishes among different levels and types of AI risk, prohibits certain practices, imposes requirements on high-risk systems, establishes transparency obligations, and introduces additional requirements for general-purpose AI models, including provisions related to evaluation, risk management, adversarial testing, and cybersecurity for models with systemic risk.

.. _EU AI Act: https://artificialintelligenceact.eu/

.. csv-filter:: Relevant Tags
    :delim: tab
    :widths: 20, 30, 50
    :align: left
    :file: ../../garak/data/tags.misp.tsv
    :include: {0: '^euai:'}
