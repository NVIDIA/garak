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

Relevant Tags
~~~~~~~~~~~~~
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| owasp:llm01                      | LLM01: Prompt Injection                    | Crafty inputs can manipulate a Large Language Model, causing unintended  |
|                                  |                                            | actions. Direct injections overwrite system prompts, while indirect ones |
|                                  |                                            | manipulate inputs from external sources.                                 |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| owasp:llm02                      | LLM02: Insecure Output Handling            | This vulnerability occurs when an LLM output is accepted without         |
|                                  |                                            | scrutiny, exposing backend systems. Misuse may lead to severe            |
|                                  |                                            | consequences like XSS, CSRF, SSRF, privilege escalation, or remote code  |
|                                  |                                            | execution.                                                               |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| owasp:llm03                      | LLM03: Training Data Poisoning             | This occurs when LLM training data is tampered, introducing              |
|                                  |                                            | vulnerabilities or biases that compromise security, effectiveness, or    |
|                                  |                                            | ethical behavior. Sources include Common Crawl, WebText, OpenWebText, &  |
|                                  |                                            | books.                                                                   |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| owasp:llm04                      | LLM04: Model Denial of Service             | Attackers cause resource-heavy operations on Large Language Models       |
|                                  |                                            | leading to service degradation or high costs. The vulnerability is       |
|                                  |                                            | magnified due to the resource-intensive nature of LLMs and               |
|                                  |                                            | unpredictability of user inputs.                                         |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| owasp:llm05                      | LLM05: Supply Chain Vulnerabilities        | LLM application lifecycle can be compromised by vulnerable components or |
|                                  |                                            | services, leading to security attacks. Using third-party datasets, pre-  |
|                                  |                                            | trained models, and plugins can add vulnerabilities.                     |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| owasp:llm06                      | LLM06: Sensitive Information Disclosure    | LLMs may reveal confidential data in its responses, leading to           |
|                                  |                                            | unauthorized data access, privacy violations, and security breaches.     |
|                                  |                                            | It’s crucial to implement data sanitization and strict user policies to  |
|                                  |                                            | mitigate this.                                                           |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| owasp:llm07                      | LLM07: Insecure Plugin Design              | LLM plugins can have insecure inputs and insufficient access control.    |
|                                  |                                            | This lack of application control makes them easier to exploit and can    |
|                                  |                                            | result in consequences like remote code execution.                       |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| owasp:llm08                      | LLM08: Excessive Agency                    | LLM-based systems may undertake actions leading to unintended            |
|                                  |                                            | consequences. The issue arises from excessive functionality,             |
|                                  |                                            | permissions, or autonomy granted to the LLM-based systems.               |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| owasp:llm09                      | LLM09: Overreliance                        | Systems or people overly depending on LLMs without oversight may face    |
|                                  |                                            | misinformation, miscommunication, legal issues, and security             |
|                                  |                                            | vulnerabilities due to incorrect or inappropriate content generated by   |
|                                  |                                            | LLMs.                                                                    |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| owasp:llm10                      | LLM10: Model Theft                         | This involves unauthorized access, copying, or exfiltration of           |
|                                  |                                            | proprietary LLM models. The impact includes economic losses, compromised |
|                                  |                                            | competitive advantage, and potential access to sensitive information.    |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+

AVID Effects
------------
The `AI Vulnerability Database`_ (AVID) is an open-source knowledge base and taxonomy for documenting observed failures and vulnerabilities in AI systems.
AVID organizes issues across areas such as security, ethics, and performance, helping practitioners classify findings consistently and relate them to known AI failure modes and other risk frameworks.

.. _AI Vulnerability Database: https://avidml.org/

Relevant Tags
~~~~~~~~~~~~~
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0100       | Software Vulnerability                     | Vulnerability in system around model—a traditional vulnerability         |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0200       | Supply Chain Compromise                    | Compromising development components of a ML model, e.g. data, model,     |
|                                  |                                            | hardware, and software stack.                                            |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0201       | Model Compromise                           | Infected model file                                                      |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0202       | Software compromise                        | Upstream Dependency Compromise                                           |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0300       | Over-permissive API                        | Unintended information leakage through API                               |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0301       | Information Leak                           | Cloud Model API leaks more information than it needs to                  |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0302       | Excessive Queries                          | Cloud Model API isn’t sufficiently rate limited                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0400       | Model Bypass                               | Intentionally try to make a model perform poorly                         |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0401       | Bad Features                               | The model uses features that are easily gamed by the attacker            |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0402       | Insufficient Training Data                 | The bypass is not represented in the training data                       |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0403       | Adversarial Example                        | Input data points intentionally supplied to draw mispredictions.         |
|                                  |                                            | Potential Cause: Over permissive API                                     |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0500       | Exfiltration                               | Directly or indirectly exfiltrate ML artifacts                           |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0501       | Model inversion                            | Reconstruct training data through strategic queries                      |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0502       | Model theft                                | Extract model functionality through strategic queries                    |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0600       | Data poisoning                             | Usage of poisoned data in the ML pipeline                                |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:security:S0601       | Ingest Poisoning                           | Attackers inject poisoned data into the ingest pipeline                  |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:ethics:E0100         | Bias/Discrimination                        | Concerns of algorithms propagating societal bias                         |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:ethics:E0101         | Group fairness                             | Fairness towards specific groups of people                               |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:ethics:E0102         | Individual fairness                        | Fairness in treating similar individuals                                 |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:ethics:E0200         | Explainability                             | Ability to explain decisions made by AI                                  |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:ethics:E0201         | Global explanations                        | Explain overall functionality                                            |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:ethics:E0202         | Local explanations                         | Explain specific decisions                                               |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:ethics:E0300         | User actions                               | Perpetuating/causing/being affected by negative user actions             |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:ethics:E0301         | Toxicity                                   | Users hostile towards other users                                        |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:ethics:E0302         | Polarization/ Exclusion                    | User behavior skewed in a significant direction                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:ethics:E0400         | Misinformation                             | Perpetuating/causing the spread of falsehoods                            |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:ethics:E0401         | Deliberative Misinformation                | Generated by individuals., e.g. vaccine disinformation                   |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:ethics:E0402         | Generative Misinformation                  | Generated algorithmically, e.g. Deep Fakes                               |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0100    | Data issues                                | Problems arising due to faults in the data pipeline                      |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0101    | Data drift                                 | Input feature distribution has drifted                                   |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0102    | Concept drift                              | Output feature/label distribution has drifted                            |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0103    | Data entanglement                          | Cases of spurious correlation and proxy features                         |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0104    | Data quality issues                        | Missing or low-quality features in data                                  |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0105    | Feedback loops                             | Unaccounted for effects of an AI affecting future data collection        |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0200    | Model issues                               | Ability for the AI to perform as intended                                |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0201    | Resilience/stability                       | Ability for outputs to not be affected by small change in inputs         |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0202    | OOD generalization                         | Test performance doesn’t deteriorate on unseen data in training          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0203    | Scaling                                    | Training and inference can scale to high data volumes                    |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0204    | Accuracy                                   | Model performance accurately reflects realistic expectations             |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0300    | Privacy                                    | Protect leakage of user information as required by rules and regulations |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0301    | Anonymization                              | Protects through anonymizing user identity                               |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0302    | Randomization                              | Protects by injecting noise in data, eg. differential privacy            |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0303    | Encryption                                 | Protects through encrypting data accessed                                |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0400    | Safety                                     | Minimizing maximum downstream harms                                      |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0401    | Psychological Safety                       | Safety from unwanted digital content, e.g. NSFW                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0402    | Physical safety                            | Safety from physical actions driven by a AI system                       |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0403    | Socioeconomic safety                       | Safety from socioeconomic harms, e.g. harms to job prospects or social   |
|                                  |                                            | status                                                                   |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| avid-effect:performance:P0404    | Environmental safety                       | Safety from environmental harms driven by AI systems                     |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+

Language Model Risk Cards
-------------------------
`Language Model Risk Cards`_ provide a structured way to document risks associated with a language model or its deployment context.
Each RiskCard describes how a risk can lead to harm, relates it to broader harm taxonomies, and can include representative prompt-and-output examples, making the framework useful for evaluating and communicating risks that may depend heavily on how a model is used.

.. _Language Model Risk Cards: https://arxiv.org/abs/2303.18190

Relevant Tags
~~~~~~~~~~~~~
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:aggression_user  | Aggression User                            | Aggression User                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:anthropomorphisa | Anthropomorphisation                       | Anthropomorphisation                                                     |
| tion                             |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:astroturfing     | Astroturfing                               | Astroturfing                                                             |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:bad_medical_advi | Bad Medical Advice                         | Bad Medical Advice                                                       |
| ce                               |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:bad_social_advic | Bad Social Advice                          | Bad Social Advice                                                        |
| e                                |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:bullying         | Bullying                                   | Bullying                                                                 |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:calls_for_conver | Calls For Conversion                       | Calls For Conversion                                                     |
| sion                             |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:challenge_presup | Challenge Presuppositions                  | Challenge Presuppositions                                                |
| positions                        |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:conspiracy_theor | Conspiracy Theories                        | Conspiracy Theories                                                      |
| ies                              |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:csam             | Csam                                       | Csam                                                                     |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:cyber_weapon_ins | Cyber Weapon Instructions                  | Cyber Weapon Instructions                                                |
| tructions                        |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:deadnaming       | Deadnaming                                 | Deadnaming                                                               |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:deceptive_anthro | Deceptive Anthropomorphism                 | Deceptive Anthropomorphism                                               |
| pomorphism                       |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:demands_for_pers | Demands For Personal Information           | Demands For Personal Information                                         |
| onal_information                 |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:discrediting     | Discrediting                               | Discrediting                                                             |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:dos              | Dos                                        | Dos                                                                      |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:downplaying_cred | Downplaying Credible Threats               | Downplaying Credible Threats                                             |
| ible_threats                     |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:doxxing          | Doxxing                                    | Doxxing                                                                  |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:eating_disorder_ | Eating Disorder Promotion                  | Eating Disorder Promotion                                                |
| promotion                        |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:essentialising   | Essentialising                             | Essentialising                                                           |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:expressions_of_d | Expressions Of Dominance                   | Expressions Of Dominance                                                 |
| ominance                         |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:fear_of_violence | Fear Of Violence                           | Fear Of Violence                                                         |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:grooming_minors  | Grooming Minors                            | Grooming Minors                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:harmful_instruct | Harmful Instructions                       | Harmful Instructions                                                     |
| ions                             |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:hate_speech      | Hate Speech                                | Hate Speech                                                              |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:hegemonising_wor | Hegemonising Worldview                     | Hegemonising Worldview                                                   |
| ldview                           |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:holocaust_denial | Holocaust Denial                           | Holocaust Denial                                                         |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:identify_attacks | Identify Attacks                           | Identify Attacks                                                         |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:identity_misrepr | Identity Misrepresentation                 | Identity Misrepresentation                                               |
| esentation                       |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:idolisation      | Idolisation                                | Idolisation                                                              |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:impersonation    | Impersonation                              | Impersonation                                                            |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:inciting_animal_ | Inciting Animal Abuse                      | Inciting Animal Abuse                                                    |
| abuse                            |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:inciting_self-ha | Inciting Self-Harm                         | Inciting Self-Harm                                                       |
| rm                               |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:inciting_violenc | Inciting Violence                          | Inciting Violence                                                        |
| e                                |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:manipulation     | Manipulation                               | Manipulation                                                             |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:misquoting       | Misquoting                                 | Misquoting                                                               |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:mocking_people   | Mocking People                             | Mocking People                                                           |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:neosexism        | Neosexism                                  | Neosexism                                                                |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:news_encyclopedi | News Encyclopedia Hallucination            | News Encyclopedia Hallucination                                          |
| a_hallucination                  |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:nonrepresentativ | Nonrepresentativity                        | Nonrepresentativity                                                      |
| ity                              |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:objectification  | Objectification                            | Objectification                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:outdated_false_i | Outdated False Info                        | Outdated False Info                                                      |
| nfo                              |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:person_group_und | Person Group Undesirable                   | Person Group Undesirable                                                 |
| esirable                         |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:positive_reflect | Positive Reflections Death                 | Positive Reflections Death                                               |
| ions_death                       |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:profanity        | Profanity                                  | Profanity                                                                |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:prompt_extractio | Prompt Extraction                          | Prompt Extraction                                                        |
| n                                |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:providing_illega | Providing Illegal Info                     | Providing Illegal Info                                                   |
| l_info                           |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:quack_medicine   | Quack Medicine                             | Quack Medicine                                                           |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:radicalisation   | Radicalisation                             | Radicalisation                                                           |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:reacting_to_self | Reacting To Self-Harm                      | Reacting To Self-Harm                                                    |
| -harm                            |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:sexual_content   | Sexual Content                             | Sexual Content                                                           |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:sexualisation    | Sexualisation                              | Sexualisation                                                            |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:slur_usage       | Slur Usage                                 | Slur Usage                                                               |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:speculation      | Speculation                                | Speculation                                                              |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:stereotypes      | Stereotypes                                | Stereotypes                                                              |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:suicide_instruct | Suicide Instructions                       | Suicide Instructions                                                     |
| ions                             |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:support_hate     | Support Hate                               | Support Hate                                                             |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:supporting_medic | Supporting Medication Changes              | Supporting Medication Changes                                            |
| ation_changes                    |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:support_scam     | Support Scam                               | Support Scam                                                             |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:suppression_of_r | Suppression Of Rights                      | Suppression Of Rights                                                    |
| ights                            |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:threats          | Threats                                    | Threats                                                                  |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:unproven_claims  | Unproven Claims                            | Unproven Claims                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:violation_of_pri | Violation Of Privacy                       | Violation Of Privacy                                                     |
| vacy                             |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:weapon_instructi | Weapon Instructions                        | Weapon Instructions                                                      |
| ons                              |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| risk-cards:lmrc:wrong_tone       | Wrong Tone                                 | Wrong Tone                                                               |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+

Common Weakness Enumeration
---------------------------
`Common Weakness Enumeration`_ (CWE) is a community-developed list of common software and hardware weakness types that **could** have security ramifications.
Although CWE is not specific to AI, it provides standardized identifiers and terminology for implementation-level security weaknesses, making it useful for classifying conventional software vulnerabilities found in AI applications, services, and supporting infrastructure.

.. _Common Weakness Enumeration: https://cwe.mitre.org/

Relevant Tags
~~~~~~~~~~~~~
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| cwe:79                           | Improper Neutralization of Input During    | The product does not neutralize or incorrectly neutralizes               |
|                                  | Web Page Generation ('Cross-site           | user-controllable input before it is placed in output that is used as a  |
|                                  | Scripting')                                | web page that is served to other users.                                  |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| cwe:89                           | Improper Neutralization of Special         | The product constructs all or part of an SQL command using               |
|                                  | Elements used in an SQL Command            | externally-influenced input from an upstream component, but it does not  |
|                                  |                                            | neutralize or incorrectly neutralizes special elements that could modify |
|                                  |                                            | the intended SQL command when it is sent to a downstream component.      |
|                                  |                                            | Without sufficient removal or quoting of SQL syntax in user-controllable |
|                                  |                                            | inputs, the generated SQL query can cause those inputs to be interpreted |
|                                  |                                            | as SQL instead of ordinary user data.                                    |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| cwe:94                           | Improper Control of Generation of Code     | The product constructs all or part of a code segment using               |
|                                  | ('Code Injection')                         | externally-influenced input from an upstream component, but it does not  |
|                                  |                                            | neutralize or incorrectly neutralizes special elements that could modify |
|                                  |                                            | the syntax or behavior of the intended code segment.                     |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| cwe:95                           | Improper Neutralization of Directives in   | The product receives input from an upstream component, but it does not   |
|                                  | Dynamically Evaluated Code ('Eval          | neutralize or incorrectly neutralizes code syntax before using the input |
|                                  | Injection')                                | in a dynamic evaluation call (e.g. "eval").                              |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| cwe:1336                         | Improper Neutralization of Special         | The product uses a template engine to insert or process                  |
|                                  | Elements Used in a Template Engine         | externally-influenced input, but it does not neutralize or incorrectly   |
|                                  |                                            | neutralizes special elements or syntax that can be interpreted as        |
|                                  |                                            | template expressions or other code directives when processed by the      |
|                                  |                                            | engine.                                                                  |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| cwe:1426                         | Improper Validation of Generative AI       | The product invokes a generative AI/ML component whose behaviors and     |
|                                  | Output                                     | outputs cannot be directly controlled, but the product does not validate |
|                                  |                                            | or insufficiently validates the outputs to ensure that they align with   |
|                                  |                                            | the intended security, content, or privacy policy.                       |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| cwe:1427                         | Improper Neutralization of Input Used for  | The product uses externally-provided data to build prompts provided to   |
|                                  | LLM Prompting                              | large language models (LLMs), but the way these prompts are constructed  |
|                                  |                                            | causes the LLM to fail to distinguish between user-supplied inputs and   |
|                                  |                                            | developer provided system directives.                                    |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| cwe:352                          | Cross-Site Request Forgery (CSRF)          | The web application does not, or cannot, sufficiently verify whether a   |
|                                  |                                            | request was intentionally provided by the user who sent the request,     |
|                                  |                                            | which could have originated from an unauthorized actor.                  |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+

Summon a Demon and Bind It
--------------------------
`Summon a Demon and Bind It`_ presents an empirically grounded framework for understanding how practitioners red-team large language models.
Based on interviews with red-teamers, the research characterizes LLM red teaming as a limit-seeking, largely manual activity and identifies 12 attack strategies and 35 techniques, providing a useful basis for designing adversarial tests that probe model behavior and attempt to elicit failures or bypass safeguards.

.. _Summon a Demon and Bind It: https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0314658

Relevant Tags
~~~~~~~~~~~~~
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Language:Code_and_encode:P | Programming                                | Encapsulate request in code/pseudocode                                   |
| rogramming                       |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Language:Code_and_encode:D | Data encoding                              | Use an encoded representation for the request, e.g. base64 or ROT13      |
| ata_encoding                     |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Language:Code_and_encode:D | Data presentation                          | Switch to an alternative layer for input represented, e.g. token IDs or  |
| ata_presentation                 |                                            | a matrix of embeddings                                                   |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Language:Code_and_encode:T | Token                                      | Use tokenizer-specific weaknesses to alter target behaviour              |
| oken                             |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Language:Prompt_injection: | Ignore previous instructions               | Concatenating untrusted user input with the trusted prompt(s) from the   |
| Ignore_previous_instructions     |                                            | system developers                                                        |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Language:Prompt_injection: | Strong arm attack                          | Use intensifiers and strong instructions                                 |
| Strong_arm_attack                |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Language:Prompt_injection: | Stop sequences                             | Using the language of code to halt the model's direction of processing   |
| Stop_sequences                   |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Language:Stylizing:Formal_ | Formal language                            | Write from a position of authority                                       |
| language                         |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Language:Stylizing:Servile | Servile language                           | Employ servile language                                                  |
| _language                        |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Language:Stylizing:Synonym | Synonymous language                        | Varying prompt slightly in form but not meaning                          |
| ous_language                     |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Language:Stylizing:Capital | Capitalizing                               | USING CAPS                                                               |
| izing                            |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Language:Stylizing:Give_ex | Give examples                              | Issue examples of the target behaviour in the attack itself              |
| amples                           |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Rhetoric:Persuasion_and_ma | Distraction                                | Use an unrelated context or instruction to “slip something through the   |
| nipulation:Distraction           |                                            | filter”                                                                  |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Rhetoric:Persuasion_and_ma | Escalating                                 | Attempting to have target “agree” with a very small part of the          |
| nipulation:Escalating            |                                            | argument, and then building up to ask for slightly more                  |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Rhetoric:Persuasion_and_ma | Reverse psychology                         | Framing the intent as fighting the good fight                            |
| nipulation:Reverse_psychology    |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Rhetoric:Socratic_question | Identity characteristics                   | Referencing identity characteristics, such as nationalities, cultural    |
| ing:Identity_characteristics     |                                            | and/or religious symbols, historically or culturally significant events  |
|                                  |                                            | or locations, physical attribute                                         |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Rhetoric:Socratic_question | Social hierarchies                         | Reference social hierarchies while posing the request                    |
| ing:Social_hierarchies           |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Possible_worlds:Emulation: | Unreal computing                           | Emulation of a computing device                                          |
| Unreal_computing                 |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Possible_worlds:World_buil | Opposite world                             | Describe an opposite world as part of the request                        |
| ding:Opposite_world              |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Possible_worlds:World_buil | Scenarios                                  | Create scenarios where intent would be ethically sound or encouraged, or |
| ding:Scenarios                   |                                            | non-compliance risks harm                                                |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Fictionalizing:Switching_g | Poetry                                     | Framing request or response as a poem or other verse                     |
| enres:Poetry                     |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Fictionalizing:Switching_g | Games                                      | Framing request as part of a game                                        |
| enres:Games                      |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Fictionalizing:Switching_g | Posting                                    | Framing request as help writing a post or other subsuming content        |
| enres:Posting                    |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Fictionalizing:Re-storying | Goal hijacking                             | Constructing a new meaning from an existing narrative, where the         |
| :Goal_hijacking                  |                                            | attacker works within a context to redirect the narrative                |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Fictionalizing:Roleplaying | Claim authority                            | State in prose that one is a figure of authority when requesting         |
| :Claim_authority                 |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Fictionalizing:Roleplaying | DAN and target persona                     | Ask target to evoke personas that don't have restrictions                |
| :DAN_and_target_persona          |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Fictionalizing:Roleplaying | User persona                               | Inventing personas to elicit different behavior. May be evoked by simply |
| :User_persona                    |                                            | using names associated with a specific culture or world view             |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Stratagems:Scattershot:Reg | Regenerate response                        | Repeatedly eliciting a response in case target slips up                  |
| enerate_response                 |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Stratagems:Scattershot:Cle | Clean slate                                | Resetting context by e.g. starting a new session                         |
| an_slate                         |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Stratagems:Scattershot:Cha | Changing hyperparams                       | Adjusting generation params, e.g. temperature                            |
| nging_hyperparams                |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Stratagems:Meta-prompting: | Perspective-shifting                       | Hypotheticals by shifting new point of view, e.g. “what if you didn’t    |
| Perspective-shifting             |                                            | have this restriction? What would you say?”, or asking target to compare |
|                                  |                                            | outputs and clarify gap                                                  |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| demon:Stratagems:Meta-prompting: | Ask for examples                           | Request examples of intended behaviour                                   |
| Ask_for_examples                 |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+

EU AI Act
---------
The `EU AI Act`_ is a regulatory framework that establishes risk-based requirements for developing, providing, and deploying AI systems in the European Union.
It distinguishes among different levels and types of AI risk, prohibits certain practices, imposes requirements on high-risk systems, establishes transparency obligations, and introduces additional requirements for general-purpose AI models, including provisions related to evaluation, risk management, adversarial testing, and cybersecurity for models with systemic risk.

.. _EU AI Act: https://artificialintelligenceact.eu/

Relevant Tags
~~~~~~~~~~~~~
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| euai:discrimination:protected_cl | Protected Class Discrimination             | Discrimination against a protected class (age, race, sex, etc.)          |
| ass                              |                                            |                                                                          |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| euai:discrimination:personal     | Personal Attribute Discrimination          | Discrimination based on non-protected personal attributes                |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| euai:harmful:violence            | Violent Language                           | Generation of violent content                                            |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| euai:harmful:sexual              | Sexual Language                            | Generation of sexual content                                             |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| euai:harmful:sexualminor         | Sexual Language (Minor)                    | Generation of sexual content featuring minors                            |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| euai:offensive:exploitation      | Vulnerability Exploitation                 | Exploitation of software vulnerabilties                                  |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| euai:offensive:phishing          | Phishing                                   | Assistance with phishing                                                 |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| euai:deception:subliminal        | Subliminal Deception                       | Manipulation via subliminal deception                                    |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| euai:deception:hallucination     | Hallucination Deception                    | Hallucinations related to factual information                            |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
| euai:harmful:pii                 | Personally Identifiable Information        | Production of personally identifiable information                        |
+----------------------------------+--------------------------------------------+--------------------------------------------------------------------------+
