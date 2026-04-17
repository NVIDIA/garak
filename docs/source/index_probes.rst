Probes
======

garak's probes each define a number of ways of testing a generator (typically an LLM)
for a specific vulnerability or failure mode.

For a detailed oversight into how a probe operates, see :doc:`probes/base`.

For a guide to writing probes, see :doc:`extending.probe`.

.. toctree::
   :maxdepth: 2

   probes/ansiescape
   probes/apikey
   probes/atkgen
   probes/audio
   probes/av_spam_scanning
   probes/badchars
   probes/base
   probes/continuation
   probes/dan
   probes/divergence
   probes/doctor
   probes/donotanswer
   probes/dra
   probes/encoding
   probes/exploitation
   probes/fileformats
   probes/fitd
   probes/glitch
   probes/goodside
   probes/grandma
   probes/latentinjection
   probes/leakreplay
   probes/lmrc
   probes/malwaregen
   probes/misleading
   probes/packagehallucination
   probes/phrasing
   probes/promptinject
   probes/realtoxicityprompts
   probes/sata
   probes/snowball
   probes/smuggling
   probes/suffix
   probes/tap
   probes/test
   probes/topic
   probes/visual_jailbreak
   probes/web_injection
   probes/_tier
