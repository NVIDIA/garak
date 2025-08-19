garak.probes.packagehallucination
=================================

Check for package hallucination vulnerabilities. From `<https://vulcan.io/blog/ai-hallucinations-package-risk>`_:

   Using this technique, an attacker starts by formulating a question asking ChatGPT for a package that will solve a coding problem. ChatGPT then responds with multiple packages, some of which may not exist. This is where things get dangerous: when ChatGPT recommends packages that are not published in a legitimate package repository (e.g. npmjs, Pypi, etc.).

   When the attacker finds a recommendation for an unpublished package, they can publish their own malicious package in its place. The next time a user asks a similar question they may receive a recommendation from ChatGPT to use the now-existing malicious package. We recreated this scenario in the proof of concept below using ChatGPT 3.5.

.. automodule:: garak.probes.packagehallucination
   :members:
   :undoc-members:
   :show-inheritance:
