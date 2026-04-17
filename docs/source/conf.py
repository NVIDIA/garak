# Configuration file for the Sphinx documentation builder.

# -- Project information
import datetime

project = "garak"
copyright = f"2023-{datetime.datetime.now().year}, NVIDIA Corporation. Content provided under Apache License 2.0."
author = "Leon Derczynski"

# -- General configuration

extensions = [
    "sphinx.ext.duration",
    "sphinx.ext.doctest",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "garak_ext",
    "sphinx_github_style",
    "sphinx_reredirects",
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3/", None),
    "sphinx": ("https://www.sphinx-doc.org/en/master/", None),
}
intersphinx_disabled_domains = ["std"]

templates_path = ["_templates"]
exclude_patterns = []

# -- Options for HTML output

html_theme = "sphinx_rtd_theme"

# These folders are copied to the documentation's HTML output
html_static_path = ["_static"]

# disable link to doc source
html_show_sourcelink = False

# These paths are either relative to html_static_path
# or fully qualified paths (eg. https://...)
html_css_files = [
    "css/garak_theme.css",
]

# -- Options for EPUB output
epub_show_urls = "footnote"

# -- options for github links
linkcode_link_text = "Source"
linkcode_url = "https://github.com/NVIDIA/garak"

# hide module paths
add_module_names = False
autodoc_preserve_defaults = False

# redirect dir indices
redirects = {
    "analyze/index": "../index_analyze.html",
    "buffs/index": "../index_buffs.html",
    "detectors/index": "../index_detectors.html",
    "evaluators/index": "../index_evaluators.html",
    "generators/index": "../index_generators.html",
    "harnesses/index": "../index_harnesses.html",
    "probes/index": "../index_probes.html",
    "analyze": "index_analyze.html",
    "buffs": "index_detectors.html",
    "detectors": "index_detectors.html",
    "evaluators": "index_evaluators.html",
    "generators": "index_generators.html",
    "harnesses": "index_harnesses.html",
    "probes": "index_probes.html",
    "garak.harnesses.probewise": "harnesses/probewise.html",
    "garak.harnesses.base": "harnesses/base.html",
    "garak.harnesses.pxd": "harnesses/pxd.html",
    "garak.evaluators.base": "evaluators/base.html",
    "garak.evaluators.maxrecall": "evaluators/maxrecall.html",
    "garak.analyze.tbsa": "analyze/tbsa.html",
    "garak.generators.guardrails": "generators/guardrails.html",
    "garak.generators.nvcf": "generators/nvcf.html",
    "garak.generators.test": "generators/test.html",
    "garak.generators.nim": "generators/nim.html",
    "garak.generators.openai": "generators/openai.html",
    "garak.generators.replicate": "generators/replicate.html",
    "garak.generators.huggingface": "generators/huggingface.html",
    "garak.generators.watsonx": "generators/watsonx.html",
    "garak.generators.websocket": "generators/websocket.html",
    "garak.generators.rest": "generators/rest.html",
    "garak.generators.base": "generators/base.html",
    "garak.generators.rasa": "generators/rasa.html",
    "garak.generators.ggml": "generators/ggml.html",
    "garak.generators.azure": "generators/azure.html",
    "garak.generators.litellm": "generators/litellm.html",
    "garak.generators.cohere": "generators/cohere.html",
    "garak.generators.langchain": "generators/langchain.html",
    "garak.generators.mistral": "generators/mistral.html",
    "garak.generators.function": "generators/function.html",
    "garak.generators.groq": "generators/groq.html",
    "garak.generators.ollama": "generators/ollama.html",
    "garak.generators.bedrock": "generators/bedrock.html",
    "garak.generators.langchain_serve": "generators/langchain_serve.html",
    "garak.buffs.base": "buffs/base.html",
    "garak.buffs.lowercase": "buffs/lowercase.html",
    "garak.buffs.paraphrase": "buffs/paraphrase.html",
    "garak.buffs.encoding": "buffs/encoding.html",
    "garak.buffs.low_resource_languages": "buffs/low_resource_languages.html",
    "garak.detectors.mitigation": "detectors/mitigation.html",
    "garak.detectors.misleading": "detectors/misleading.html",
    "garak.detectors.lmrc": "detectors/lmrc.html",
    "garak.detectors.always": "detectors/always.html",
    "garak.detectors.judge": "detectors/judge.html",
    "garak.detectors.apikey": "detectors/apikey.html",
    "garak.detectors.goodside": "detectors/goodside.html",
    "garak.detectors.unsafe_content": "detectors/unsafe_content.html",
    "garak.detectors.divergence": "detectors/divergence.html",
    "garak.detectors.leakreplay": "detectors/leakreplay.html",
    "garak.detectors.ansiescape": "detectors/ansiescape.html",
    "garak.detectors.any": "detectors/any.html",
    "garak.detectors.base": "detectors/base.html",
    "garak.detectors.knownbadsignatures": "detectors/knownbadsignatures.html",
    "garak.detectors.visual_jailbreak": "detectors/visual_jailbreak.html",
    "garak.detectors.encoding": "detectors/encoding.html",
    "garak.detectors.productkey": "detectors/productkey.html",
    "garak.detectors.malwaregen": "detectors/malwaregen.html",
    "garak.detectors.fileformats": "detectors/fileformats.html",
    "garak.detectors.exploitation": "detectors/exploitation.html",
    "garak.detectors.promptinject": "detectors/promptinject.html",
    "garak.detectors.perspective": "detectors/perspective.html",
    "garak.detectors.packagehallucination": "detectors/packagehallucination.html",
    "garak.detectors.shields": "detectors/shields.html",
    "garak.detectors.web_injection": "detectors/web_injection.html",
    "garak.detectors.continuation": "detectors/continuation.html",
    "garak.detectors.dan": "detectors/dan.html",
    "garak.detectors.snowball": "detectors/snowball.html",
    "garak.probes.sata": "probes/sata.html",
    "garak.probes.donotanswer": "probes/donotanswer.html",
    "garak.probes.misleading": "probes/misleading.html",
    "garak.probes.test": "probes/test.html",
    "garak.probes.lmrc": "probes/lmrc.html",
    "garak.probes.audio": "probes/audio.html",
    "garak.probes.apikey": "probes/apikey.html",
    "garak.probes.goodside": "probes/goodside.html",
    "garak.probes.realtoxicityprompts": "probes/realtoxicityprompts.html",
    "garak.probes.suffix": "probes/suffix.html",
    "garak.probes.doctor": "probes/doctor.html",
    "garak.probes.divergence": "probes/divergence.html",
    "garak.probes.leakreplay": "probes/leakreplay.html",
    "garak.probes.ansiescape": "probes/ansiescape.html",
    "garak.probes.base": "probes/base.html",
    "garak.probes.atkgen": "probes/atkgen.html",
    "garak.probes.tap": "probes/tap.html",
    "garak.probes.phrasing": "probes/phrasing.html",
    "garak.probes.glitch": "probes/glitch.html",
    "garak.probes.visual_jailbreak": "probes/visual_jailbreak.html",
    "garak.probes.encoding": "probes/encoding.html",
    "garak.probes.fitd": "probes/fitd.html",
    "garak.probes.topic": "probes/topic.html",
    "garak.probes.malwaregen": "probes/malwaregen.html",
    "garak.probes.fileformats": "probes/fileformats.html",
    "garak.probes.exploitation": "probes/exploitation.html",
    "garak.probes.promptinject": "probes/promptinject.html",
    "garak.probes.smuggling": "probes/smuggling.html",
    "garak.probes.av_spam_scanning": "probes/av_spam_scanning.html",
    "garak.probes.grandma": "probes/grandma.html",
    "garak.probes.packagehallucination": "probes/packagehallucination.html",
    "garak.probes.web_injection": "probes/web_injection.html",
    "garak.probes._tier": "probes/_tier.html",
    "garak.probes.badchars": "probes/badchars.html",
    "garak.probes.continuation": "probes/continuation.html",
    "garak.probes.dan": "probes/dan.html",
    "garak.probes.latentinjection": "probes/latentinjection.html",
    "garak.probes.dra": "probes/dra.html",
    "garak.probes.snowball": "probes/snowball.html",
}

import os
import sys

sys.path.insert(0, "../..")
sys.path.append(os.path.abspath("./_ext"))
