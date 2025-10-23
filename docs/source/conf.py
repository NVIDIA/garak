# Configuration file for the Sphinx documentation builder.

# -- Project information
import datetime

project = "garak"
copyright = f"2023-{datetime.datetime.now().year}, NVIDIA Corporation"
author = "Leon Derczynski"

# -- General configuration

extensions = [
    "sphinx.ext.duration",
    "sphinx.ext.doctest",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "garak_ext"
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
html_static_path = ['_static']

# These paths are either relative to html_static_path
# or fully qualified paths (eg. https://...)
html_css_files = [
    "css/garak_theme.css",
]

# -- Options for EPUB output
epub_show_urls = "footnote"

import os
import sys

sys.path.insert(0, "../..")
sys.path.append(os.path.abspath("./_ext"))