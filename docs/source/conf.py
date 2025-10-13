# Configuration file for the Sphinx documentation builder.

# -- Project information
import datetime

project = "garak"
copyright = f"2023-{datetime.datetime.now().year}, NVIDIA Corporation"
author = "Leon Derczynski"
version: str = 'latest' # required by the version switcher

# -- General configuration

extensions = [
    "sphinx.ext.duration",
    "sphinx.ext.doctest",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "garak_ext"
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3/", None),
    "sphinx": ("https://www.sphinx-doc.org/en/master/", None),
}

intersphinx_disabled_domains = ["std"]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", "**.ipynb_checkpoints"]

# -- Options for HTML output

html_theme = "pydata_sphinx_theme"

html_theme_options = {
    "navbar_start": ["navbar-logo", "version-switcher"],
    "switcher": {
        "json_url": "https://raw.githubusercontent.com/NVIDIA/garak/refs/heads/main/docs/source/_static/switcher.json",
        "version_match": version
    },
}

html_sidebars = {
    "**": ["sidebar-nav-bs"],
}

# These folders are copied to the documentation's HTML output
html_static_path = ['_static']

# These paths are either relative to html_static_path
# or fully qualified paths (eg. https://...)
html_css_files = [
    "css/custom.css",
]

# -- Options for EPUB output
epub_show_urls = "footnote"

import os
import sys

sys.path.insert(0, "../..")
sys.path.append(os.path.abspath("./_ext"))
