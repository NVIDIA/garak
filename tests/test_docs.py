import importlib
from pathlib import Path
import re
import yaml

import pytest

TOP_PATHS = ["probes", "detectors", "harnesses", "generators", "evaluators", "buffs"]
DOC_SOURCE = Path("docs/source")

module_names = {}
for top_path in TOP_PATHS:
    module_names[top_path] = [
        i.name.replace(".py", "")
        for i in Path(f"garak/{top_path}").glob("*py")
        if not str(i).endswith("__init__.py")
    ]

ROOT_MODULES = list(Path("garak").glob("*py"))

MARKDOWN_CANARIES = set(
    [
        re.compile(r"(^|[^`!])\!?\[.+\]\((http|java).+\)"),  #  [link](http://link)
        re.compile(r"```"),  #  ```   (code block)
    ]
)


@pytest.mark.parametrize("category", TOP_PATHS)
def test_top_docs(category: str):
    file_path = DOC_SOURCE / f"garak.{category}.rst"
    assert (
        file_path.is_file()
    ), "Top level category %s needs to have docs in %s but file is absent" % (
        category,
        file_path,
    )
    assert file_path.stat().st_size > 0, "Top level doc %s cannot be blank" % file_path


@pytest.mark.parametrize("classname", module_names["probes"])
def test_docs_probes(classname: str):
    file_path = DOC_SOURCE / f"garak.probes.{classname}.rst"
    assert (
        file_path.is_file()
    ), f"There must be an entry for each probe family in the docs; missing {file_path}"
    assert (
        file_path.stat().st_size
    ), "plugin docs cannot be empty. you can just use a stub to read python docstrings, look at existing doc files"
    category_file = DOC_SOURCE / "probes.rst"
    target_doc = f"garak.probes.{classname}\n"
    assert (
        open(category_file, "r", encoding="utf-8").read().find(target_doc) != -1
    ), "probe docs must be linked to in probes.rst"


@pytest.mark.parametrize("classname", module_names["detectors"])
def test_docs_detectors(classname: str):
    file_path = DOC_SOURCE / f"garak.detectors.{classname}.rst"
    assert (
        file_path.is_file()
    ), f"There must be an entry for each detector family in the docs; missing {file_path}"
    assert (
        file_path.stat().st_size
    ), "plugin docs cannot be empty. you can just use a stub to read python docstrings, look at existing doc files"
    category_file = DOC_SOURCE / "detectors.rst"
    target_doc = f"garak.detectors.{classname}\n"
    assert (
        open(category_file, "r", encoding="utf-8").read().find(target_doc) != -1
    ), "detector docs must be linked to in detectors.rst"


@pytest.mark.parametrize("classname", module_names["harnesses"])
def test_docs_harnesses(classname: str):
    file_path = DOC_SOURCE / f"garak.harnesses.{classname}.rst"
    assert (
        file_path.is_file()
    ), f"There must be an entry for each harness family in the docs; missing {file_path}"
    assert (
        file_path.stat().st_size
    ), "plugin docs cannot be empty. you can just use a stub to read python docstrings, look at existing doc files"
    category_file = DOC_SOURCE / "harnesses.rst"
    target_doc = f"garak.harnesses.{classname}\n"
    assert (
        open(category_file, "r", encoding="utf-8").read().find(target_doc) != -1
    ), "harness docs must be linked to in harnesses.rst"


@pytest.mark.parametrize("classname", module_names["evaluators"])
def test_docs_evaluators(classname: str):
    file_path = DOC_SOURCE / f"garak.evaluators.{classname}.rst"
    assert (
        file_path.is_file()
    ), f"There must be an entry for each evaluator family in the docs; missing {file_path}"
    assert (
        file_path.stat().st_size
    ), "plugin docs cannot be empty. you can just use a stub to read python docstrings, look at existing doc files"
    category_file = DOC_SOURCE / "evaluators.rst"
    target_doc = f"garak.evaluators.{classname}\n"
    assert (
        open(category_file, "r", encoding="utf-8").read().find(target_doc) != -1
    ), "evaluator docs must be linked to in evaluators.rst"


@pytest.mark.parametrize("classname", module_names["generators"])
def test_docs_generators(classname: str):
    file_path = DOC_SOURCE / f"garak.generators.{classname}.rst"
    assert (
        file_path.is_file()
    ), f"There must be an entry for each generator family in the docs; missing {file_path}"
    assert (
        file_path.stat().st_size
    ), "plugin docs cannot be empty. you can just use a stub to read python docstrings, look at existing doc files"
    category_file = DOC_SOURCE / "generators.rst"
    target_doc = f"garak.generators.{classname}\n"
    assert (
        open(category_file, "r", encoding="utf-8").read().find(target_doc) != -1
    ), "generator docs must be linked to in generators.rst"


@pytest.mark.parametrize("classname", module_names["buffs"])
def test_docs_buffs(classname: str):
    file_path = DOC_SOURCE / f"garak.buffs.{classname}.rst"
    assert (
        file_path.is_file()
    ), f"There must be an entry for each buff family in the docs; missing {file_path}"
    assert (
        file_path.stat().st_size
    ), "plugin docs cannot be empty. you can just use a stub to read python docstrings, look at existing doc files"
    category_file = DOC_SOURCE / "buffs.rst"
    target_doc = f"garak.buffs.{classname}\n"
    assert (
        open(category_file, "r", encoding="utf-8").read().find(target_doc) != -1
    ), "buff docs must be linked to in buffs.rst"


from garak import _plugins

probes = [classname for (classname, active) in _plugins.enumerate_plugins("probes")]
detectors = [
    classname for (classname, active) in _plugins.enumerate_plugins("detectors")
]
generators = [
    classname for (classname, active) in _plugins.enumerate_plugins("generators")
]
harnesses = [
    classname for (classname, active) in _plugins.enumerate_plugins("harnesses")
]
buffs = [classname for (classname, active) in _plugins.enumerate_plugins("buffs")]
# commented out until enumerate_plugins supports evaluators
# evaluators = [
#    classname for (classname, active) in _plugins.enumerate_plugins("evaluators")
# ]
plugins = sorted(probes + detectors + generators + buffs)


@pytest.mark.parametrize("plugin_name", plugins)
def test_check_plugin_class_docstring(plugin_name: str):
    plugin_name_parts = plugin_name.split(".")
    module_name = "garak." + ".".join(plugin_name_parts[:-1])
    class_name = plugin_name_parts[-1]
    mod = importlib.import_module(module_name)
    doc = getattr(getattr(mod, class_name), "__doc__")
    assert isinstance(doc, str), "All plugin classes must have docstrings"
    assert len(doc) > 0, "Plugin class docstrings must not be empty"
    for canary in MARKDOWN_CANARIES:
        canary_match = canary.search(doc, re.I)
        assert (
            canary_match is None
        ), f"Markdown in docstring: '{canary_match.group().strip()}' - use ReStructured Text for garak docs"


PLUGIN_GROUPS = sorted(
    list(set([".".join(plugin_name.split(".")[:2]) for plugin_name in plugins]))
)


@pytest.mark.parametrize("plugin_group", PLUGIN_GROUPS)
def test_check_plugin_module_docstring(plugin_group: str):
    module_name = "garak." + plugin_group
    mod = importlib.import_module(module_name)
    doc = getattr(mod, "__doc__")
    assert isinstance(doc, str), "All plugin groups/modules must have docstrings"
    assert len(doc) > 0, "Plugin group/module docstrings must not be empty"
    for canary in MARKDOWN_CANARIES:
        canary_match = canary.search(doc, re.I)
        assert (
            canary_match is None
        ), f"Markdown in docstring: '{canary_match.group().strip()}' - use ReStructured Text for garak docs"


@pytest.fixture(scope="session")
def doc_index_source_text():
    return open(DOC_SOURCE / "index.rst", "r", encoding="utf-8").read()


@pytest.mark.parametrize("root_module", ROOT_MODULES)
def test_root_modules_docs(doc_index_source_text, root_module: str):
    if not root_module.name.startswith("__"):
        assert f"{root_module.stem}.rst" in [
            entry.name for entry in DOC_SOURCE.glob("*rst")
        ], f"root module {root_module.stem} must have documentation in {root_module.stem}.rst"
        assert (
            f" {root_module.stem}\n" in doc_index_source_text
        ), f"root module doc page for {root_module.name} should be linked from doc root index"


def test_core_config_options_explained():
    import garak._config

    core_config_file_name = (
        garak._config.transient.package_dir / "resources" / "garak.core.yaml"
    )
    l1_nodes_to_check = []
    l2_nodes_to_check = []

    with open(core_config_file_name, encoding="utf-8") as settings_file:
        settings = yaml.safe_load(settings_file)
        for top_level_setting in settings:
            l1_nodes_to_check.append(top_level_setting)
            for second_level_setting in settings[top_level_setting]:
                l2_nodes_to_check.append(second_level_setting)

    configurable_rst = open(
        DOC_SOURCE / "configurable.rst", "r", encoding="utf-8"
    ).read()

    for l1_node in l1_nodes_to_check:
        title_case_l1_node = f"\n{l1_node} Config Items\n".title()
        assert (
            title_case_l1_node in configurable_rst
        ), f"core config value '{l1_node}' must be documented in configurable.rst"

    for l2_node in l2_nodes_to_check:
        assert (
            f"\n* ``{l2_node}`` - " in configurable_rst
        ), f"core config value '{l2_node}' must be documented in configurable.rst"


@pytest.mark.parametrize("doc_source_entry", DOC_SOURCE.iterdir())
def test_doc_src_extensions(doc_source_entry):
    if doc_source_entry.is_file():
        if doc_source_entry.name not in ("Makefile", "conf.py"):
            assert doc_source_entry.suffix == ".rst", (
                "Doc entry %s should be a .rst file" % doc_source_entry
            )


RST_FILES = DOC_SOURCE.glob("*rst")


@pytest.mark.parametrize("rst_file", RST_FILES)
def test_doc_src_no_markdown(rst_file):
    rst_file_content = open(rst_file, "r", encoding="utf-8").read()
    for canary in MARKDOWN_CANARIES:
        canary_match = canary.search(rst_file_content, re.I)
        assert (
            canary_match is None
        ), f"Markdown-like content in rst: {result.group().strip()} use ReStructured Text for garak docs - Markdown won't render"
