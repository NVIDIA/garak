# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Retrieval of intents and intent stubs.

The intent service manages everything related to initialisation and enumeration of intents.
Intents are potential traits or failure modes of a target.
They could be things like 'produce hate speech', 'generate malware', or 'reveal training recipe'.
Each intent has on or more "stubs", which are prototypical requests.
Stubs should begin with a verb, like the three example instructions above.

See also: :doc:`../intents/base` for more on ``Intent`` and ``Stub``.

The intent service is responsible for tasks such as:

- loading the intent typology
- selecting intents to be passed to other classes
- managing the set of intents active within a run
- supplying stubs for probes

The service loads at garak startup, and based on the active configuration, identifies a set of intents that may be provided to requesting code.
This requesting code is typically probes, asking which intents they should attempt to apply.

The intent service is also responsible for summoning stubs to be presented as representations of an intent.
These can come from the intent typology, from text, from YAML or JSON (both of which support single-line and conversational stubs), and in code. The entry point for this stub assembly is :py:meth:`get_intent_stubs`.

To check the quality of the intents present in the system, see ``tools.cas.intent_quality``.
"""

import importlib
import json
import logging
from typing import List, Set
import yaml

import garak._config
import garak.data
from garak._spec import validate_intent_specifier, DEFAULT_INTENT_SCOPE
from garak.exception import GarakException
from garak.intents import Stub, TextStub, ConversationStub

cas_data_path = garak.data.path / "cas"
stub_dir = cas_data_path / "intent_stubs"

is_loaded = False
intent_typology = {}
intent_detectors = {}
intents_active = set()

INTENT_PREFIX = "🎯"


def start_msg() -> tuple[str, str]:
    """return a start message, assumes enabled"""
    return INTENT_PREFIX, "loading intent service"


def enabled() -> bool:
    """are requirements met for intent service to be enabled"""
    """we may want to predicate this on config"""
    if not garak._config.is_loaded:
        logging.warning("_config must be loaded before intentservice is started")
        return False
    return True


def _load_intent_typology(intents_path=None) -> None:
    """load intent typology into service object"""
    global intent_typology
    if intents_path is None:
        intents_path = cas_data_path / "trait_typology.json"
    with open(intents_path, "r", encoding="utf-8") as intents_file:
        intent_typology = json.load(intents_file)


def _load_intent_detector_mapping(detectors_path=None) -> None:
    """load 1:* intent:detectors mapping into service object"""
    global intent_detectors
    if detectors_path is None:
        detectors_path = cas_data_path / "intent_detectors.json"
    with open(detectors_path, "r", encoding="utf-8") as intent_detectors_file:
        intent_detectors = json.load(intent_detectors_file)


def _expand_intent_spec(
    intent_spec: str | None, expand_subnodes: bool = True
) -> Set[str]:
    """expand an intent spec. expand_subnodes controls whether the
    intent typology is used to expand non-leaf intent IDs to include
    child nodes."""

    expanded_intents = set()

    if intent_spec in (None, "*", "all", ""):
        expanded_intents.update(intent_typology.keys())
    else:
        for intent_prefix in intent_spec.split(","):
            if expand_subnodes:
                expanded_intents.update(
                    _expand_intent_specifier_children(intent_prefix)
                )
            else:
                expanded_intents.update({intent_prefix})

    return expanded_intents


def _expand_intent_specifier_children(intent_specifier: str) -> Set[str]:
    """expand an intent specified into itself plus child nodes"""

    intent_codes_to_lookup = set([intent_specifier])
    with open(cas_data_path / "intent_skip.json") as skip_f:
        intents_to_skip = json.load(skip_f)

    # expand intent codes
    if len(intent_specifier) <= 4:
        for code in intent_typology.keys():
            if code.startswith(intent_specifier):
                if code not in intents_to_skip:
                    intent_codes_to_lookup.add(code)

    return intent_codes_to_lookup


def _validate_intent_codes(intent_spec: str | None) -> None:
    """Fail-closed when a requested include code is well-formed but absent from
    the loaded typology (e.g. ``S999``). Vacuous specs (``None``/``*``/``all``/
    ``""``) select everything and are not validated."""

    if intent_spec in (None, "*", "all", ""):
        return
    for code in (c.strip() for c in intent_spec.split(",")):
        if code and code not in intent_typology:
            raise GarakException(
                f"intent code '{code}' is not in the loaded intent typology"
            )


def _populate_intents(intent_spec: str | None, blocked_spec: str | None = "") -> None:
    """Set the active intents from an include spec minus a blocked spec.

    Both are comma-separated typology codes or prefixes. Requested include codes
    must exist in the loaded typology (fail-closed). Non-leaf codes expand to
    their children when ``run.expand_intent_tree`` is set; intents without a
    mapped detector are dropped unless ``run.serve_detectorless_intents``."""

    global intents_active

    _validate_intent_codes(intent_spec)

    if intent_spec in (None, "*", "all", ""):
        intents_active = _expand_intent_spec(intent_spec)
    else:
        intents_active = _expand_intent_spec(
            intent_spec, expand_subnodes=garak._config.run.expand_intent_tree
        )

    if blocked_spec:
        blocked = _expand_intent_spec(blocked_spec, expand_subnodes=True)
        if not (intents_active & blocked):
            logging.debug(
                "run.spec: no active intent to remove for -intent spec %r", blocked_spec
            )
        intents_active.difference_update(blocked)

    if not garak._config.run.serve_detectorless_intents:
        detectorless_intents = set()
        for intent_code in intents_active:
            if get_detectors(intent_code, override_loaded_check=True) is None:
                detectorless_intents.add(intent_code)
        intents_active.difference_update(detectorless_intents)

    if len(intents_active) == 0:
        logging.info("Intent service running with no intents active")

    else:
        msg = "intents active: " + ", ".join(sorted(list(intents_active)))
        logging.info(msg)
        print(INTENT_PREFIX, msg)


def load():
    """load the intentservice.

    The active intents come from the resolved ``run.spec`` (``intent:`` axis),
    stashed on ``_config.transient`` by the CLI. When that is absent (e.g. a
    direct service load that did not resolve a spec), fall back to
    :data:`garak._spec.DEFAULT_INTENT_SCOPE`."""
    global is_loaded
    _load_intent_typology()
    _load_intent_detector_mapping()
    intent_spec = getattr(garak._config.transient, "intent_spec", None)
    blocked_spec = getattr(garak._config.transient, "blocked_intent_spec", None)
    if intent_spec is None:
        intent_spec = DEFAULT_INTENT_SCOPE
    _populate_intents(intent_spec, blocked_spec or "")
    is_loaded = True


def _get_stubs_typology(intent_code: str) -> Set[Stub]:
    """get stubs for an intent based on its configured default_stub"""

    raw_stub = intent_typology.get(intent_code, {}).get("default_stub")
    if not raw_stub:
        return set()

    stubs = set([TextStub(intent_code, raw_stub)])
    return stubs


def _glob_stubs(intent_code: str, suffix_expr: str):
    """find filenames for text stub files"""
    stub_glob = set()
    stub_glob.update(stub_dir.glob(f"{intent_code}.{suffix_expr}"))
    stub_glob.update(stub_dir.glob(f"{intent_code}_*.{suffix_expr}"))
    return stub_glob


def _get_stubs_txt(intent_code: str) -> Set[Stub]:
    """get stubs for an intent based on text files, one stub per line"""

    # search path: cas/intent_text/xxx_*.txt
    stub_glob = _glob_stubs(intent_code, "txt")

    stubs = set()
    for stub_file_path in stub_glob:
        if stub_file_path.exists():
            logging.info("intents: loading from %s" % stub_file_path)
            with open(stub_file_path, "r", encoding="utf-8") as sf:
                for line in sf:
                    stubs.add(TextStub(intent_code, line.strip()))

    return stubs


def _get_stubs_json(intent_code: str) -> Set[Stub]:
    """get intent stubs generated by an Intent class"""

    stub_glob = _glob_stubs(intent_code, "json")

    stubs = set()
    for stub_file_path in stub_glob:
        if stub_file_path.exists():
            logging.info("intents: loading stubs from %s" % stub_file_path)
            with open(stub_file_path, "r", encoding="utf-8") as sf:
                stub_src_obj = json.load(sf)
                if not isinstance(stub_src_obj, list):  # support list of strings
                    logging.warning(
                        "%s top-level item needs to be a list" % stub_file_path
                    )
                else:
                    for stub_obj_entry in stub_src_obj:
                        if isinstance(stub_obj_entry, str):
                            stubs.add(TextStub(intent_code, stub_obj_entry))
                        else:
                            logging.warning(
                                "skipping stub entry %s", repr(stub_obj_entry)
                            )

    return stubs


def _get_stubs_yaml(intent_code: str) -> Set[Stub]:
    """get stubs of prompts or conversations, in yaml format"""

    # openai api format conversations

    stub_glob = _glob_stubs(intent_code, "y*ml")

    stubs = set()
    for stub_file_path in stub_glob:
        if stub_file_path.exists():
            logging.info("intents: loading stubs from %s" % stub_file_path)
            with open(stub_file_path, "r", encoding="utf-8") as yf:
                stub_src_obj = yaml.safe_load(yf.read())
                if not isinstance(stub_src_obj, list):  # support list of strings
                    logging.warning(
                        "%s top-level item needs to be a list" % stub_file_path
                    )
                else:
                    for stub_obj_entry in stub_src_obj:
                        if isinstance(stub_obj_entry, str):
                            stubs.add(TextStub(intent_code, stub_obj_entry))
                        else:
                            logging.warning(
                                "skipping stub entry %s", repr(stub_obj_entry)
                            )
    return stubs


def _get_stubs_code(intent_code: str) -> Set[Stub]:
    """get intent stubs generated by an Intent class"""

    if not garak._config.run.trust_code_stubs:  # default false
        return set()

    if len(intent_code) <= 4:  # code only supported for fully-specified intents
        return set()

    module_name = intent_code[:4]
    class_name = intent_code[4:].capitalize()

    try:
        module_name = f"garak.intents.{module_name}"
        logging.info("intents: loading from %s.%s" % (module_name, class_name))
        intent_module = importlib.import_module(module_name)
        intent = getattr(intent_module, class_name)()
        stubs = intent.stubs()

    except (ModuleNotFoundError, AttributeError):
        stubs = set()

    return stubs


def get_intent_parts(intent_specifier: str) -> List[str]:
    """separate an intent specifier into its consituent parts:

    X999aaa - X is top-level code, 999 is a three-digit category,
    aaa is a text name for a leaf subcategory"""

    parts = []
    parts.append(intent_specifier[0])

    if len(intent_specifier) >= 4:
        parts.append(intent_specifier[0:4])
    if len(intent_specifier) > 4:
        parts.append(intent_specifier)

    return parts


def get_applicable_intents(blocked_spec: str | None = None) -> Set[str]:
    """return the set of intents configured in the service, minus those
    in block_spec (and its items' children), optionally minus those for
    which there are no detectors configured"""

    if not is_loaded:
        raise GarakException(
            "get_applicable_intents called on non-loaded intentservice"
        )

    applicable_intents = set(intents_active)

    # expand blocked spec, including leaves
    blocked_intents = set()
    if blocked_spec is not None and blocked_spec:  # don't expand the whole set
        blocked_intents = _expand_intent_spec(blocked_spec, expand_subnodes=True)

    # remove blocked items from active intents
    for blocked_intent in blocked_intents:
        if blocked_intent in applicable_intents:
            applicable_intents.remove(blocked_intent)

    # return remaining intents, no expansion
    return applicable_intents


def get_intent_stubs(intent_code: str, text_only=True, conv_only=False) -> Set[Stub]:
    """retrieve a list of intent strings given an intent code (doesn't have to be a leaf)"""

    if not is_loaded:
        raise GarakException("get_intent_stubs called on non-loaded intentservice")

    if not validate_intent_specifier(intent_code):  # data sanitation before fs access
        raise ValueError("Not a valid intent code: " + intent_code)

    if not intent_code in intent_typology:
        raise ValueError("Intent code not in loaded typology: " + intent_code)

    stubs = set()
    # retrieve intent stubs
    stubs.update(_get_stubs_typology(intent_code))
    stubs.update(_get_stubs_txt(intent_code))
    stubs.update(_get_stubs_code(intent_code))
    stubs.update(_get_stubs_json(intent_code))
    stubs.update(_get_stubs_yaml(intent_code))

    # filter to requested type
    if text_only:
        stubs = set(filter(lambda s: isinstance(s, TextStub), stubs))

    if conv_only:
        stubs = set(filter(lambda s: isinstance(s, ConversationStub), stubs))

    # a leaf intent with no stubs cannot be exercised; surface the gap
    if not stubs and len(intent_code) > 4:
        logging.warning("intents: no stubs available for intent %s", intent_code)

    # return stubs
    return stubs


def get_detectors(
    intent_specifier: str, override_loaded_check=False
) -> Set[str] | None:
    """return the set of detectors applicable to a single intent"""

    if not is_loaded and not override_loaded_check:
        raise GarakException("intent_to_detectors called on non-loaded intentservice")

    intent_parts = get_intent_parts(intent_specifier)

    detectors = None
    while detectors == None and intent_parts:
        spec = intent_parts.pop()
        if spec in intent_detectors:
            detectors = intent_detectors[spec]

    return detectors
