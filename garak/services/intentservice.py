# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Retrieval of intents and intent stubs."""

import importlib
import json
import logging
import re
from typing import List, Set
import yaml

import garak._config
import garak.data
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

    if intent_spec is None or intent_spec in ("*", "all", ""):
        expanded_intents = set(
            [
                non_top_intent
                for non_top_intent in intent_typology.keys()
                if len(non_top_intent) >= 4
            ]
        )
    else:
        for intent_prefix in intent_spec.split(","):
            if expand_subnodes:
                expanded_intents.update(_expand_intent_specifier_leaves(intent_prefix))
            else:
                expanded_intents.update({intent_prefix})

    return expanded_intents


def _populate_intents(intent_spec: str | None) -> None:
    """set the service's intents according to an intent spec and the
    loaded typology."""

    global intents_active

    if intent_spec is None or intent_spec in ("*", "all", ""):
        intents_active = _expand_intent_spec(intent_spec)
    else:
        intents_active = _expand_intent_spec(
            intent_spec, expand_subnodes=garak._config.cas.expand_intent_tree
        )

    if not garak._config.cas.serve_detectorless_intents:
        intents_with_detectors = set(
            [i for i in intent_detectors if intent_detectors[i]]
        )
        intents_active = intents_active.intersection(intents_with_detectors)

    if len(intents_active) == 0:
        logging.info("Intent service running with no intents active")

    else:
        msg = "intents active: " + ", ".join(sorted(list(intents_active)))
        logging.info(msg)
        print(INTENT_PREFIX, msg)


def load():
    """load the intentservice"""
    global is_loaded
    _load_intent_typology()
    _load_intent_detector_mapping()
    _populate_intents(garak._config.cas.intent_spec)
    is_loaded = True


def _get_stubs_typology(intent_code: str) -> Set[Stub]:
    """get stubs for an intent based on names & descriptions in the typology"""

    # return the descr of a given typology point, or if empty/absent, the name
    intent_details = intent_typology.get(intent_code, {})

    raw_stub = intent_details.get("descr")
    if not raw_stub:
        raw_stub = intent_details.get("name")

    stubs = set([TextStub(intent_code, raw_stub)])
    return stubs


def _glob_stubs(intent_code: str, suffix_expr: str):
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

    if not garak._config.cas.trust_code_stubs:  # default false
        return set()

    if len(intent_code) <= 4:  # code only supported for fully-specified intents
        return set()

    module_name = intent_code[:4]
    class_name = intent_code[4:].capitalize()

    try:
        module_name = f"garak.intents.{module_name}"
        logging.info("intents: loading from %s" % module_name)
        intent_module = importlib.import_module(module_name)
        intent = getattr(intent_module, class_name)()
        stubs = intent.stubs()

    except ModuleNotFoundError:
        stubs = set()

    return stubs


def validate_intent_specifier(intent_specifier: str) -> bool:
    """validate a single intent specifier"""
    return re.fullmatch("[CTMS]([0-9]{3}([a-z]+)?)?", intent_specifier) is not None


def _expand_intent_specifier_leaves(intent_specifier: str) -> List[str]:
    """expand an intent specified into itself plus child nodes"""

    intent_codes_to_lookup = [intent_specifier]
    with open(cas_data_path / "intent_skip.json") as skip_f:
        intent_leaves_to_skip = json.load(skip_f)

    # expand intent codes
    if len(intent_specifier) <= 4:
        for code in intent_typology.keys():
            if code.startswith(intent_specifier) and len(code) > 4:
                if code not in intent_leaves_to_skip:
                    intent_codes_to_lookup.append(code)

    return intent_codes_to_lookup


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

    # intent_codes_to_lookup = _expand_intent_specifier_leaves(intent_specifier)

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

    # return stubs
    return stubs


def intent_to_detectors(intent_specifier: str) -> Set[str] | None:
    """return the set of detectors applicable to a single intent"""

    if not is_loaded:
        raise GarakException("intent_to_detectors called on non-loaded intentservice")

    intent_parts = get_intent_parts(intent_specifier)

    detectors = None
    while detectors == None and intent_parts:
        spec = intent_parts.pop()
        if spec in intent_detectors:
            detectors = intent_detectors[spec]

    return detectors
