# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

""" Context-Aware Scanning

Models are often deployed in systems. Those systems and contexts have varying requirements.
Context-aware scanning is garak's approach to recognising that variation, by supporting
different model traits and different attack intents. This includes the concept of a policy
that described which traits a model does and does not (or should and should not) exhibit.

Context-aware scanning is experimental and incomplete as of October 2025.

Policy in garak describes how a model behaves without using any adversarial techniques.
The idea is that in order to know that an attack makes a difference, we need to know
if the model will offer up the target behaviour when no adversarial technique is applied.
If we can get the target behaviour out-of-the-box, then we say that the model's *policy*
is to offer that behaviour.

We implement policy with two, separate concepts:
1. A set of functions/behaviours that models could potentially exhibit (traits)
2. Data on whether the target model exhibits each of these traits

The first comes from a typology, which is externally defined. There's some JSON that tracks
this. It's the categories of model behaviour we're interested in. This is not exhaustive and
not intended to be exhaustive - rather, it's constrained to model behaviours that have been
either helpful in aiding attacks, or the targets of attacks, in the literature, as well as
items that aligners have discussed.

The second is derived by testing each trait. We don't have complete tests for all the
points at launch; that's a lot of detectors, and a lot to validate.


Policy metadata
---------------
The total set of traits in the behaviour typology can be represented as a dictionary. 
Definitions of names, descriptions, and behaviours are stored in a JSON data file

* Key: trait identifier - format is TDDDs*
	* T: a top-level hierarchy code letter, in CTMS for chat/tasks/meta/safety
	* D: a three-digit code for this behaviour
	* s*: (optional) one or more letters identifying a trait

* Value: a dict describing a trait
    * “name”: A short name of what is permitted when this behaviour is allowed
    * “description”: (optional) a deeper description of this behaviour

The structure of the identifiers describes the hierarchical structure.

Nomenclature
------------
* ``trait`` - a behavioural trait of a model
* ``policy`` - a hierarchy of traits including descriptions of whether each trait should be enabled
* ``observed policy`` - a policy describing how the target was observed to behave
* ``policy point`` - any point in a policy. This subsumes traits and groups of traits
* ``trait typology`` - a structured set of traits, including and descriptions


Policy expectations / examples
------------------------------

We might like to define an example policy for an LLM. This can be done in JSON.

* Key: behaviour identifier
* Value: True if this is allowed, False if this is not allowed, None if no stance is taken

If leaf behaviours are not included, the parent's value is assumed to apply, rather than the leaf taking a default like None.

Denoting policy
---------------

Object: `Policy`

Methods: 
```
policy.permitted(trait) -> True/False/None
policy.compare(another_policy) -> list of policy points where there's a difference
policy.set(prefix, value) -> set prefix to value
policy.settree(prefix, value) -> set this and all sub-points in the policy to value
```

"""

import importlib
import json
import logging
import re
from typing import Union

from garak.data import path as data_path


""" Traits have a key describing where they fit in the behaviour typology.
* Key: behaviour identifier - format is TDDDs*
	* T: a top-level hierarchy code letter, in CTMS for chat/tasks/meta/safety
	* D: a three-digit code for this behaviour
	* s*: (optional) one or more letters identifying a sub-trait
"""

POLICY_POINT_CODE_RX = r"^[A-Z]([0-9]{3}([a-z]+)?)?$"


class Policy:
    """Type representing a model function/behaviour policy. Consists of
    a hierarchy of policy points, each of which can be allowed, disallowed,
    or have no policy set. Includes methods for loading the hierarchy, for
    altering the values within it, for populating a policy based on results
    describing how a target behaves, and for extracting values from the policy."""

    # policy.points[behaviour] -> dict of policy keys and True/False/None
    # policy.is_permitted[behaviour] -> True/False/None
    # policy.settree(prefix, value) -> set this and all sub-points in the policy to value
    # policy.parse_eval_result(eval_result) -> plug in to probes, load up results from an eval, build a policy
    # policy.compare(policy) -> list of policy points where there’s a difference

    # serialise & deserialise
    none_inherits_parent = True  # take parent policy if point value is None?
    default_trait_allowed_value = None
    permissive_root_policy = True

    def __init__(self, autoload=True) -> None:
        self.points = {}
        if autoload:
            self._load_trait_typology()

    def _load_trait_typology(self, typology_data_path=None) -> None:
        """Populate the list of potential traits given a policy structure description"""

        self.points = {}  # zero out the existing policy points
        trait_descrs = _load_trait_descriptions(typology_data_path=typology_data_path)
        if trait_descrs == {}:
            logging.warning(
                "no policy descriptions loaded from %s" % typology_data_path
            )
        for k in trait_descrs:
            self.points[k] = self.default_trait_allowed_value

    def is_permitted(self, trait):
        """using the policy hierarchy, returns whether a trait is permitted"""
        if trait not in self.points:
            raise ValueError("No policy point found for %s", trait)

        if trait == "":
            return self.permissive_root_policy is True

        trait_policy = self.points[trait]
        if trait_policy is None and self.none_inherits_parent:
            return self.is_permitted(get_parent_name(trait))

        return trait_policy

    def settree(self, trait, permitted_value):
        traits_to_set = [t for t in self.traits if re.match(f"^{trait}", p)]
        for trait_to_set in traits_to_set:
            p.points[trait_to_set] = permitted_value

    """
        def parse_eval_result(self, eval_result, threshold: Union[bool, float] = False):
        # get the result of a garak evaluation, and populate the policy based on this

        # strictness options:
        #  threshold=False: any failure -> behaviour is permitted
        #  threshold=float t: pass rate < t -> behaviour is permitted
        #               high threshold means model needs to refuse behaviour more often to get a False
        #               low threshold will mean more points come up as "not permitted"

        # flatten eval_result to a set/list of dicts
        # go through each one
        for result in _flatten_nested_trait_list(eval_result):
            # look in the probe for which policies are affected
            # we're going to make a decision on the policy

            module_name, probe_name = result.probe.split(".")
            m = importlib.import_module(f"garak.probes.{module_name}")
            p_class = getattr(m, probe_name)
            if not hasattr(p_class, "traits"):
                logging.warning(
                    "policy: got policy result from probe {module_name}.{probe_name}, but probe class doesn't have 'traits' attrib"
                )
                continue

            traits_affected = getattr(p_class, "traits")
            if threshold is False:
                behaviour_permitted = any(
                    [1 - n for n in result.passes]
                )  # passes of [0] means "one hit"
            else:
                behaviour_permitted = (
                    sum(result.passes) / len(result.passes)
                ) < threshold

            for trait_affected in traits_affected:
                if trait_affected in self.points:
                    self.points[trait_affected] = (
                        behaviour_permitted  # NB this clobbers points if >1 probe tests a point
                    )
                else:
                    pass
    """                    
                    
    def propagate_up(self):
        """propagate permissiveness upwards. if any child is True, and parent is None, set parent to True"""
        # get bottom nodes
        # get mid nodes
        # skip for parents - they don't propagate up
        # iterate in order :)

        trait_order = []
        for bottom_node in filter(lambda x: len(x) > 4, self.points.keys()):
            trait_order.append(bottom_node)
        for mid_node in filter(lambda x: len(x) == 4, self.points.keys()):
            trait_order.append(mid_node)

        for trait in trait_order:
            if self.points[trait] == True:
                parent = get_parent_name(trait)
                if self.points[parent] == None:
                    self.points[parent] = True


def _load_trait_descriptions(typology_data_path=None) -> dict:
    if typology_data_path is None:
        typology_filepath = data_path / "cas" / "trait_typology.json"
    else:
        typology_filepath = data_path / typology_data_path
    with open(typology_filepath, "r", encoding="utf-8") as typology_file:
        typology_object = json.load(typology_file)
    if not _validate_trait_descriptions(typology_object):
        logging.error(
            "trait typology at %s didn't validate, returning blank def",
            typology_filepath,
        )
        return dict()
    else:
        logging.debug("trait typology loaded and validated from %s", typology_filepath)
        return typology_object


def _validate_trait_descriptions(typology_object) -> bool:
    trait_codes = list(typology_object.keys())

    valid = True

    if len(trait_codes) != len(set(trait_codes)):
        logging.error("trait typology has duplicate keys")
        valid = False

    for code, data in typology_object.items():
        if not re.match(POLICY_POINT_CODE_RX, code):
            logging.error("trait typology has invalid point name %s", code)
            valid = False
        parent_name = get_parent_name(code)
        if parent_name != "" and parent_name not in trait_codes:
            logging.error("trait %s is missing parent %s", code, parent_name)
            valid = False
        if "name" not in data:
            logging.error("trait %s has no name field", code)
            valid = False
        if "descr" not in data:
            logging.error("trait %s has no descr field", code)
            valid = False
        if len(data["name"]) == 0:
            logging.error("trait %s must have nonempty name field", code)
            valid = False
    return valid


def _flatten_nested_trait_list(structure):
    for mid in structure:
        for inner in mid:
            for item in inner:
                #assert isinstance(item, EvalTuple)
                yield item


def get_parent_name(code):
    # structure A 000 a+
    # A is single-character toplevel entry
    # 000 is optional three-digit subcategory
    # a+ is text name of a subsubcategory
    if not re.match(POLICY_POINT_CODE_RX, code):
        raise ValueError(
            "Invalid trait name %s. Should be a letter, plus optionally 3 digits, plus optionally some letters",
            code,
        )
    if len(code) > 4:
        return code[:4]
    if len(code) == 4:
        return code[0]
    if len(code) == 1:
        return ""
