# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

""" Policy tools 

Policy in garak describes how a model behaves without using any adversarial techniques.
The idea is that in order to know that an attack makes a difference, we need to know
if the model will offer up the target behaviour when no adversarial technique is applied.
If we can get the target behaviour out-of-the-box, then we say that the model's *policy*
is to offer that behaviour.

We implement policy with two, separate concepts:
1. A set of functions/behaviours that models could potentially exhibit
2. Data on whether the target model exhibits each of these behaviours

The first comes from a typology, which is externally defined. There's some JSON that tracks
this. It's the categories of model behaviour we're interested in. This is not exhaustive and
not intended to be exhaustive - rather, it's constrained to model behaviours that have been
either helpful in aiding attacks, or the targets of attacks, in the literature, as well as
items that aligners have discussed.

The second is derived by testing each policy point. We don't have complete tests for all the
points at launch; that's a lot of detectors, and a lot to validate.


Policy metadata
---------------
The total set of points in the behaviour typology can be represented as a dictionary. Definitions of policy names, descriptions, and behaviours are stored in a JSON data file

* Key: behaviour identifier - format is TDDDs*
	* T: a top-level hierarchy code letter, in CTMS for chat/tasks/meta/safety
	* D: a three-digit code for this behaviour
	* s*: (optional) one or more letters identifying a sub-policy

* Value: a dict describing a behaviour
    * “name”: A short name of what is permitted when this behaviour is allowed
    * “description”: (optional) a deeper description of this behaviour

The structure of the identifiers describes the hierarchical structure.
Prompts & probes
Example prompts or probes to be used to test a behaviour. Not every entry in the policy needs to have prompts or probes defined, and if a policy does have them define, it doesn't need to have both described. If a prompt is given, it's assumed that the mitigation.mitigationBypass detector should be used for this. That detector should always point to our best-effort mitigation message detection.

* Key: behaviour identifier
* Value: a dict describing how to test
	* “prompts”: a list of strings to try to test the behaviour
	* “probes”: garak probes compatible with load_plugin() that can test the behaviour

Implementing policy probes
--------------------------

Probes that are non-adversarial and only test a policy should have a class attr like “policy_probe”

Policy probes, i.e. those where this is set to true, should also list the policies that they test for, in a class var. E.g. if “policies_tested = [“C006”]” then hits in this probe indicate the model's policy is to permit policy point C006.

Following from this, 

-- list_probes should NOT show policy probes
-- list_policy_probes should list policy probes, and be added to garak.command 
probe_spec expansions need to be able to select between policy and non-policy probes
Propose an optional filter value in plugin enumeration, a dict where values have to be matched for them to be returned

Questions:

* Where do the policy scan results go? Harnesses don't return much -> evaluators return information used to develop results; policy is serialised and written to report jonsl and policy jsonl
* How do we differentiate policy results in the results log? Distinct type tag

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
policy.permitted(behaviour) -> True/False/None
policy.compare(policy) -> list of policy points where there's a difference
policy.set(prefix, value) -> set prefix to value
policy.settree(prefix, value) -> set this and all sub-points in the policy to value
```

Run flow
--------

1. Start-up
2. If policy scan is enabled..
3. Run a policy test (garak.command)
    a. Select policy probes (add filtering to _plugins.enumerate() ?)
    b. Invoke a policy harness (garak.harnesses.policy)
    6. Process results using a policy evaluator (garak.evaluators.policy ?)
    d. Convert eval result into a policy (garak.policy)
4. Write policy to report jsonl
5. Assemble the main run
    a. (optionally) Skip probes that test things we permit anyway
6. Store policy somewhere transient where can grab it later


"""

import importlib
import json
import logging
import re
from typing import Union

from garak.data import path as data_path
from garak.evaluators.base import EvalTuple


""" Policy points have a key describing where they fit in the policy typology.
* Key: behaviour identifier - format is TDDDs*
	* T: a top-level hierarchy code letter, in CTMS for chat/tasks/meta/safety
	* D: a three-digit code for this behaviour
	* s*: (optional) one or more letters identifying a sub-policy
"""

POLICY_CODE_RX = r"^[A-Z]([0-9]{3}([a-z]+)?)?$"


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
    default_point_policy = None
    permissive_root_policy = True

    def __init__(self, autoload=True) -> None:
        self.points = {}
        if autoload:
            self._load_policy_typology()

    def _load_policy_typology(self, policy_data_path=None) -> None:
        """Populate the list of potential policy points given a policy structure description"""

        self.points = {}  # zero out the existing policy points
        policy_descrs = _load_policy_descriptions(policy_data_path=policy_data_path)
        if policy_descrs == {}:
            logging.warning("no policy descriptions loaded from %s" % policy_data_path)
        for k in policy_descrs:
            self.points[k] = self.default_point_policy

    def is_permitted(self, point):
        """using the policy hierarchy, returns whether a policy point is permitted"""
        if point not in self.points:
            raise ValueError("No policy point found for %s", point)

        if point == "":
            return self.permissive_root_policy is True

        point_policy = self.points[point]
        if point_policy is None and self.none_inherits_parent:
            return self.is_permitted(get_parent_name(point))

        return point_policy

    def settree(self, point, policy_value):
        points_to_set = [p for p in self.points if re.match(f"^{point}", p)]
        for point_to_set in points_to_set:
            p.points[point_to_set] = policy_value

    def parse_eval_result(self, eval_result, threshold: Union[bool, float] = False):
        """get the result of a garak evaluation, and populate the policy based on this"""

        # strictness options:
        #  threshold=False: any failure -> behaviour is permitted
        #  threshold=float t: pass rate < t -> behaviour is permitted
        #               high threshold means model needs to refuse behaviour more often to get a False
        #               low threshold will mean more points come up as "not permitted"

        # flatten eval_result to a set/list of dicts
        # go through each one
        for result in _flatten_nested_policy_list(eval_result):
            # look in the probe for which policies are affected
            # we're going to make a decision on the policy

            module_name, probe_name = result.probe.split(".")
            m = importlib.import_module(f"garak.probes.{module_name}")
            p_class = getattr(m, probe_name)
            if not hasattr(p_class, "policies"):
                logging.warning(
                    "policy: got policy result from probe {module_name}.{probe_name}, but probe class doesn't have 'policies' attrib"
                )
                continue

            points_affected = getattr(p_class, "policies")
            if threshold is False:
                behaviour_permitted = any(
                    [1 - n for n in result.passes]
                )  # passes of [0] means "one hit"
            else:
                behaviour_permitted = (
                    sum(result.passes) / len(result.passes)
                ) < threshold

            for point_affected in points_affected:
                if point_affected in self.points:
                    self.points[point_affected] = (
                        behaviour_permitted  # NB this clobbers points if >1 probe tests a point
                    )
                else:
                    pass

    def propagate_up(self):
        """propagate permissiveness upwards. if any child is True, and parent is None, set parent to True"""
        # get bottom nodes
        # get mid nodes
        # skip for parents - they don't propagate up
        # iterate in order :)

        point_order = []
        for bottom_node in filter(lambda x: len(x) > 4, self.points.keys()):
            point_order.append(bottom_node)
        for mid_node in filter(lambda x: len(x) == 4, self.points.keys()):
            point_order.append(mid_node)

        for point in point_order:
            if self.points[point] == True:
                parent = get_parent_name(point)
                if self.points[parent] == None:
                    self.points[parent] = True


def _load_policy_descriptions(policy_data_path=None) -> dict:
    if policy_data_path is None:
        policy_filepath = data_path / "policy" / "policy_typology.json"
    else:
        policy_filepath = data_path / policy_data_path
    with open(policy_filepath, "r", encoding="utf-8") as policy_file:
        policy_object = json.load(policy_file)
    if not _validate_policy_descriptions(policy_object):
        logging.error(
            "policy typology at %s didn't validate, returning blank policy def",
            policy_filepath,
        )
        return dict()
    else:
        logging.debug("policy typology loaded and validated from %s", policy_filepath)
        return policy_object


def _validate_policy_descriptions(policy_object) -> bool:
    policy_codes = list(policy_object.keys())

    valid = True

    if len(policy_codes) != len(set(policy_codes)):
        logging.error("policy typology has duplicate keys")
        valid = False

    for code, data in policy_object.items():
        if not re.match(POLICY_CODE_RX, code):
            logging.error("policy typology has invalid point name %s", code)
            valid = False
        parent_name = get_parent_name(code)
        if parent_name != "" and parent_name not in policy_codes:
            logging.error(
                "policy typology point %s is missing parent %s", code, parent_name
            )
            valid = False
        if "name" not in data:
            logging.error("policy typology point %s has no name field", code)
            valid = False
        if "descr" not in data:
            logging.error("policy typology point %s has no descr field", code)
            valid = False
        if len(data["name"]) == 0:
            logging.error(
                "policy typology point %s must have nonempty name field", code
            )
            valid = False
    return valid


def _flatten_nested_policy_list(structure):
    for mid in structure:
        for inner in mid:
            for item in inner:
                assert isinstance(item, EvalTuple)
                yield item


def get_parent_name(code):
    # structure A 000 a+
    # A is single-character toplevel entry
    # 000 is optional three-digit subcategory
    # a+ is text name of a subsubcategory
    if not re.match(POLICY_CODE_RX, code):
        raise ValueError(
            "Invalid policy name %s. Should be a letter, plus optionally 3 digits, plus optionally some letters",
            code,
        )
    if len(code) > 4:
        return code[:4]
    if len(code) == 4:
        return code[0]
    if len(code) == 1:
        return ""
