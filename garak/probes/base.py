# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Base classes for probes.

Probe plugins must inherit one of these. `Probe` serves as a template showing
what expectations there are for inheriting classes."""

import copy
import json
import logging
from collections.abc import Iterable
import random
from typing import Iterable, Union

from colorama import Fore, Style
import tqdm

from garak import _config
from garak.configurable import Configurable
from garak.exception import GarakException, PluginConfigurationError
from garak.probes._tier import Tier
import garak.attempt
import garak.resources.theme


class Probe(Configurable):
    """Base class for objects that define and execute LLM evaluations"""

    # docs uri for a description of the probe (perhaps a paper)
    doc_uri: str = ""
    # language this is for, in BCP47 format; * for all langs
    lang: Union[str, None] = None
    # should this probe be included by default?
    active: bool = False
    # MISP-format taxonomy categories
    tags: Iterable[str] = []
    # what the probe is trying to do, phrased as an imperative
    goal: str = ""
    # Deprecated -- the detectors that should be run for this probe. always.Fail is chosen as default to send a signal if this isn't overridden.
    recommended_detector: Iterable[str] = ["always.Fail"]
    # default detector to run, if the primary/extended way of doing it is to be used (should be a string formatted like recommended_detector)
    primary_detector: Union[str, None] = None
    # optional extended detectors
    extended_detectors: Iterable[str] = []
    # can attempts from this probe be parallelised?
    parallelisable_attempts: bool = True
    # Keeps state of whether a buff is loaded that requires a call to untransform model outputs
    post_buff_hook: bool = False
    # support mainstream any-to-any large models
    # legal element for str list `modality['in']`: 'text', 'image', 'audio', 'video', '3d'
    # refer to Table 1 in https://arxiv.org/abs/2401.13601
    # we focus on LLM input for probe
    modality: dict = {"in": {"text"}}
    # what tier is this probe? should be in (OF_CONCERN,COMPETE_WITH_SOTA,INFORMATIONAL,UNLISTED)
    # let mixins override this
    # tier: Tier = Tier.UNLISTED
    tier: Tier = Tier.UNLISTED
    # list of strings naming modules required but not explicitly in garak by default
    extra_dependency_names = []

    DEFAULT_PARAMS = {}

    _run_params = {"generations", "soft_probe_prompt_cap", "seed"}
    _system_params = {"parallel_attempts", "max_workers"}

    def __init__(self, config_root=_config):
        """Sets up a probe.

        This constructor:
        1. populates self.probename based on the class name,
        2. logs and optionally prints the probe's loading,
        3. populates self.description based on the class docstring if not yet set
        """
        self._load_config(config_root)
        self.probename = str(self.__class__).split("'")[1]
        if hasattr(_config.system, "verbose") and _config.system.verbose > 0:
            print(
                f"loading {Style.BRIGHT}{Fore.LIGHTYELLOW_EX}probe: {Style.RESET_ALL}{self.probename}"
            )
        logging.info(f"probe init: {self}")
        if "description" not in dir(self):
            if self.__doc__:
                self.description = self.__doc__.split("\n", maxsplit=1)[0]
            else:
                self.description = ""
        self.langprovider = self._get_langprovider()
        if self.langprovider is not None and hasattr(self, "triggers"):
            # check for triggers that are not type str|list or just call translate_triggers
            preparation_bar = tqdm.tqdm(
                total=len(self.triggers),
                leave=False,
                colour=f"#{garak.resources.theme.LANGPROVIDER_RGB}",
                desc="Preparing triggers",
            )
            if len(self.triggers) > 0:
                if isinstance(self.triggers[0], str):
                    self.triggers = self.langprovider.get_text(
                        self.triggers, notify_callback=preparation_bar.update
                    )
                elif isinstance(self.triggers[0], list):
                    self.triggers = [
                        self.langprovider.get_text(trigger_list)
                        for trigger_list in self.triggers
                    ]
                    preparation_bar.update()
                else:
                    raise PluginConfigurationError(
                        f"trigger type: {type(self.triggers[0])} is not supported."
                    )
            preparation_bar.close()
        self.reverse_langprovider = self._get_reverse_langprovider()

    def _get_langprovider(self):
        from garak.langservice import get_langprovider

        langprovider_instance = get_langprovider(self.lang)
        return langprovider_instance

    def _get_reverse_langprovider(self):
        from garak.langservice import get_langprovider

        langprovider_instance = get_langprovider(self.lang, reverse=True)
        return langprovider_instance

    def _attempt_prestore_hook(
        self, attempt: garak.attempt.Attempt, seq: int
    ) -> garak.attempt.Attempt:
        """hook called when a new attempt is registered, allowing e.g.
        systematic transformation of attempts"""
        return attempt

    def _generator_precall_hook(self, generator, attempt=None):
        """function to be overloaded if a probe wants to take actions between
        attempt generation and posing prompts to the model"""
        pass

    def _buff_hook(
        self, attempts: Iterable[garak.attempt.Attempt]
    ) -> Iterable[garak.attempt.Attempt]:
        """this is where we do the buffing, if there's any to do"""
        if len(_config.buffmanager.buffs) == 0:
            return attempts
        buffed_attempts = []
        buffed_attempts_added = 0
        if _config.plugins.buffs_include_original_prompt:
            for attempt in attempts:
                buffed_attempts.append(attempt)
        for buff in _config.buffmanager.buffs:
            if (
                _config.plugins.buff_max is not None
                and buffed_attempts_added >= _config.plugins.buff_max
            ):
                break
            if buff.post_buff_hook:
                self.post_buff_hook = True
            for buffed_attempt in buff.buff(
                attempts, probename=".".join(self.probename.split(".")[-2:])
            ):
                buffed_attempts.append(buffed_attempt)
                buffed_attempts_added += 1
        return buffed_attempts

    @staticmethod
    def _postprocess_buff(attempt: garak.attempt.Attempt) -> garak.attempt.Attempt:
        """hook called immediately after an attempt has been to the generator,
        buff de-transformation; gated on self.post_buff_hook"""
        for buff in _config.buffmanager.buffs:
            if buff.post_buff_hook:
                attempt = buff.untransform(attempt)
        return attempt

    def _generator_cleanup(self):
        """Hook to clean up generator state"""
        self.generator.clear_history()

    def _postprocess_hook(
        self, attempt: garak.attempt.Attempt
    ) -> garak.attempt.Attempt:
        """hook called to process completed attempts; always called"""
        return attempt

    def _mint_attempt(
        self, prompt=None, seq=None, notes=None, lang="*"
    ) -> garak.attempt.Attempt:
        """function for creating a new attempt given a prompt"""
        new_attempt = garak.attempt.Attempt(
            probe_classname=(
                str(self.__class__.__module__).replace("garak.probes.", "")
                + "."
                + self.__class__.__name__
            ),
            goal=self.goal,
            status=garak.attempt.ATTEMPT_STARTED,
            seq=seq,
            prompt=prompt,
            notes=notes,
            lang=lang,
        )

        new_attempt = self._attempt_prestore_hook(new_attempt, seq)
        return new_attempt

    def _execute_attempt(self, this_attempt):
        """handles sending an attempt to the generator, postprocessing, and logging"""
        self._generator_precall_hook(self.generator, this_attempt)
        this_attempt.outputs = self.generator.generate(
            this_attempt.prompt, generations_this_call=self.generations
        )
        if self.post_buff_hook:
            this_attempt = self._postprocess_buff(this_attempt)
        this_attempt = self._postprocess_hook(this_attempt)
        self._generator_cleanup()
        return copy.deepcopy(this_attempt)

    def _execute_all(self, attempts) -> Iterable[garak.attempt.Attempt]:
        """handles sending a set of attempt to the generator"""
        attempts_completed: Iterable[garak.attempt.Attempt] = []

        if (
            self.parallel_attempts
            and self.parallel_attempts > 1
            and self.parallelisable_attempts
            and len(attempts) > 1
            and self.generator.parallel_capable
        ):
            from multiprocessing import Pool

            attempt_bar = tqdm.tqdm(total=len(attempts), leave=False)
            attempt_bar.set_description(self.probename.replace("garak.", ""))

            pool_size = min(
                len(attempts),
                self.parallel_attempts,
                self.max_workers,
            )

            try:
                with Pool(pool_size) as attempt_pool:
                    for result in attempt_pool.imap_unordered(
                        self._execute_attempt, attempts
                    ):
                        # reverse translate outputs if required, this is intentionally executed in the core process
                        if result.lang != self.lang:
                            result.reverse_translation_outputs = (
                                self.reverse_langprovider.get_text(result.all_outputs)
                            )

                        _config.transient.reportfile.write(
                            json.dumps(result.as_dict(), ensure_ascii=False) + "\n"
                        )
                        attempts_completed.append(
                            result
                        )  # these will be out of original order
                        attempt_bar.update(1)
            except OSError as o:
                if o.errno == 24:
                    msg = "Parallelisation limit hit. Try reducing parallel_attempts or raising limit (e.g. ulimit -n 4096)"
                    logging.critical(msg)
                    raise GarakException(msg) from o
                else:
                    raise (o)

        else:
            attempt_iterator = tqdm.tqdm(attempts, leave=False)
            attempt_iterator.set_description(self.probename.replace("garak.", ""))
            for this_attempt in attempt_iterator:
                result = self._execute_attempt(this_attempt)
                # reverse langprovider outputs if required
                if result.lang != self.lang:
                    result.reverse_translation_outputs = (
                        self.reverse_langprovider.get_text(result.all_outputs)
                    )

                _config.transient.reportfile.write(json.dumps(result.as_dict(), ensure_ascii=False) + "\n")
                attempts_completed.append(result)
        return attempts_completed

    def probe(self, generator) -> Iterable[garak.attempt.Attempt]:
        """attempt to exploit the target generator, returning a list of results"""
        logging.debug("probe execute: %s", self)

        self.generator = generator

        # build list of attempts
        attempts_todo: Iterable[garak.attempt.Attempt] = []
        prompts = list(self.prompts)
        lang = self.lang
        # account for visual jailbreak until Turn/Conversation is supported
        preparation_bar = tqdm.tqdm(
            total=len(prompts),
            leave=False,
            colour=f"#{garak.resources.theme.LANGPROVIDER_RGB}",
            desc="Preparing prompts",
        )
        if isinstance(prompts[0], str):
            prompts = self.langprovider.get_text(
                prompts, notify_callback=preparation_bar.update
            )
        else:
            for prompt in prompts:
                if "text" in prompt:
                    prompt["text"] = self.langprovider.get_text(
                        prompt["text"], notify_callback=preparation_bar.update
                    )
        lang = self.langprovider.target_lang
        preparation_bar.close()
        for seq, prompt in enumerate(prompts):
            notes = (
                {"pre_translation_prompt": self.prompts[seq]}
                if lang != self.lang
                else None
            )
            attempts_todo.append(self._mint_attempt(prompt, seq, notes, lang))

        # buff hook
        if len(_config.buffmanager.buffs) > 0:
            attempts_todo = self._buff_hook(attempts_todo)

        # iterate through attempts
        attempts_completed = self._execute_all(attempts_todo)

        logging.debug(
            "probe return: %s with %s attempts", self, len(attempts_completed)
        )

        return attempts_completed

    def _prune_data(self, cap, prune_triggers=False):
        num_ids_to_delete = max(0, len(self.prompts) - cap)
        ids_to_rm = random.sample(range(len(self.prompts)), num_ids_to_delete)
        # delete in descending order
        ids_to_rm = sorted(ids_to_rm, reverse=True)
        for id in ids_to_rm:
            del self.prompts[id]
            if prune_triggers:
                del self.triggers[id]


class TreeSearchProbe(Probe):

    DEFAULT_PARAMS = Probe.DEFAULT_PARAMS | {
        "queue_children_at_start": True,
        "per_generation_threshold": 0.5,
        "per_node_threshold": 0.1,
        "strategy": "breadth_first",  # could also be depth_first, that's often less efficient
        "target_soft": True,  # should we be getting deeping into areas that fail? (False = push on resilient areas)
    }

    def _get_initial_nodes(self) -> Iterable:
        """Return iterable of node objects to start the queue with"""
        raise NotImplementedError

    def _get_node_id(self, node) -> str:
        """Return a unique ID string representing the current node; for queue management"""
        raise NotImplementedError

    def _get_node_children(self, node) -> Iterable:
        """Return a list of node objects that are children of the supplied node"""
        raise NotImplementedError

    def _get_node_terms(self, node) -> Iterable[str]:
        """Return a list of terms corresponding to the given node"""
        raise NotImplementedError

    def _gen_prompts(self, term: str) -> Iterable[str]:
        """Convert a term into a set of prompts"""
        raise NotImplementedError

    def _get_node_parent(self, node):
        """Return a node object's parent"""
        raise NotImplementedError

    def _get_node_siblings(self, node) -> Iterable:
        """Return sibling nodes, i.e. other children of parent"""
        raise NotImplementedError

    def probe(self, generator):

        node_ids_explored = set()
        nodes_to_explore = self._get_initial_nodes()
        surface_forms_probed = set()

        self.generator = generator
        detector = garak._plugins.load_plugin(f"detectors.{self.primary_detector}")

        all_completed_attempts: Iterable[garak.attempt.Attempt] = []

        if not len(nodes_to_explore):
            logging.info("No initial nodes for %s, skipping" % self.probename)
            return []

        tree_bar = tqdm.tqdm(
            total=int(len(nodes_to_explore) * 4),
            leave=False,
            colour=f"#{garak.resources.theme.PROBE_RGB}",
        )
        tree_bar.set_description("Tree search nodes traversed")

        while len(nodes_to_explore):

            logging.debug(
                "%s Queue: %s" % (self.__class__.__name__, repr(nodes_to_explore))
            )
            if self.strategy == "breadth_first":
                current_node = nodes_to_explore.pop(0)
            elif self.strategy == "depth_first":
                current_node = nodes_to_explore.pop()

            # update progress bar
            progress_nodes_previous = len(node_ids_explored)
            progress_nodes_todo = int(1 + len(nodes_to_explore) * 2.5)
            # print("seen", node_ids_explored, progress_nodes_previous)
            # print("curr", current_node)
            # print("todo", nodes_to_explore, progress_nodes_todo)

            tree_bar.total = progress_nodes_previous + progress_nodes_todo
            tree_bar.refresh()

            node_ids_explored.add(self._get_node_id(current_node))

            # init this round's list of attempts
            attempts_todo: Iterable[garak.attempt.Attempt] = []

            logging.debug(
                "%s %s, %s"
                % (self.__class__.__name__, current_node, current_node.words())
            )

            # generate surface forms
            new_surface_forms = list(self._get_node_terms(current_node))

            # get prompts
            for surface_form in new_surface_forms:
                if (
                    surface_form in surface_forms_probed
                    or surface_form in self.never_queue_forms
                ):
                    continue

                for prompt in self._gen_prompts(surface_form):
                    notes = {"surface_form": surface_form}
                    a = self._mint_attempt(prompt, notes=notes, lang=self.lang)
                    attempts_todo.append(a)

                surface_forms_probed.add(surface_form)

            if len(attempts_todo) == 0:
                tree_bar.update()
                tree_bar.refresh()
                continue

            # buff hook
            if len(_config.buffmanager.buffs) > 0:
                attempts_todo = self._buff_hook(attempts_todo)

            attempts_completed = self._execute_all(attempts_todo)

            # now we call the detector 🙃
            node_results = []
            for attempt in attempts_completed:
                attempt.detector_results[self.primary_detector] = detector.detect(
                    attempt
                )
                node_results += attempt.detector_results[self.primary_detector]
                attempt.status = garak.attempt.ATTEMPT_COMPLETE
                _config.transient.reportfile.write(json.dumps(attempt.as_dict(), ensure_ascii=False) + "\n")

            tree_bar.update()
            tree_bar.refresh()

            all_completed_attempts += attempts_completed

            node_results = [
                1.0 if s > self.per_generation_threshold else 0 for s in node_results
            ]
            if len(node_results) > 0:
                mean_score = sum(node_results) / len(node_results)
            else:
                mean_score = 0
            parent = self._get_node_parent(current_node)
            node_info = {
                "entry_type": "tree_data",
                "probe": self.__class__.__name__,
                "detector": self.primary_detector,
                "node_id": self._get_node_id(current_node),
                "node_parent": (
                    self._get_node_id(parent) if parent is not None else None
                ),
                "node_score": mean_score,
                "surface_forms": new_surface_forms,
            }
            _config.transient.reportfile.write(json.dumps(node_info, ensure_ascii=False) + "\n")
            logging.debug("%s  node score %s" % (self.__class__.__name__, mean_score))

            if (mean_score > self.per_node_threshold and self.target_soft) or (
                mean_score < self.per_node_threshold and not self.target_soft
            ):
                children = self._get_node_children(current_node)
                logging.debug(
                    f"{self.__class__.__name__}  adding children" + repr(children)
                )
                for child in children:
                    if (
                        self._get_node_id(child) not in node_ids_explored
                        and child not in nodes_to_explore
                        and child not in self.never_queue_nodes
                    ):
                        logging.debug("%s   %s" % (self.__class__.__name__, child))
                        nodes_to_explore.append(child)
                    else:
                        logging.debug(
                            "%s   skipping %s" % (self.__class__.__name__, child)
                        )
            else:
                logging.debug("%s closing node" % self.__class__.__name__)

        tree_bar.total = len(node_ids_explored)
        tree_bar.update(len(node_ids_explored))
        tree_bar.refresh()
        tree_bar.close()

        # we've done detection, so let's skip the main one
        self.primary_detector_real = self.primary_detector
        self.primary_detector = "always.Passthru"

        return all_completed_attempts

    def __init__(self, config_root=_config):
        super().__init__(config_root)
        if self.strategy not in ("breadth_first, depth_first"):
            raise ValueError(f"Unsupported tree search strategy '{self.strategy}'")

        self.never_queue_nodes: Iterable[str] = set()
        self.never_queue_forms: Iterable[str] = set()
