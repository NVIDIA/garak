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
from typing import Iterable, Union, List

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
    # tier: tier = Tier.UNLISTED
    tier: Tier = Tier.UNLISTED

    DEFAULT_PARAMS = {}

    _run_params = {"generations", "soft_probe_prompt_cap", "seed", "system_prompt"}
    _system_params = {"parallel_attempts", "max_workers"}

    def __init__(self, config_root=_config):
        """Sets up a probe.

        This constructor:
        1. populates self.probename based on the class name,
        2. logs and optionally logging.debugs the probe's loading,
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
        turns = []
        if isinstance(prompt, garak.attempt.Conversation):
            try:
                # only add system prompt if the prompt does not contain one
                prompt.last_message("system")
                turns = prompt.turns
            except ValueError as e:
                turns.append(prompt.turns)
        elif hasattr(self, "system_prompt") and self.system_prompt:
            turns.append(
                garak.attempt.Turn(
                    role="system",
                    content=garak.attempt.Message(
                        text=self.system_prompt, lang=lang
                    ),
                )
            )
        if isinstance(prompt, str):
            turns.append(
                garak.attempt.Turn(
                    role="user", content=garak.attempt.Message(text=prompt, lang=lang)
                )
            )
        elif isinstance(prompt, garak.attempt.Message):
            turns.append(garak.attempt.Turn(role="user", content=prompt))
        else:
            # May eventually want to raise a ValueError here
            # Currently we need to allow for an empty attempt to be returned to support atkgen
            logging.warning("No prompt set for attempt in %s" % self.__class__.__name__)

        if len(turns) > 0:
            prompt = garak.attempt.Conversation(
                turns=turns,
                notes=notes,
            )

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

    def _postprocess_attempt(self, this_attempt) -> garak.attempt.Attempt:
        # Messages from the generator have no language set, propagate the target language to all outputs
        # TODO: determine if this should come from `self.langprovider.target_lang` instead of the result object
        all_outputs = this_attempt.all_outputs
        for output in all_outputs:
            if output is not None:
                output.lang = this_attempt.lang
        # reverse translate outputs if required, this is intentionally executed in the core process
        if this_attempt.lang != self.lang:
            # account for possible None output
            results_text = [msg.text for msg in all_outputs if msg is not None]
            reverse_translation_outputs = [
                garak.attempt.Message(
                    translated_text, lang=self.reverse_langprovider.target_lang
                )
                for translated_text in self.reverse_langprovider.get_text(results_text)
            ]
            this_attempt.reverse_translation_outputs = []
            for output in all_outputs:
                if output is not None:
                    this_attempt.reverse_translation_outputs.append(
                        reverse_translation_outputs.pop()
                    )
                else:
                    this_attempt.reverse_translation_outputs.append(None)
        return copy.deepcopy(this_attempt)

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
                        processed_attempt = self._postprocess_attempt(result)

                        _config.transient.reportfile.write(
                            json.dumps(processed_attempt.as_dict(), ensure_ascii=False)
                            + "\n"
                        )
                        attempts_completed.append(
                            processed_attempt
                        )  # these can be out of original order
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
                processed_attempt = self._postprocess_attempt(result)

                _config.transient.reportfile.write(
                    json.dumps(processed_attempt.as_dict()) + "\n"
                )
                attempts_completed.append(processed_attempt)

        return attempts_completed

    def probe(self, generator) -> Iterable[garak.attempt.Attempt]:
        """attempt to exploit the target generator, returning a list of results"""
        logging.debug("probe execute: %s", self)

        self.generator = generator

        # build list of attempts
        attempts_todo: Iterable[garak.attempt.Attempt] = []
        prompts = list(
            self.prompts
        )  # will this still make a copy if prompts are `Message` objects?
        lang = self.lang
        # account for visual jailbreak until Turn/Conversation is supported
        preparation_bar = tqdm.tqdm(
            total=len(prompts),
            leave=False,
            colour=f"#{garak.resources.theme.LANGPROVIDER_RGB}",
            desc="Preparing prompts",
        )
        if isinstance(prompts[0], str):
            localized_prompts = self.langprovider.get_text(
                prompts, notify_callback=preparation_bar.update
            )
            prompts = []
            for prompt in localized_prompts:
                prompts.append(
                    garak.attempt.Message(prompt, lang=self.langprovider.target_lang)
                )
        else:
            # what types should this expect? Message, Conversation?
            for prompt in prompts:
                if isinstance(prompt, garak.attempt.Message):
                    prompt.text = self.langprovider.get_text(
                        prompt.text, notify_callback=preparation_bar.update
                    )
                    prompt.lang = self.langprovider.target_lang
                if isinstance(prompt, garak.attempt.Conversation):
                    for turn in prompt.turns:
                        msg = turn.content
                        msg.text = self.langprovider.get_text(
                            msg.text, notify_callback=preparation_bar.update
                        )
                        msg.lang = self.langprovider.target_lang
        lang = self.langprovider.target_lang
        preparation_bar.close()
        for seq, prompt in enumerate(prompts):
            notes = (
                {
                    "pre_translation_prompt": garak.attempt.Conversation(
                        [
                            garak.attempt.Turn(
                                "user",
                                garak.attempt.Message(
                                    self.prompts[seq], lang=self.lang
                                ),
                            )
                        ]
                    )
                }
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
            # logging.debug("seen", node_ids_explored, progress_nodes_previous)
            # logging.debug("curr", current_node)
            # logging.debug("todo", nodes_to_explore, progress_nodes_todo)

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
                _config.transient.reportfile.write(
                    json.dumps(attempt.as_dict(), ensure_ascii=False) + "\n"
                )

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
            _config.transient.reportfile.write(
                json.dumps(node_info, ensure_ascii=False) + "\n"
            )
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


class IterativeProbe(Probe):
    """
    Base class for multi turn probes where each probe turn is generated based on the target's response to the previous turn.
    """
    DEFAULT_PARAMS = Probe.DEFAULT_PARAMS | {
        "max_turns": 10,
        "end_condition": "detector",
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root)
        if self.end_condition not in ("detector", "verify"):
            raise ValueError(f"Unsupported end condition '{self.end_condition}'")
        self.detector = None
        self.detector_score_threshold = 0.5

    def generate_init_turns(self) -> Iterable[str]:
        """Function to be overridden with initial turns of each unique attempt"""
        raise NotImplementedError

    def _mint_attempt(
        self, prompt=None, seq=None, notes=None, lang="*"
    ) -> garak.attempt.Attempt:
        """function for creating a new attempt given a prompt"""
        turns = []
        # Create initial turn for system prompt
        if hasattr(self, "system_prompt") and self.system_prompt:
            turns.append(
                garak.attempt.Turn(
                    role="system",
                    content=garak.attempt.Message(
                        text=self.system_prompt, lang=lang
                    ),
                )
            )

        if isinstance(prompt, str):
            # Current prompt is just an str so add a user turn with it
            turns.append(
                garak.attempt.Turn(
                    role="user", content=garak.attempt.Message(text=prompt, lang=lang)
                )
            )
        elif isinstance(prompt, garak.attempt.Message):
            # Current prompt is a Message object so add a user turn with it
            turns.append(garak.attempt.Turn(role="user", content=prompt))
        elif isinstance(prompt, garak.attempt.Conversation):
            try:
                prompt.last_message("system")
                # Conversation already has a system turn; Keep it as is.
                turns = prompt.turns
            except ValueError as e:
                # Conversation doesn't have a system turn; Append existing conversation turns to the new system prompt turn created above
                turns += prompt.turns
        else:
            # May eventually want to raise a ValueError here
            # Currently we need to allow for an empty attempt to be returned to support atkgen
            logging.warning("No prompt set for attempt in %s" % self.__class__.__name__)

        if len(turns) > 0:
            prompt = garak.attempt.Conversation(
                turns=turns,
                notes=notes,
            )

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

    def _create_attempt(self, prompt) -> garak.attempt.Attempt:
        """Create an attempt from a prompt. Prompt can be of type str if this is an initial turn or garak.attempt.Conversation if this is a subsequent turn.
        Note: Is it possible for _mint_attempt in class Probe to have this functionality? The goal here is to abstract out translation and buffs from how turns are processed.
        """
        notes = (
            {
                "pre_translation_prompt": garak.attempt.Conversation(
                    [
                        garak.attempt.Turn(
                            "user",
                            garak.attempt.Message(
                                prompt, lang=self.lang # TODO: Will this work if prompt here is not str?
                            ),
                        )
                    ]
                )
            }
            if self.langprovider.target_lang != self.lang
            else None
        )
        
        if isinstance(prompt, str):
            localized_prompt = self.langprovider.get_text(
                prompt
            ) # TODO: Is it less efficient to call langprovider like this instead of on a list of prompts as is done in Probe.probe()?
            prompt = garak.attempt.Message(localized_prompt, lang=self.langprovider.target_lang)
        else:
            # what types should this expect? Message, Conversation?
            if isinstance(prompt, garak.attempt.Message):
                prompt.text = self.langprovider.get_text(
                    prompt.text
                )
                prompt.lang = self.langprovider.target_lang
            if isinstance(prompt, garak.attempt.Conversation):
                for turn in prompt.turns:
                    msg = turn.content
                    msg.text = self.langprovider.get_text(
                        msg.text
                    )
                    msg.lang = self.langprovider.target_lang

        
        return self._mint_attempt(prompt=prompt, seq=None, notes=notes, lang=self.langprovider.target_lang)

    def create_init_attempts(self, init_turns: Iterable[str]) -> Iterable[garak.attempt.Attempt]:
        """Wrapper converting init turns to garak.attempt.Attempt objects. 
        Base class sets turn number in attempt notes. Subclasses can use notes to mark attempts as non-adversarial if detector should skip them.
        """
        init_attempts = [self._create_attempt(turn) for turn in init_turns]
        for attempt in init_attempts:
            if attempt.notes is None:
                attempt.notes = dict()
                attempt.notes["turn_num"] = 0
        return init_attempts

    def verify_is_last_response_success(self, attempt: garak.attempt.Attempt) -> List[bool]:
        """Function to be overridden if a custom method is used to determine whether to terminate the conversation based on the last response. Evaluates each of attempt.outputs as a possible last response and returns a list of bools of the same size as attempt.outputs with True is that response indicated a successful attack and False otherwise."""
        raise NotImplementedError

    def _should_terminate_conversation(self, attempt: garak.attempt.Attempt) -> List[bool]:
        """Uses detector or verify_last_response function based on end_condition to determine if the conversation should be terminates at each of attempt.outputs. Returns a list of size equal to attempt.outputs with True if the conversation should be terminated at that outputand False otherwise."""
        if self.end_condition == "detector":
            detector_outputs = self.detector.detect(attempt)
            should_terminate = list()
            for detector_output in detector_outputs:
                if detector_output is not None:
                    should_terminate.append(detector_output > self.detector_score_threshold)
                else:
                    should_terminate.append(True)
            logging.debug("IterativeProbe._should_terminate_conversation() using detector, should_terminate = %s" % should_terminate)
            return should_terminate
            # TODO: Is it really correct to terminate the conversation of the detector returns None? What about skips?
            # TODO: It's an interesting trade-off if on the one hand a probe does want to use a detector to decide whether to terminate the conversation, but also specifies that most turns are non adversarial and should be skipped by the detector.
        elif self.end_condition == "verify":
            logging.debug("IterativeProbe._should_terminate_conversation() using verify")
            return self.verify_is_last_response_success(attempt)
        else:
            raise ValueError(f"Unsupported end condition '{self.end_condition}'")

    def generate_next_turn_str(self, conversation: garak.attempt.Conversation, last_attempt: garak.attempt.Attempt) -> str:
        """Function to be overridden with logic to get the next turn of the conversation based on the previous turn"""
        raise NotImplementedError

    def generate_next_turn_attempt(self, conversation: garak.attempt.Conversation, last_attempt: garak.attempt.Attempt) -> garak.attempt.Attempt:
        """Function to be overridden with logic to get a conversation object for the next turn of the conversation based on the previous turn"""
        next_turn_str = self.generate_next_turn_str(conversation, last_attempt)
        next_turn_conv = copy.deepcopy(conversation)
        next_turn_conv.turns.append(garak.attempt.Turn("user", garak.attempt.Message(text=next_turn_str)))
        next_turn_attempt = self._create_attempt(next_turn_conv)
        return next_turn_attempt

    def probe(self, generator):
        """Wrapper generating all attempts and handling execution against generator"""
        if self.end_condition == "detector":
            self.detector = garak._plugins.load_plugin(f"detectors.{self.primary_detector}") # TODO: Ideally we shouldn't be instantiating the detector again just for this. Is there a way for the probe to call the detector or use detector results withotu reinstantiating? Should we have a new subclass of Harness to shange how probe.probe() is even used or is that going too far?

        logging.debug("In IterativeProbe.probe() generating init turns")
        self.init_turns = self.generate_init_turns()
        self.generator = generator
        all_attempts_completed = list()
        attempts_todo = self.create_init_attempts(self.init_turns)
        self.max_attempts_before_termination = len(self.init_turns) * self.soft_probe_prompt_cap

        if len(_config.buffmanager.buffs) > 0:
            attempts_todo = self._buff_hook(attempts_todo) # TODO: What's actually happening here? Is it possible to abstract it out at attempt creation?

        logging.debug("In IterativeProbe.probe() running init turns")
        attempts_completed = self._execute_all(attempts_todo)
        all_attempts_completed.extend(attempts_completed)

        # TODO: This implementation is definitely expanding the generations tree in BFS fashion. Do we want to allow an option for DFS? Also what about the type of sampling which only duplicates the initial turn? BFS is nice because we can just reuse Probe._execute_all() which may not be an option if we are only duplicating the initial turn.
        for turn_num in range(1, self.max_turns):
            attempts_todo = list()
            for attempt in attempts_completed:
                should_terminate_per_output = self._should_terminate_conversation(attempt)
                conversations_to_continue = [attempt.conversations[idx] for idx, should_terminate in enumerate(should_terminate_per_output) if not should_terminate] # TODO: At this point, we can estimate whether the next turn would cause the three size to exceed max_attempts_before_termination. Should we break out of the loop here instead?
                next_turn_attempts = [self.generate_next_turn_attempt(conversation, attempt) for conversation in conversations_to_continue] # TODO: This can be slow. Do we want to add parallelization / at least a tqdm bar?
                attempts_todo.extend(next_turn_attempts)
                
            print("Turn %d: Attempts created: %d" % (turn_num, len(attempts_todo)))
            if len(attempts_todo) == 0:
                print("No new attempts created for turn %d; Breaking out of loop" % turn_num)
                break

            if len(_config.buffmanager.buffs) > 0:
                attempts_todo = self._buff_hook(attempts_todo)

            attempts_completed = self._execute_all(attempts_todo)
            all_attempts_completed.extend(attempts_completed)

            print("End of turn %d; Attempts this turn: %d; Total attempts completed: %d" % (turn_num, len(attempts_completed), len(all_attempts_completed)))

            if len(all_attempts_completed) > self.max_attempts_before_termination:
                print("Max attempts before termination reached; Breaking out of loop")
                break

        print("Probe exiting; Total attempts completed: %d" % len(all_attempts_completed))

        return all_attempts_completed