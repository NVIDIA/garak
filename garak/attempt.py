"""Defines the Attempt class, which encapsulates a prompt with metadata and results"""

from types import GeneratorType
from typing import Any, List
import uuid

(
    ATTEMPT_NEW,
    ATTEMPT_STARTED,
    ATTEMPT_COMPLETE,
) = range(3)

roles = {"system", "user", "assistant"}


class Attempt:
    """A class defining objects that represent everything that constitutes a single attempt at evaluating an LLM.

    :param status: The status of this attempt; ``ATTEMPT_NEW``, ``ATTEMPT_STARTED``, or ``ATTEMPT_COMPLETE``
    :type status: int
    :param prompt: The processed prompt that will presented to the generator
    :type prompt: str
    :param probe_classname: Name of the probe class that originated this ``Attempt``
    :type probe_classname: str
    :param probe_params: Non-default parameters logged by the probe
    :type probe_params: dict, optional
    :param targets: A list of target strings to be searched for in generator responses to this attempt's prompt
    :type targets: List(str), optional
    :param outputs: The outputs from the generator in response to the prompt
    :type outputs: List(str)
    :param notes: A free-form dictionary of notes accompanying the attempt
    :type notes: dict
    :param detector_results: A dictionary of detector scores, keyed by detector name, where each value is a list of scores corresponding to each of the generator output strings in ``outputs``
    :type detector_results: dict
    :param goal: Free-text simple description of the goal of this attempt, set by the originating probe
    :type goal: str
    :param seq: Sequence number (starting 0) set in :meth:`garak.probes.base.Probe.probe`, to allow matching individual prompts with lists of answers/targets or other post-hoc ordering and keying
    :type seq: int
    :param messages: conversation turn histories; list of list of dicts have the format {"role": role, "content": text}, with actor being something like "system", "user", "assistant"
    :type messages: List(dict)
    :param lang: Language code for prompt as sent to the target
    :type lang: str, valid BCP47
    :param reverse_translation_outputs: The reverse translation of output based on the original language of the probe
    :param reverse_translation_outputs: List(str)

    Typical use:

    * An attempt tracks a seed prompt and responses to the prompt.
    * There is a 1:1 relationship between an attempt and a source prompt.
    * Attempts track all generations.
      This means ``messages`` tracks many histories, one per generation.
    * For compatibility, setting ``Attempt.prompt`` sets just one turn and the prompt is unpacked later when output is set.
      We don't know the number of generations to expect until some output arrives.
    * To keep alignment, generators must return lists of length generations.

    Patterns and expectations for Attempt access:

    * ``.prompt`` returns the first user prompt.
    * ``.outputs`` returns the most recent model outputs.
    * ``.latest_prompts`` returns a list of the latest user prompts.

    Patterns and expectations for Attempt setting:

    * ``.prompt`` sets the first prompt, or fails if the first prompt is already set.
    * ``.outputs`` sets a new layer of model responses.
      Silently handles expansion of prompt to multiple histories.
      Prompt must be set before outputs are set.
    * ``.latest_prompts`` adds a new set of user prompts.
    """

    def __init__(
        self,
        status=ATTEMPT_NEW,
        prompt=None,
        probe_classname=None,
        probe_params=None,
        targets=None,
        notes=None,
        detector_results=None,
        goal=None,
        seq=-1,
        lang=None,  # language code for prompt as sent to the target
        reverse_translation_outputs=None,
    ) -> None:
        self.uuid = uuid.uuid4()
        self.messages = []

        self.status = status
        self.probe_classname = probe_classname
        self.probe_params = {} if probe_params is None else probe_params
        self.targets = [] if targets is None else targets
        self.notes = {} if notes is None else notes
        self.detector_results = {} if detector_results is None else detector_results
        self.goal = goal
        self.seq = seq
        if prompt is not None:
            self.prompt = prompt
        self.lang = lang
        self.reverse_translation_outputs = (
            {} if reverse_translation_outputs is None else reverse_translation_outputs
        )

    def as_dict(self) -> dict:
        """Converts the attempt to a dictionary."""
        return {
            "entry_type": "attempt",
            "uuid": str(self.uuid),
            "seq": self.seq,
            "status": self.status,
            "probe_classname": self.probe_classname,
            "probe_params": self.probe_params,
            "targets": self.targets,
            "prompt": self.prompt,
            "outputs": list(self.outputs),
            "detector_results": {k: list(v) for k, v in self.detector_results.items()},
            "notes": self.notes,
            "goal": self.goal,
            "messages": self.messages,
            "lang": self.lang,
            "reverse_translation_outputs": list(self.reverse_translation_outputs),
        }

    @property
    def prompt(self):
        if len(self.messages) == 0:  # nothing set
            return None
        if isinstance(self.messages[0], dict):  # only initial prompt set
            return self.messages[0]["content"]
        if isinstance(self.messages, list):  # there's initial prompt plus some history
            return self.messages[0][0]["content"]
        else:
            raise ValueError(
                "Message history of attempt uuid %s in unexpected state, sorry: "
                % str(self.uuid)
                + repr(self.messages)
            )

    @property
    def outputs(self):
        if len(self.messages) and isinstance(self.messages[0], list):
            # work out last_output_turn that was assistant
            assistant_turns = [
                idx
                for idx, val in enumerate(self.messages[0])
                if val["role"] == "assistant"
            ]
            if assistant_turns == []:
                return []
            last_output_turn = max(assistant_turns)
            # return these (via list compr)
            return [m[last_output_turn]["content"] for m in self.messages]
        else:
            return []

    @property
    def latest_prompts(self):
        if len(self.messages[0]) > 1:
            # work out last_output_turn that was user
            last_output_turn = max(
                [
                    idx
                    for idx, val in enumerate(self.messages[0])
                    if val["role"] == "user"
                ]
            )
            # return these (via list compr)
            return [m[last_output_turn]["content"] for m in self.messages]
        else:
            return (
                self.prompt
            )  # returning a string instead of a list tips us off that generation count is not yet known

    @property
    def all_outputs(self):
        all_outputs = []
        if len(self.messages) and not isinstance(self.messages[0], dict):
            for thread in self.messages:
                for turn in thread:
                    if turn["role"] == "assistant":
                        all_outputs.append(turn["content"])
        return all_outputs

    @prompt.setter
    def prompt(self, value):
        if value is None:
            raise TypeError("'None' prompts are not valid")
        self._add_first_turn("user", value)

    @outputs.setter
    def outputs(self, value):
        if not (isinstance(value, list) or isinstance(value, GeneratorType)):
            raise TypeError("Value for attempt.outputs must be a list or generator")
        value = list(value)
        if len(self.messages) == 0:
            raise TypeError("A prompt must be set before outputs are given")
        # do we have only the initial prompt? in which case, let's flesh out messages a bit
        elif len(self.messages) == 1 and isinstance(self.messages[0], dict):
            self._expand_prompt_to_histories(len(value))
        # append each list item to each history, with role:assistant
        self._add_turn("assistant", value)

    @latest_prompts.setter
    def latest_prompts(self, value):
        assert isinstance(value, list)
        self._add_turn("user", value)

    def prompt_for(self, lang) -> str:
        """prompt for a known language

        When "*" or None are passed returns the prompt passed to the model
        """
        if lang is not None and self.lang != "*" and lang != "*" and self.lang != lang:
            return self.notes.get(
                "pre_translation_prompt", self.prompt
            )  # update if found in notes

        return self.prompt

    def outputs_for(self, lang) -> List[str]:
        """outputs for a known language

        When "*" or None are passed returns the original model output
        """
        if lang is not None and self.lang != "*" and lang != "*" and self.lang != lang:
            return self.reverse_translation_outputs
        return self.all_outputs

    def _expand_prompt_to_histories(self, breadth):
        """expand a prompt-only message history to many threads"""
        if len(self.messages) == 0:
            raise TypeError(
                "A prompt needs to be set before it can be expanded to conversation threads"
            )
        elif isinstance(self.messages[0], list):
            raise TypeError(
                "attempt.messages contains lists, expected a single dict of one turn"
            )

        base_message = dict(self.messages[0])
        self.messages = [[base_message] for i in range(breadth)]

    def _add_first_turn(self, role: str, content: str) -> None:
        """add the first turn (after a prompt) to a message history"""

        if len(self.messages):
            if isinstance(self.messages[0], list):
                raise TypeError(
                    "Cannot set prompt of attempt uuid %s with content already in message history: "
                    % str(self.uuid)
                    + repr(self.messages)
                )

            elif isinstance(self.messages[0], dict):  # we only have the prompt
                if self.messages[0]["role"] == "user":
                    self.messages[0] = {"role": role, "content": content}
                else:
                    raise ValueError(
                        "Unexpected state in attempt messages - first message not from user"
                    )

        else:
            self.messages.append({"role": role, "content": content})
            return

    def _add_turn(self, role: str, contents: List[str]) -> None:
        """add a 'layer' to a message history.

        the contents should be as broad as the established number of
        generations for this attempt. e.g. if there's a prompt and a
        first turn with k responses, every add_turn on the attempt
        must give a list with k entries.
        """
        if len(contents) != len(self.messages):
            raise ValueError(
                "Message history misalignment in attempt uuid %s: tried to add %d items to %d message histories"
                % (str(self.uuid), len(contents), len(self.messages))
            )
        if role == "user" and (
            len(self.messages) == 0 or isinstance(self.messages[0], dict)
        ):
            raise ValueError(
                "Can only add a list of user prompts after at least one system generation, so that generations count is known"
            )
        if role in roles:
            for idx, entry in enumerate(contents):
                self.messages[idx].append({"role": role, "content": entry})
            return
        raise ValueError(
            "Conversation turn role must be one of '%s', got '%s'"
            % ("'/'".join(roles), role)
        )
