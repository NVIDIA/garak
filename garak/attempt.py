"""Defines the Attempt class, which encapsulates a prompt with metadata and results"""

from dataclasses import dataclass, field, asdict, is_dataclass
from copy import deepcopy
from pathlib import Path
from types import GeneratorType
from typing import List, Optional, Union
import uuid

(
    ATTEMPT_NEW,
    ATTEMPT_STARTED,
    ATTEMPT_COMPLETE,
) = range(3)

roles = {"system", "user", "assistant"}


@dataclass
class Message:
    """Object to represent a single message posed to or received from a generator

    Messages can be prompts, replies, system prompts. While many prompts are text,
    they may also be (or include) images, audio, files, or even a composition of
    these. The Turn object encapsulates this flexibility.
    `Message` doesn't yet support multiple attachments of the same type.

    :param text: Text of the prompt/response
    :type text: str
    :param data_path: Path to attachment
    :type data_path: Union[str, Path]
    :param data_type: (type, encoding) Mime type of data
    :type data_type: Tuple(str, str)
    :param data_checksum: sha256 checksum of data loaded
    :type data_checksum: str
    :param data: Data to attach
    :type data: Any
    :param lang: language code for `text` content
    :type lang: str (bcp47 language code)
    :param notes: Free form dictionary of notes for the turn
    :type notes: dict
    """

    text: str = None
    lang: str = None
    data_path: Optional[str] = None
    data_type: Optional[str] = None
    data_checksum: Optional[str] = None
    # data: bytes = None  # should this dataclass attribute exist?
    notes: Optional[dict] = field(default_factory=dict)

    @property
    def data(self):
        if not hasattr(self, "_data"):
            if self.data_path is not None:
                import hashlib
                import mimetypes

                self.data_type = mimetypes.guess_type(self.data_path)
                self._data = Message._load_data(self.data_path)
                self.data_checksum = hashlib.sha256(
                    self._data, usedforsecurity=False
                ).hexdigest()
            else:
                return None
        return self._data

    @data.setter
    def data(self, value):
        if self.data_path is not None and hasattr(self, "_data"):
            raise ValueError("data_path has been set data cannot be modified")
        if self.data_type is None:
            raise ValueError("data_type must be set before data")
        self._data = value
        self.data_checksum = None
        if self._data:
            import hashlib

            self.data_checksum = hashlib.sha256(
                self._data, usedforsecurity=False
            ).hexdigest()

    @staticmethod
    def _load_data(data_path: Union[str, Path]):
        with open(data_path, "rb") as f:
            return f.read()


@dataclass
class Turn:
    """Object to attach actor context to a message, denoted as taking a `Turn` in the conversation

    :param role: Role of the participant who issued the utterance Expected: ["system", "user", "assistant"]
    :type role: str
    """

    role: str
    content: Message

    @classmethod
    def from_dict(cls, value: dict):
        entity = deepcopy(value)
        if "role" in entity.keys():
            role = entity["role"]
        else:
            raise ValueError("Expected `role` in Turn dict")
        message = entity.pop("content", {})
        if isinstance(message, str):
            content = Message(text=message)
        else:
            content = Message(**message)
        return cls(role=role, content=content)


@dataclass
class Conversation:
    """Class to maintain a sequence of Turn objects and, if relevant, apply conversation templates.

    :param turns: A list of Turns
    :type turns: list
    :param notes: Free form dictionary of notes for the conversation
    :type notes: dict
    """

    turns: List[Turn] = field(default_factory=list)
    notes: Optional[dict] = field(default_factory=dict)

    def last_message(self, role=None) -> Message:
        """The last message exchanged in the conversation

        :param role: Optional, role to search for
        :type role: str
        """
        if len(self.turns) < 1:
            raise ValueError("No messages available")
        if not role:
            return self.turns[-1].content
        for idx in range(len(self.turns) - 1, -1, -1):
            if role == self.turns[idx].role:
                return self.turns[idx].content
        raise ValueError(f"No messages for role: {role}")

    @staticmethod
    def from_dict(value: dict):
        entity = deepcopy(value)
        turns = entity.pop("turns", [])
        ret_val = Conversation(**entity)
        for turn in turns:
            ret_val.turns.append(Turn.from_dict(turn))
        return ret_val


class Attempt:
    """A class defining objects that represent everything that constitutes a single attempt at evaluating an LLM.

    :param status: The status of this attempt; ``ATTEMPT_NEW``, ``ATTEMPT_STARTED``, or ``ATTEMPT_COMPLETE``
    :type status: int
    :param prompt: The processed prompt that will presented to the generator
    :type prompt: Union[str|Turn|Conversation]
    :param probe_classname: Name of the probe class that originated this ``Attempt``
    :type probe_classname: str
    :param probe_params: Non-default parameters logged by the probe
    :type probe_params: dict, optional
    :param targets: A list of target strings to be searched for in generator responses to this attempt's prompt
    :type targets: List(str), optional
    :param outputs: The outputs from the generator in response to the prompt
    :type outputs: List(Message)
    :param notes: A free-form dictionary of notes accompanying the attempt
    :type notes: dict
    :param detector_results: A dictionary of detector scores, keyed by detector name, where each value is a list of scores corresponding to each of the generator output strings in ``outputs``
    :type detector_results: dict
    :param goal: Free-text simple description of the goal of this attempt, set by the originating probe
    :type goal: str
    :param seq: Sequence number (starting 0) set in :meth:`garak.probes.base.Probe.probe`, to allow matching individual prompts with lists of answers/targets or other post-hoc ordering and keying
    :type seq: int
    :param conversations: conversation turn histories
    :type conversations: List(Conversation)
    :param lang: Language code for prompt as sent to the target
    :type lang: str, valid BCP47
    :param reverse_translation_outputs: The reverse translation of output based on the original language of the probe
    :param reverse_translation_outputs: List(str)

    Typical use:

    * An attempt tracks a seed prompt and responses to the prompt.
    * There is a 1:1 relationship between an attempt and a source prompt.
    * Attempts track all generations.
      This means ``conversations`` tracks many histories, one per generation.
    * this means messages tracks many histories, one per generation
    * For compatibility, setting ``Attempt.prompt`` sets just one turn and the prompt is unpacked later when output is set.
      We don't know the number of generations to expect until some output arrives.
    * To keep alignment, generators must return lists of length generations.

    Patterns and expectations for Attempt access:

    * ``.prompt`` returns the first user prompt.
    * ``.outputs`` returns the most recent model outputs.

    Patterns and expectations for Attempt setting:

    * ``.prompt`` sets the first prompt, or fails if the first prompt is already set.
    * ``.outputs`` sets a new layer of model responses.
      Silently handles expansion of prompt to multiple histories.
      Prompt must be set before outputs are set.
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
        if prompt is not None:
            if isinstance(prompt, Conversation):
                self.conversations = [prompt]
            elif isinstance(prompt, str):
                msg = Message(text=prompt, lang=lang)
            elif isinstance(prompt, Message):
                msg = prompt
            else:
                raise TypeError("prompts must be of type str | Message | Conversation")
            if not hasattr(self, "conversations"):
                self.conversations = [Conversation([Turn("user", msg)])]
            self.prompt = self.conversations[0]
        else:
            self.conversations = [Conversation()]
        self.status = status
        self.probe_classname = probe_classname
        self.probe_params = {} if probe_params is None else probe_params
        self.targets = [] if targets is None else targets
        self.notes = {} if notes is None else notes
        self.detector_results = {} if detector_results is None else detector_results
        self.goal = goal
        self.seq = seq
        self.reverse_translation_outputs = (
            {} if reverse_translation_outputs is None else reverse_translation_outputs
        )

    def as_dict(self) -> dict:
        """Converts the attempt to a dictionary."""
        notes = {}
        for k, v in self.notes.items():
            if is_dataclass(v):
                notes[k] = asdict(v)
                continue
            if isinstance(v, list) and len(v) > 0 and is_dataclass(v[0]):
                notes[k] = [asdict(e) for e in v]
            else:
                notes[k] = v

        return {
            "entry_type": "attempt",
            "uuid": str(self.uuid),
            "seq": self.seq,
            "status": self.status,
            "probe_classname": self.probe_classname,
            "probe_params": self.probe_params,
            "targets": self.targets,
            "prompt": asdict(self.prompt),
            "outputs": [asdict(output) if output else None for output in self.outputs],
            "detector_results": {k: list(v) for k, v in self.detector_results.items()},
            "notes": notes,
            "goal": self.goal,
            "conversations": [
                asdict(conversation) for conversation in self.conversations
            ],
            "reverse_translation_outputs": [
                asdict(output) if output else None
                for output in self.reverse_translation_outputs
            ],
        }

    @property
    def prompt(self) -> Union[Conversation, None]:
        if hasattr(self, "_prompt"):
            return self._prompt
        # should this return a conversation with a user message.text == None?
        # possibly also consider a `raise` if prompt is accessed but not set
        # this would require contributors to be more defensive and guard for the
        # exception, though that may be a reasonable trade off.
        return None

    @property
    def lang(self):
        return self.prompt.turns[-1].content.lang

    @property
    def outputs(self) -> List[Message]:
        generated_outputs = list()
        if len(self.conversations) and isinstance(self.conversations[0], Conversation):
            for conversation in self.conversations:
                # work out last_output_turn that was assistant
                assistant_turns = [
                    idx
                    for idx, val in enumerate(conversation.turns)
                    if val.role == "assistant"
                ]
                if not assistant_turns:
                    continue
                last_output_turn = max(assistant_turns)
                generated_outputs.append(conversation.turns[last_output_turn].content)
        return generated_outputs

    @property
    def all_outputs(self) -> List[Message]:
        all_outputs = []
        if len(self.conversations) > 0:
            for conversation in self.conversations:
                for message in conversation.turns:
                    if message.role == "assistant":
                        all_outputs.append(message.content)
        return all_outputs

    @prompt.setter
    def prompt(self, value: Union[str | Message | Conversation]):
        if hasattr(self, "_prompt"):
            raise TypeError("prompt cannot be changed once set")
        if value is None:
            raise TypeError("'None' prompts are not valid")
        if isinstance(value, str):
            # note this does not contain a lang
            self._prompt = Conversation([Turn("user", Message(text=value))])
        if isinstance(value, Message):
            # make a copy to store an immutable object
            self._prompt = Conversation([Turn("user", Message(**asdict(value)))])
        if isinstance(value, Conversation):
            # make a copy to store an immutable object
            self._prompt = Conversation.from_dict(asdict(value))
        if not hasattr(self, "_prompt"):
            raise TypeError("prompt must be a Conversation, Message or str object")
        self.conversations = [Conversation.from_dict(asdict(self._prompt))]

    @outputs.setter
    def outputs(
        self, value: Union[GeneratorType | List[str | Message]]
    ) -> List[Message]:
        # these need to build or be Message objects and add to Conversations
        if not (isinstance(value, list) or isinstance(value, GeneratorType)):
            raise TypeError("Value for attempt.outputs must be a list or generator")
        value = list(value)
        # testing suggests this should only attempt to set if the initial prompt was already injected
        if len(self.conversations) == 0 or len(self.conversations[0].turns) == 0:
            raise TypeError("A prompt must be set before outputs are given")
        # do we have only the initial prompt? in which case, let's flesh out messages a bit
        elif (
            len(self.conversations) == 1 and len(value) > 1
        ):  # only attempt to expand if give more than one value
            self._expand_prompt_to_histories(len(value))
        # append each list item to each history, with role:assistant
        self._add_turn("assistant", value)

    def prompt_for(self, lang) -> Conversation:
        """prompt for a known language

        When "*" or None are passed returns the prompt passed to the model
        """
        if (
            lang is not None
            and self.prompt.last_message().lang != "*"
            and lang != "*"
            and self.prompt.last_message().lang != lang
        ):
            return self.notes.get(
                "pre_translation_prompt", self.prompt
            )  # update if found in notes

        return self.prompt

    def outputs_for(self, lang) -> List[Message]:
        """outputs for a known language

        When "*" or None are passed returns the original model output
        """
        if (
            lang is not None
            and self.prompt.last_message().lang != "*"
            and lang != "*"
            and self.prompt.last_message().lang != lang
        ):
            return (
                self.reverse_translation_outputs
            )  # this needs to be wired back in for support
        return self.outputs

    def _expand_prompt_to_histories(self, breadth):
        """expand a prompt-only message history to many threads"""
        if len(self.conversations[0].turns) == 0:
            raise TypeError(
                "A prompt needs to be set before it can be expanded to conversation threads"
            )
        elif len(self.conversations) > 1 or len(self.conversations[-1].turns) > len(
            self.prompt.turns
        ):
            raise TypeError(
                "attempt.conversations contains Conversations, expected a single Conversation object"
            )

        self.conversations = [deepcopy(self.conversations[0]) for _ in range(breadth)]

    def _add_turn(self, role: str, contents: List[Union[Message, str]]) -> None:
        """add a 'layer' to a message history.

        the contents should be as broad as the established number of
        generations for this attempt. e.g. if there's a prompt and a
        first turn with k responses, every add_turn on the attempt
        must give a list with k entries.
        """

        # this needs to accept a List[Union[str|Turn]]
        if len(contents) != len(self.conversations):
            raise ValueError(
                "Message history misalignment in attempt uuid %s: tried to add %d items to %d message histories"
                % (str(self.uuid), len(contents), len(self.conversations))
            )
        if role == "user" and len(self.conversations[0].turns) == 0:
            raise ValueError(
                "Can only add a list of user prompts after at least one system generation, so that generations count is known"
            )

        if role in roles:
            for idx, entry in enumerate(contents):
                content = entry
                if isinstance(entry, str):
                    content = Message(entry, lang=self.lang)
                self.conversations[idx].turns.append(Turn(role, content))
            return
        raise ValueError(
            "Conversation turn role must be one of '%s', got '%s'"
            % ("'/'".join(roles), role)
        )
