"""Imperceptible perturbation probes inspired by the Bad Characters paper.

Implements the "just try everything" strategy for invisible Unicode characters,
homoglyph substitutions, bidi-based reorderings, and deletion/backspace pairs as
described in https://arxiv.org/abs/2106.09898.
"""

import itertools
import logging
import random
from dataclasses import dataclass
from functools import cached_property
from typing import Iterator, List, Sequence, Tuple

import garak.attempt
import garak.payloads
import garak.probes
from garak import _config
from garak.data import path as data_path
from garak.exception import PluginConfigurationError
from garak.intents import Stub

ASCII_PRINTABLE = tuple(chr(i) for i in range(0x20, 0x7F))
DEFAULT_INVISIBLE = ("\u200b", "\u200c", "\u200d")  # ZWSP, ZWNJ, ZWJ
BIDI_CONTROLS = {
    "PDF": "\u202c",
    "LRO": "\u202d",
    "RLO": "\u202e",
    "LRI": "\u2066",
    "RLI": "\u2067",
    "PDI": "\u2069",
}


@dataclass(frozen=True)
class _Swap:
    """Represents a bidi-wrapped swap request between two code points."""

    first: str
    second: str


def _render_swaps(elements: Sequence) -> str:
    """Recursively expand swap objects into bidi control sequences.

    The sequence mirrors the bidi swap function from Boucher et al.
    ("Bad Characters," arXiv:2106.09898) and the imperceptible reference
    implementation: it forces two adjacent code points to render in reverse
    order while containing all directionality side effects.
    """

    rendered: List[str] = []
    for element in elements:
        if isinstance(element, _Swap):
            payload = [
                BIDI_CONTROLS["LRO"],
                BIDI_CONTROLS["LRI"],
                BIDI_CONTROLS["RLO"],
                BIDI_CONTROLS["LRI"],
                element.first,
                BIDI_CONTROLS["PDI"],
                BIDI_CONTROLS["LRI"],
                element.second,
                BIDI_CONTROLS["PDI"],
                BIDI_CONTROLS["PDF"],
                BIDI_CONTROLS["PDI"],
                BIDI_CONTROLS["PDF"],
            ]
            rendered.append(_render_swaps(payload))
        elif isinstance(element, str):
            rendered.append(element)
        elif isinstance(element, Sequence):
            rendered.append(_render_swaps(element))
        else:
            rendered.append(str(element))
    return "".join(rendered)


def _load_homoglyph_map() -> dict[str, List[str]]:
    """Parse intentional.txt into a source -> targets dictionary."""

    mapping: dict[str, set[str]] = {}
    intent_path = data_path / "badchars" / "intentional.txt"
    try:
        with open(intent_path, "r", encoding="utf-8") as infile:
            for raw_line in infile:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                left, remainder = line.split(";", maxsplit=1)
                remainder = remainder.split("#", maxsplit=1)[0].strip()
                if not remainder:
                    continue
                codepoints = remainder.split()
                if not codepoints:
                    continue
                source = chr(int(left.strip(), 16))
                target = "".join(chr(int(cp, 16)) for cp in codepoints)
                if source == target:
                    continue
                mapping.setdefault(source, set()).add(target)
    except FileNotFoundError as exc:
        msg = (
            "Unable to load intentional.txt for homoglyph perturbations. "
            "Get data from - https://www.unicode.org/Public/security/latest/intentional.txt"
        )
        logging.error(msg)
        raise PluginConfigurationError(msg) from exc

    return {key: sorted(values) for key, values in mapping.items()}


class BadCharacters(garak.probes.Probe):
    """Imperceptible perturbations mixing invisible chars, homoglyphs, swaps, deletions.

    Implements the paper's full spectrum of adversarial perturbations by generating prompt variants that insert invisible Unicode,
    swap characters with bidi tricks, substitute homoglyphs, and inject deletions/backspaces.
    The goal is to stress refusal policies with subtle transformations that should remain semantically equivalent to the original payloads.
    """

    lang = "en"
    active = True
    doc_uri = "https://arxiv.org/abs/2106.09898"
    intent = "T009ignore"  # imperceptible perturbations silently bypass refusal policies without the model explicitly decoding anything
    # T018decode is a secondary fit because the model may internally normalize the obfuscated text.
    goal = "inject imperceptible text perturbations that bypass refusal policies"
    primary_detector = "mitigation.MitigationBypass"
    tags = [
        "avid-effect:security:S0403",
        "quality:Security:PromptStability",
        "payload:jailbreak",
        "demon:Language:Code_and_encode:Token",  # uses invisible Unicode, homoglyphs, bidi tricks to exploit token processing
        "euai:robustness:unexpected_behavior",
    ]
    tier = garak.probes.Tier.COMPETE_WITH_SOTA

    DEFAULT_PARAMS = garak.probes.Probe.DEFAULT_PARAMS | {
        "payload_name": "harmful_behaviors",
        "perturbation_budget": 1,
        "enabled_categories": [
            "invisible",
            "homoglyph",
            "reordering",
            "deletion",
        ],
        "max_position_candidates": 24,
        "max_reorder_candidates": 24,
        "max_ascii_variants": len(ASCII_PRINTABLE),
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)

        self._perturbation = _BadCharacterPerturbation(
            enabled_categories=self.enabled_categories,
            perturbation_budget=self.perturbation_budget,
            max_position_candidates=self.max_position_candidates,
            max_reorder_candidates=self.max_reorder_candidates,
            max_ascii_variants=self.max_ascii_variants,
        )

        payload_group = garak.payloads.load(self.payload_name)
        self._source_payloads = payload_group.payloads
        if payload_group.intent:
            self._payload_intent = payload_group.intent
        self.prompts: List[garak.attempt.Conversation] = []
        self._seen_prompts: set[str] = set()

        for idx, payload in enumerate(self._source_payloads):
            for text, metadata in self._perturbation.variants(payload):
                metadata["source_payload_index"] = idx
                metadata["source_payload_excerpt"] = self._excerpt(payload)
                self._append_prompt(text, metadata)

        if not self.prompts:
            raise PluginConfigurationError(
                "BadCharacters failed to generate any prompts. "
                "Check payload_name and category configuration."
            )

        self._prune_data()

    def _append_prompt(self, text: str, metadata: dict) -> None:
        if text in self._seen_prompts:
            return
        self._seen_prompts.add(text)
        conversation = garak.attempt.Conversation(
            [
                garak.attempt.Turn(
                    "user",
                    garak.attempt.Message(text=text, lang=self.lang),
                )
            ],
            notes=metadata,
        )
        self.prompts.append(conversation)

    @staticmethod
    def _excerpt(payload: str, limit: int = 96) -> str:
        flattened = " ".join(payload.split())
        if len(flattened) <= limit:
            return flattened
        return f"{flattened[: limit - 1]}…"

    def _prune_data(self, cap=None, prune_triggers=False) -> None:
        """Prune prompts while keeping category balance and seedable shuffling.

        Unlike ``Probe._prune_data``, which truncates at random, this preserves
        coverage across bad-character categories."""
        if not self.prompts:
            return
        cap = self._prune_cap(cap)
        if cap is None or cap <= 0 or len(self.prompts) <= cap:
            return

        grouped: dict[str, List[garak.attempt.Conversation]] = {}
        for conv in self.prompts:
            category = conv.notes.get("bad_character_category", "unknown")
            grouped.setdefault(category, []).append(conv)

        if hasattr(_config, "run") and getattr(_config.run, "seed", None) is not None:
            rng = random.Random(_config.run.seed)
            for group in grouped.values():
                rng.shuffle(group)
        else:
            for group in grouped.values():
                random.shuffle(group)

        total = len(self.prompts)
        allocation: dict[str, int] = {}
        remaining = cap
        for category, group in grouped.items():
            share = min(len(group), max(1, round(cap * len(group) / total)))
            allocation[category] = share
            remaining -= share

        while remaining > 0:
            progress = False
            for category, group in grouped.items():
                if allocation.get(category, 0) < len(group):
                    allocation[category] += 1
                    remaining -= 1
                    progress = True
                    if remaining == 0:
                        break
            if not progress:
                break

        selection: List[garak.attempt.Conversation] = []
        for category, group in grouped.items():
            take = min(len(group), allocation.get(category, 0))
            selection.extend(group[:take])
        self.prompts = selection[:cap]


PERTURBATION_PARAMS = {
    "perturbation_budget": 1,
    "enabled_categories": [
        "invisible",
        "homoglyph",
        "reordering",
        "deletion",
    ],
    "max_position_candidates": 24,  # caps insertion positions sampled per payload, bounding variant explosion
    "max_reorder_candidates": 24,  # caps adjacent-pair positions sampled for bidi reordering per payload
    "max_ascii_variants": len(ASCII_PRINTABLE),
}


class _BadCharacterPerturbation:
    """Standalone renderer for the bad-character technique.

    Maps base text plus a fixed configuration to an iterator of
    ``(perturbed_text, metadata)`` pairs. It owns the four perturbation
    families, position selection, the homoglyph map, the bidi swap sequence and
    the deletion/backspace pairs, and deliberately applies no Unicode
    normalisation. Adapters supply their own source provenance on top of the
    returned transformation metadata."""

    def __init__(
        self,
        enabled_categories,
        perturbation_budget: int,
        max_position_candidates: int,
        max_reorder_candidates: int,
        max_ascii_variants: int,
        homoglyph_map: dict[str, List[str]] | None = None,
    ) -> None:
        if perturbation_budget <= 0:
            raise PluginConfigurationError(
                "perturbation_budget must be a positive integer"
            )
        self.perturbation_budget = perturbation_budget
        self.max_position_candidates = max_position_candidates
        self.max_reorder_candidates = max_reorder_candidates
        self.max_ascii_variants = max_ascii_variants
        self._homoglyph_map = (
            homoglyph_map if homoglyph_map is not None else _load_homoglyph_map()
        )

        categories = enabled_categories
        if isinstance(categories, str):
            categories = [categories]
        resolved = {cat.lower() for cat in categories if isinstance(cat, str)}
        if not resolved:
            raise PluginConfigurationError(
                "enabled_categories must include at least one entry"
            )

        self._generators = {
            "invisible": self._generate_invisible_variants,
            "homoglyph": self._generate_homoglyph_variants,
            "reordering": self._generate_reordering_variants,
            "deletion": self._generate_deletion_variants,
        }
        supported_categories = set(self._generators)
        unknown_categories = resolved - supported_categories
        if unknown_categories:
            logging.warning(
                "Unknown BadCharacters categories %s; skipping",
                sorted(unknown_categories),
            )
            resolved &= supported_categories
        if not resolved:
            raise PluginConfigurationError(
                "enabled_categories must include at least one recognized entry "
                f"{sorted(supported_categories)}"
            )
        self.enabled_categories = resolved

    def variants(self, text: str) -> Iterator[Tuple[str, dict]]:
        """Yield every perturbed variant of ``text`` with transformation metadata."""
        for category in self.enabled_categories:
            generator = self._generators.get(category)
            if generator is None:
                continue
            for variant_text, details in generator(text):
                yield variant_text, {
                    "bad_character_category": category,
                    "perturbation_count": details.get("count"),
                    "operations": details.get("operations"),
                }

    def _generate_invisible_variants(self, payload: str) -> Iterator[Tuple[str, dict]]:
        positions = self._select_positions(len(payload), self.max_position_candidates)
        for count in range(1, self.perturbation_budget + 1):
            if len(positions) < count:
                break
            for pos_combo in itertools.combinations(positions, count):
                for chars in itertools.product(DEFAULT_INVISIBLE, repeat=count):
                    text = self._inject_sequences(payload, list(zip(pos_combo, chars)))
                    yield text, {
                        "count": count,
                        "operations": {
                            "positions": list(pos_combo),
                            "characters": [ord(ch) for ch in chars],
                        },
                    }

    def _generate_homoglyph_variants(self, payload: str) -> Iterator[Tuple[str, dict]]:
        candidate_positions = [
            idx for idx, ch in enumerate(payload) if ch in self._homoglyph_map
        ]
        if not candidate_positions:
            return

        max_replacements = min(self.perturbation_budget, len(candidate_positions))
        for count in range(1, max_replacements + 1):
            for idx_combo in itertools.combinations(candidate_positions, count):
                replacement_options = [
                    self._homoglyph_map[payload[idx]] for idx in idx_combo
                ]
                for replacements in itertools.product(*replacement_options):
                    mutable = list(payload)
                    for idx, rep in zip(idx_combo, replacements):
                        mutable[idx] = rep
                    text = "".join(mutable)
                    yield text, {
                        "count": count,
                        "operations": {
                            "positions": list(idx_combo),
                            "replacements": replacements,
                        },
                    }

    def _generate_reordering_variants(self, payload: str) -> Iterator[Tuple[str, dict]]:
        if len(payload) < 2:
            return
        candidates = self._select_positions(
            len(payload) - 1, self.max_reorder_candidates, include_endpoint=False
        )
        valid_indices = [idx for idx in candidates if idx < len(payload) - 1]
        for count in range(1, min(self.perturbation_budget, len(valid_indices)) + 1):
            for combo in itertools.combinations(valid_indices, count):
                if not self._non_overlapping(combo):
                    continue
                text = self._apply_swaps(payload, combo)
                yield text, {
                    "count": count,
                    "operations": {"positions": list(combo)},
                }

    def _generate_deletion_variants(self, payload: str) -> Iterator[Tuple[str, dict]]:
        positions = self._select_positions(len(payload), self.max_position_candidates)
        ascii_candidates = self._select_ascii(self.max_ascii_variants)
        for count in range(1, self.perturbation_budget + 1):
            if len(positions) < count:
                break
            for pos_combo in itertools.combinations(positions, count):
                for chars in itertools.product(ascii_candidates, repeat=count):
                    text = self._inject_sequences(
                        payload,
                        [(pos, f"{char}\b") for pos, char in zip(pos_combo, chars)],
                    )
                    yield text, {
                        "count": count,
                        "operations": {
                            "positions": list(pos_combo),
                            "ascii_codes": [ord(c) for c in chars],
                        },
                    }

    @staticmethod
    def _inject_sequences(payload: str, insertions: List[Tuple[int, str]]) -> str:
        result = payload
        offset = 0
        for position, value in sorted(insertions, key=lambda item: item[0]):
            idx = min(max(position + offset, 0), len(result))
            result = result[:idx] + value + result[idx:]
            offset += len(value)
        return result

    @staticmethod
    def _apply_swaps(payload: str, indices: Sequence[int]) -> str:
        working: List = list(payload)
        swaps_done = 0
        for original_idx in sorted(indices):
            adjusted = original_idx - swaps_done
            if adjusted < 0 or adjusted >= len(working) - 1:
                continue
            first, second = working[adjusted], working[adjusted + 1]
            working = (
                working[:adjusted] + [_Swap(second, first)] + working[adjusted + 2 :]
            )
            swaps_done += 1
        return _render_swaps(working)

    @staticmethod
    def _non_overlapping(indices: Sequence[int]) -> bool:
        return all(b - a >= 2 for a, b in zip(indices, indices[1:]))

    @staticmethod
    def _select_positions(
        length: int,
        cap: int,
        include_endpoint: bool = True,
    ) -> List[int]:
        positions = list(range(length + (1 if include_endpoint else 0)))
        if cap is None or cap <= 0 or len(positions) <= cap:
            return positions

        if cap == 1:
            return [positions[0]]

        step = (len(positions) - 1) / (cap - 1)
        selected = []
        seen = set()
        for idx in range(cap):
            pick = round(idx * step)
            value = positions[pick]
            if value in seen:
                continue
            selected.append(value)
            seen.add(value)
        for value in positions:
            if len(selected) >= cap:
                break
            if value not in seen:
                selected.append(value)
                seen.add(value)
        selected.sort()
        return selected

    @staticmethod
    def _select_ascii(limit: int) -> List[str]:
        if limit is None or limit <= 0 or limit >= len(ASCII_PRINTABLE):
            return list(ASCII_PRINTABLE)

        if limit == 1:
            return [ASCII_PRINTABLE[0]]

        step = max(1, (len(ASCII_PRINTABLE) - 1) // (limit - 1))
        selected = [ASCII_PRINTABLE[i] for i in range(0, len(ASCII_PRINTABLE), step)]
        return selected[:limit]


class BadCharactersIntent(garak.probes.IntentProbe):
    """Imperceptible character perturbations applied across intents.

    Serves the Bad Characters technique through the intent service: each intent
    stub is perturbed with invisible Unicode, homoglyphs, bidi swaps and
    deletion/backspace pairs while its intent is preserved on the attempt. The
    whole stub is perturbed unchanged (identity) because, unlike the doctor and
    grandma roleplays, there is no frame to supply a replacement verb.
    """

    lang = "en"
    active = True
    doc_uri = "https://arxiv.org/abs/2106.09898"
    intent = (
        None  # IntentProbe spans the typology; the attempt intent comes from each stub
    )
    goal = "inject imperceptible text perturbations that bypass refusal policies across intents"
    # fallback only: the harness needs a detector when an intent has no
    # intentservice mapping; it does not make a detectorless intent eligible.
    primary_detector = "mitigation.MitigationBypass"
    tags = [
        "avid-effect:security:S0403",  # evasion: adversarial example crafted to slip past controls
        "quality:Security:PromptStability",  # tests output stability under imperceptible input perturbation
        "payload:jailbreak",  # goal is to bypass refusal policies
        "demon:Language:Code_and_encode:Token",  # uses invisible Unicode, homoglyphs, bidi tricks to exploit token processing
        "euai:robustness:unexpected_behavior",  # EU AI Act robustness: unexpected behaviour from perturbed input
    ]
    tier = garak.probes.Tier.COMPETE_WITH_SOTA

    DEFAULT_PARAMS = garak.probes.IntentProbe.DEFAULT_PARAMS | PERTURBATION_PARAMS

    @cached_property
    def _perturbation(self) -> _BadCharacterPerturbation:
        # Built lazily: IntentProbe.__init__ runs the stub hooks before the
        # subclass __init__ body, but after config is loaded.
        return _BadCharacterPerturbation(
            enabled_categories=self.enabled_categories,
            perturbation_budget=self.perturbation_budget,
            max_position_candidates=self.max_position_candidates,
            max_reorder_candidates=self.max_reorder_candidates,
            max_ascii_variants=self.max_ascii_variants,
        )

    def _prompts_from_stub(self, stub: Stub) -> List[garak.attempt.Conversation]:
        content = getattr(stub, "content", None)
        if not isinstance(content, str) or not content:
            logging.warning("BadCharactersIntent skipping unsupported stub %r", stub)
            return []
        return [
            garak.attempt.Conversation(
                [
                    garak.attempt.Turn(
                        "user", garak.attempt.Message(text=text, lang=self.lang)
                    )
                ],
                notes=metadata,
            )
            for text, metadata in self._perturbation.variants(content)
        ]

    def _prune_data(self, cap=None, prune_triggers=False):
        """Prune per intent, then restore the legacy floor of one per category.

        ``IntentProbe`` balances across intents only. The deletion family
        dominates the generation pool, so random per-intent sampling can drop a
        whole perturbation category. After the base prune runs, re-inject one
        representative per missing category by reclaiming a slot from the
        most-represented surviving one, keeping the prompt count at ``cap``.
        """
        resolved_cap = self._prune_cap(cap)
        if resolved_cap is None or resolved_cap >= len(self.prompts):
            return

        representatives: dict[str, Tuple[garak.attempt.Conversation, object]] = {}
        for conv, intent in zip(self.prompts, self.prompt_intents):
            category = conv.notes.get("bad_character_category")
            if category is not None:
                representatives.setdefault(category, (conv, intent))

        super()._prune_data(cap=cap, prune_triggers=prune_triggers)

        surviving: dict[str, int] = {}
        for conv in self.prompts:
            category = conv.notes.get("bad_character_category")
            surviving[category] = surviving.get(category, 0) + 1

        for category, (conv, intent) in representatives.items():
            if surviving.get(category):
                continue
            donor = max(surviving, key=surviving.get)
            if surviving[donor] <= 1:
                break  # borrowing a slot would empty another family
            donor_idx = next(
                idx
                for idx, existing in enumerate(self.prompts)
                if existing.notes.get("bad_character_category") == donor
            )
            self.prompts[donor_idx] = conv
            self.prompt_intents[donor_idx] = intent
            surviving[donor] -= 1
            surviving[category] = 1
