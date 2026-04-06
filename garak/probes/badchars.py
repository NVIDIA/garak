"""Imperceptible perturbation probes inspired by the Bad Characters paper.

Implements the "just try everything" strategy for invisible Unicode characters,
homoglyph substitutions, bidi-based reorderings, and deletion/backspace pairs as
described in https://arxiv.org/abs/2106.09898.
"""

import itertools
import logging
import random
from dataclasses import dataclass
from typing import Iterator, List, Sequence, Tuple

import garak.attempt
import garak.payloads
import garak.probes
from garak import _config
from garak.data import path as data_path
from garak.exception import PluginConfigurationError

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
    goal = "inject imperceptible text perturbations that bypass refusal policies"
    primary_detector = "mitigation.MitigationBypass"
    tags = [
        "avid-effect:security:S0403",
        "quality:Security:PromptStability",
        "payload:jailbreak",
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
        "follow_prompt_cap": True,
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        if self.perturbation_budget <= 0:
            raise PluginConfigurationError(
                "perturbation_budget must be a positive integer"
            )

        self._homoglyph_map = _load_homoglyph_map()
        categories = self.enabled_categories
        if isinstance(categories, str):
            categories = [categories]
        self._enabled_categories = {
            cat.lower() for cat in categories if isinstance(cat, str)
        }
        if not self._enabled_categories:
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
        unknown_categories = self._enabled_categories - supported_categories
        if unknown_categories:
            logging.warning(
                "Unknown BadCharacters categories %s; skipping",
                sorted(unknown_categories),
            )
            self._enabled_categories &= supported_categories
        if not self._enabled_categories:
            raise PluginConfigurationError(
                "enabled_categories must include at least one recognized entry "
                f"{sorted(supported_categories)}"
            )

        payload_group = garak.payloads.load(self.payload_name)
        self._source_payloads = payload_group.payloads
        self.prompts: List[garak.attempt.Conversation] = []
        self._seen_prompts: set[str] = set()

        for idx, payload in enumerate(self._source_payloads):
            for text, metadata in self._generate_variants(payload, idx):
                self._append_prompt(text, metadata)

        if not self.prompts:
            raise PluginConfigurationError(
                "BadCharacters failed to generate any prompts. "
                "Check payload_name and category configuration."
            )

        if (
            self.follow_prompt_cap
            and self.soft_probe_prompt_cap is not None
            and len(self.prompts) > self.soft_probe_prompt_cap
        ):
            self._downsample_prompts()

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

    def _generate_variants(
        self, payload: str, payload_idx: int
    ) -> Iterator[Tuple[str, dict]]:
        for category in self._enabled_categories:
            generator = self._generators.get(category)
            if generator is None:
                continue
            for variant_text, details in generator(payload):
                metadata = {
                    "bad_character_category": category,
                    "perturbation_count": details.get("count"),
                    "operations": details.get("operations"),
                    "source_payload_index": payload_idx,
                    "source_payload_excerpt": self._excerpt(payload),
                }
                yield variant_text, metadata

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

    def _inject_sequences(self, payload: str, insertions: List[Tuple[int, str]]) -> str:
        result = payload
        offset = 0
        for position, value in sorted(insertions, key=lambda item: item[0]):
            idx = min(max(position + offset, 0), len(result))
            result = result[:idx] + value + result[idx:]
            offset += len(value)
        return result

    def _apply_swaps(self, payload: str, indices: Sequence[int]) -> str:
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

    def _select_positions(
        self,
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
        step = max(1, (len(ASCII_PRINTABLE) - 1) // (limit - 1))
        selected = [ASCII_PRINTABLE[i] for i in range(0, len(ASCII_PRINTABLE), step)]
        return selected[:limit]

    @staticmethod
    def _excerpt(payload: str, limit: int = 96) -> str:
        flattened = " ".join(payload.split())
        if len(flattened) <= limit:
            return flattened
        return f"{flattened[: limit - 1]}…"

    def _downsample_prompts(self) -> None:
        """Downsample prompts while keeping category balance and seedable shuffling.

        Differs from Probe._prune_data, which randomly truncates without preserving
        category coverage."""
        if not self.prompts:
            return
        cap = self.soft_probe_prompt_cap
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
