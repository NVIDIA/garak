# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Patch-only injector for the system_prompt channel."""

import garak.channels
from garak import _config
from garak.exception import InvalidInjectionPlanError
from garak.injection import (
    Coverage,
    Delivery,
    InjectionBinding,
    InjectionEvidence,
    InjectionPlan,
    Surface,
    SystemPromptPatch,
)
from garak.injectors.base import Injector

# plan operations the prompt injector understands, and the fields each
# carries beyond the shared "op"
PROMPT_OPERATIONS = {
    "replace_text": {"text"},
    "append_text": {"text"},
    "insert_at_marker": {"text", "marker"},
}


class SystemPromptBinding(InjectionBinding):
    """One system prompt patch bound to one generation.

    The payload rides in the patch itself: once the generator applies
    it, the delivery is complete, so the evidence reports delivery and
    no tool events.
    """

    def __init__(self, patch: SystemPromptPatch, execution_id: str) -> None:
        super().__init__()
        self.execution_id = execution_id
        self.target_patch = patch

    def collect_evidence(self) -> InjectionEvidence:
        """Report the patch delivery; a patch channel has no tool events."""
        return InjectionEvidence(
            execution_id=self.execution_id,
            delivery=Delivery(delivered=True),
            coverage=Coverage(errors=tuple(self.coverage_errors)),
            events=(),
        )

    def _close(self) -> None:
        pass  # a patch leaves nothing to release


class SystemPrompt(Injector):
    """Injector that delivers payloads through the system prompt channel.

    There is no external backend: the binding's patch carries the
    payload, and the generator splices it into its own request. The
    scenario's operations pick the patch mode — ``replace_text``,
    ``append_text``, or ``insert_at_marker``.
    """

    doc_uri = "https://github.com/NVIDIA/garak/issues/1652"
    active = True
    channels = frozenset({garak.channels.SYSTEM_PROMPT})

    DEFAULT_PARAMS = {
        # surfaces are optional: without config, one system_prompt surface
        "surfaces": {},
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)
        self._configured_surfaces = tuple(
            self._surface_from_config(name, entry)
            for name, entry in (self.surfaces or {}).items()
        )

    def offered_surfaces(self) -> tuple[Surface, ...]:
        """Return the configured surfaces, or one default surface."""
        if self._configured_surfaces:
            return self._configured_surfaces
        return (
            Surface(
                name=garak.channels.SYSTEM_PROMPT,
                channel=garak.channels.SYSTEM_PROMPT,
                attach={"patch": garak.channels.PATCH_SYSTEM_PROMPT},
            ),
        )

    def _surface_from_config(self, name: str, entry: dict) -> Surface:
        if not isinstance(entry, dict):
            raise InvalidInjectionPlanError(
                f"surface {name!r} in {self.fullname} config must be a mapping"
            )
        channel = entry.get("channel", garak.channels.SYSTEM_PROMPT)
        if channel != garak.channels.SYSTEM_PROMPT:
            raise InvalidInjectionPlanError(
                f"surface {name!r} in {self.fullname} config names channel "
                f"{channel!r}; this injector only patches "
                f"{garak.channels.SYSTEM_PROMPT}"
            )
        attach = entry.get("attach", {"patch": garak.channels.PATCH_SYSTEM_PROMPT})
        if not isinstance(attach, dict) or attach.get("patch") not in (
            None,
            garak.channels.PATCH_SYSTEM_PROMPT,
        ):
            raise InvalidInjectionPlanError(
                f"surface {name!r} in {self.fullname} config attaches "
                f"{attach!r}; this injector only attaches "
                f"{garak.channels.PATCH_SYSTEM_PROMPT}"
            )
        return Surface(name=name, channel=channel, attach=attach)

    def validate(self, plan: InjectionPlan, surface: Surface) -> None:
        """Reject plans the system prompt patch cannot express."""
        super().validate(plan, surface)
        if len(plan.operations) != 1:
            raise InvalidInjectionPlanError(
                "a system prompt plan carries exactly one operation; "
                f"got {len(plan.operations)}"
            )
        operation = plan.operations[0]
        if not isinstance(operation, dict):
            raise InvalidInjectionPlanError(
                f"the operation is not a mapping: {operation!r}"
            )
        op = operation.get("op")
        if op not in PROMPT_OPERATIONS:
            raise InvalidInjectionPlanError(
                f"the system prompt injector cannot express {op!r}; it "
                f"supports {sorted(PROMPT_OPERATIONS)}"
            )
        allowed = PROMPT_OPERATIONS[op] | {"op"}
        unknown = set(operation) - allowed
        if unknown:
            raise InvalidInjectionPlanError(
                f"the operation ({op}) carries unknown fields {sorted(unknown)}; "
                f"allowed are {sorted(allowed)}"
            )
        if not operation.get("text"):
            raise InvalidInjectionPlanError(f"the operation ({op}) is missing its text")
        if op == "insert_at_marker" and not operation.get("marker"):
            raise InvalidInjectionPlanError(
                "insert_at_marker needs a marker to splice at"
            )

    def bind(
        self, plan: InjectionPlan, surface: Surface, execution_id: str
    ) -> SystemPromptBinding:
        """Build the system prompt patch for one execution."""
        operation = plan.operations[0]
        mode = {
            "replace_text": "replace",
            "append_text": "append",
            "insert_at_marker": "insert_at_marker",
        }[operation["op"]]
        return SystemPromptBinding(
            SystemPromptPatch(
                mode=mode,
                text=operation["text"],
                marker=operation.get("marker"),
            ),
            execution_id,
        )
