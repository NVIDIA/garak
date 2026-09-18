# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""**Inference Parameter Manipulation**

Sweep inference parameters to discover configurations that produce unsafe or
unreliable outputs, testing CWE-1434.

Probes in this module systematically vary generator inference parameters
(temperature, top_p, top_k, etc.) across the prompts of any existing probe,
measuring how behaviour changes under different settings. Pointing this at a
probe that covers a particular vulnerability reveals whether unusual parameter
settings make that vulnerability worse.

This supports detection of CWE-1434: Insecure Setting of Generative AI/ML Model
Inference Parameters.

Configuration example:

.. code-block:: yaml

    plugins:
        probes:
            hyperparams:
                HyperparamBasher:
                    source_probe: packagehallucination.Python
                    param_space:
                        temperature: [0.0, 0.5, 1.0, 1.5, 2.0]
                        top_p: [0.1, 0.5, 0.9, 1.0]
                    sweep_strategy: single

Further info:

* https://cwe.mitre.org/data/definitions/1434.html
* https://github.com/NVIDIA/garak/issues/1233
"""

import copy
import itertools
import logging
import random
from typing import Iterable

import numpy as np

from garak import _config, _plugins
from garak.attempt import Attempt
from garak.exception import PluginConfigurationError
import garak.probes


def _find_hook_in_mro(klass: type, hook_name: str) -> object | None:
    """Return the first override of *hook_name* in *klass*'s MRO below
    ``garak.probes.Probe``, or ``None`` if the hook is not overridden."""
    for cls in klass.__mro__:
        if cls is garak.probes.Probe:
            break
        fn = cls.__dict__.get(hook_name)
        if fn is not None:
            return fn
    return None


class HyperparamBasher(garak.probes.Probe):
    """Generic inference parameter sweep probe.

    Loads prompts from any existing probe (``source_probe``) and poses them to
    the generator under a range of inference parameter settings. The parameter
    space and sweep strategy are fully configurable.

    On the first call to ``probe()``, every parameter in ``param_space`` is
    validated against the generator: if a parameter does not exist on the
    generator a ``PluginConfigurationError`` is raised so that the caller can
    correct the configuration rather than silently running an incomplete sweep.

    **Source probe compatibility**

    * **Works correctly** — all source probes that do not define a custom
      ``_generator_precall_hook``.  This covers text/classifier-based probes
      (``packagehallucination.*``, ``dan.*``, ``snowball.*``, ``topic.*``,
      ``donotanswer.*``, ``lmrc.*``, etc.) as well as probes that use
      trigger-based detection (``continuation.*``, ``leakreplay.*``,
      ``latentinjection.*``, ``goodside.*``, ``propile.*``,
      ``web_injection.*``).  For trigger-based probes, per-prompt data arrays
      (e.g. ``triggers``, ``pii_types``) are copied from the source instance
      and the source's ``_attempt_prestore_hook`` is chained so that
      ``attempt.notes["triggers"]`` is populated correctly.

    * **Rejected at initialisation** — source probes that define a custom
      ``_generator_precall_hook`` (``promptinject.*``, ``divergence.Repeat``).
      Those hooks depend on instance state that cannot safely be transferred to
      ``HyperparamBasher``; a ``PluginConfigurationError`` is raised immediately.

    **Generator compatibility**

    This probe requires a generator that reads instance attributes dynamically
    when constructing API requests — ``openai.OpenAICompatible`` and its
    subclasses are the intended target.  Template-based generators such as
    ``rest.RestGenerator`` store inference params as attributes but never read
    them when building the request body, so the sweep has no effect and results
    are misleading.  ``_validate_params_against_generator`` cannot detect this
    because the attribute exists on the generator; it simply goes unused.  A
    ``WARNING`` is emitted when the generator's MRO does not include
    ``OpenAICompatible`` so that results from such generators are not trusted
    silently.

    Each completed attempt records the active parameter combination and the
    original generator values in ``attempt.notes`` for post-hoc analysis:

    * ``attempt.notes["hyperparam_combo"]`` – the params applied this attempt
    * ``attempt.notes["hyperparam_original"]`` – the pre-sweep original values

    Run ``python -m garak.analyze.hyperparam_summary --report <report>``
    after the run to produce a per-combo pass/fail summary from the harness
    detector results.
    """

    active = True
    lang = "*"
    parallelisable_attempts = True
    doc_uri = "https://cwe.mitre.org/data/definitions/1434.html"
    primary_detector = "always.Fail"  # overridden at init from source_probe
    tags = [
        "cwe:1434",  # insecure setting of generative AI/ML model inference parameters
    ]
    goal = "find inference parameter settings that degrade model safety or quality"
    tier = garak.probes.Tier.INFORMATIONAL

    DEFAULT_PARAMS = garak.probes.Probe.DEFAULT_PARAMS | {
        "source_probe": None,  # dotted probe name, e.g. "packagehallucination.Python"
        "param_space": {
            "temperature": [0.0, 0.5, 1.0, 1.5, 2.0],
        },
        "sweep_strategy": "single",  # "single" or "random"
        "random_samples": 20,
        "random_seed": None,  # set an int for reproducible random sweeps
        "follow_prompt_cap": True,
    }

    def __init__(self, config_root=_config):
        super().__init__(config_root=config_root)

        # Initialise hook-chaining state so _attempt_prestore_hook is safe to
        # call even when no source probe is configured.
        self._source_prestore_hook = None
        self._source_parallel_attrs: list[str] = []
        self._source_n_base_prompts = 0

        if self.source_probe is None:
            # no source configured; probe() will warn and return early
            self.prompts = []
            self._param_combos = []
            return

        source = _plugins.load_plugin(f"probes.{self.source_probe}")

        # Reject source probes that define a custom _generator_precall_hook;
        # their hooks depend on instance state that cannot be safely transferred
        # to HyperparamBasher (e.g. promptinject reads attempt.notes["settings"]
        # set by its own _attempt_prestore_hook; divergence reads self.override_maxlen).
        source_class = type(source)

        source_precall = _find_hook_in_mro(source_class, "_generator_precall_hook")
        if source_precall is not None:
            raise PluginConfigurationError(
                f"{self.__class__.__name__}: source probe '{self.source_probe}' "
                "defines a custom _generator_precall_hook, which is not supported. "
                "Choose a source probe that does not override _generator_precall_hook."
            )

        _n_source = len(source.prompts)
        self.prompts = list(copy.deepcopy(source.prompts))

        # If the source probe defines a custom _attempt_prestore_hook (e.g. to
        # populate attempt.notes["triggers"] for trigger-based detectors), chain
        # it so detection accuracy is preserved across the hyperparam sweep.
        # Strategy:
        #   1. Copy every instance-level list attribute of the source that has the
        #      same length as source.prompts — these are per-prompt parallel arrays
        #      (triggers, pii_types, attempt_descrs, …).  Track their names so
        #      _prune_data_parallel can keep them in sync with self.prompts.
        #   2. Copy any remaining source instance attributes not already on self
        #      (e.g. _pii_data_path) so the bound hook can access them.
        #   3. Bind the source class's hook function to self so it reads the copied
        #      attributes via self.<attr> rather than from the source instance.
        source_prestore_fn = _find_hook_in_mro(source_class, "_attempt_prestore_hook")
        if source_prestore_fn is not None:
            for attr, val in vars(source).items():
                if attr.startswith("__") or hasattr(self, attr):
                    continue
                if isinstance(val, list) and len(val) == _n_source:
                    # per-prompt parallel data — remember for sync pruning
                    self._source_parallel_attrs.append(attr)
                setattr(self, attr, copy.deepcopy(val))
            # Rebind to self so the hook reads our (pruned) copies of triggers etc.
            self._source_prestore_hook = source_prestore_fn.__get__(self, type(self))
            logging.debug(
                "%s: source probe %s defines _attempt_prestore_hook; will chain",
                self.__class__.__name__,
                self.source_probe,
            )

        # Inherit detector and extended detectors from the source probe
        if self.primary_detector == "always.Fail" and hasattr(
            source, "primary_detector"
        ):
            self.primary_detector = source.primary_detector
        if not self.extended_detectors and hasattr(source, "extended_detectors"):
            self.extended_detectors = list(source.extended_detectors)

        if self.follow_prompt_cap and self.soft_probe_prompt_cap:
            # Use our atomic pruning so parallel per-prompt arrays stay aligned
            # with self.prompts; plain _prune_data only handles self.triggers.
            self._prune_data_parallel(cap=self.soft_probe_prompt_cap)

        # Record base prompt count after pruning; used in _attempt_prestore_hook
        # to re-map expanded seq back to the original prompt index.
        self._source_n_base_prompts = len(self.prompts)

        self._param_combos = self._build_param_combos()

    def _prune_data_parallel(self, cap: int) -> None:
        """Prune self.prompts to at most ``cap`` entries.

        Unlike :meth:`_prune_data`, this method also prunes every parallel
        per-prompt attribute listed in ``self._source_parallel_attrs`` (e.g.
        ``triggers``, ``pii_types``) at the same random indices so that index
        correspondence between prompts and their associated data is preserved.
        """
        n = len(self.prompts)
        if n <= cap:
            return
        ids_to_rm = sorted(random.sample(range(n), n - cap), reverse=True)
        for i in ids_to_rm:
            del self.prompts[i]
            # Prune parallel per-prompt attributes at the same index so trigger
            # lists and other per-prompt data stay aligned with self.prompts.
            for attr in self._source_parallel_attrs:
                lst = getattr(self, attr, None)
                if isinstance(lst, list) and i < len(lst):
                    del lst[i]

    def _build_param_combos(self) -> list[dict]:
        """Build the list of parameter combinations to sweep.

        ``sweep_strategy`` determines the approach:

        - ``"single"`` varies one parameter at a time whilst leaving others at
          their generator defaults; yields one combo per parameter value.
        - ``"random"`` draws ``random_samples`` unique combinations at random
          from the Cartesian product of all param value lists.
        """
        param_space = self.param_space
        if not param_space:
            return [{}]

        combos: list[dict] = []

        if self.sweep_strategy == "single":
            for param, values in param_space.items():
                for value in values:
                    combos.append({param: value})

        elif self.sweep_strategy == "random":
            # Build the full Cartesian product then sample without replacement.
            # This guarantees uniqueness structurally (no rejection loop needed),
            # handles random_samples > product size gracefully via min(), and makes
            # results reproducible via random_seed.
            param_names = list(param_space.keys())
            all_combos = [
                dict(zip(param_names, values))
                for values in itertools.product(*param_space.values())
            ]
            rng = np.random.default_rng(self.random_seed)
            n = min(self.random_samples, len(all_combos))
            combos = [all_combos[i] for i in rng.choice(len(all_combos), size=n, replace=False)]

        else:
            raise ValueError(
                f"Unsupported sweep_strategy '{self.sweep_strategy}'; "
                "expected 'single' or 'random'"
            )

        return combos

    def _validate_params_against_generator(self, generator) -> None:
        """Confirm every param in ``param_space`` exists on the generator.

        :raises PluginConfigurationError: if a param is not present on the
            generator, so the caller can correct the configuration before
            running an incomplete or misleading sweep.
        """
        missing = [param for param in self.param_space if not hasattr(generator, param)]
        if missing:
            raise PluginConfigurationError(
                f"{self.__class__.__name__}: the following param_space entries "
                f"are not supported by generator '{type(generator).__name__}': "
                f"{missing}. Remove them from param_space or use a different generator."
            )

        if not any(cls.__name__ == "OpenAICompatible" for cls in type(generator).__mro__):
            msg = (
                f"{self.__class__.__name__}: generator '{type(generator).__name__}' may not apply "
                f"inference param changes to API requests — param sweeping is verified for "
                f"openai.OpenAICompatible subclasses, which read instance attributes dynamically via "
                f"inspect.signature; for other generators confirm that {list(self.param_space.keys())} "
                f"are interpolated into outgoing requests before relying on results"
            )
            logging.warning(msg)
            print(f"⚠️  {msg}")

    def _attempt_prestore_hook(self, attempt: Attempt, seq: int) -> Attempt:
        """Store the parameter combo for this attempt in ``attempt.notes``.

        If the source probe defined its own ``_attempt_prestore_hook`` (e.g. to
        populate ``attempt.notes["triggers"]`` for trigger-based detectors),
        that hook is called first.  The seq index is re-mapped to the original
        base-prompt position (``seq % _source_n_base_prompts``) so that
        per-prompt data arrays (triggers, pii_types, …) are indexed correctly
        after the prompt list has been expanded across param combos.

        Hyperparam tracking keys are then added to ``attempt.notes`` without
        overwriting anything the source hook may have set.
        """
        if self._source_prestore_hook is not None:
            # Re-map the expanded seq back to the original prompt index.
            # After expansion: prompts = [p0, p1, …, pN, p0, p1, …, pN, …]
            # so seq % n_base gives the correct index into the source's data arrays.
            base_seq = seq % self._source_n_base_prompts
            attempt = self._source_prestore_hook(attempt, base_seq)

        combo_idx = seq % len(self._param_combos) if self._param_combos else 0
        # These keys are distinct from any notes set by the source hook above.
        attempt.notes["hyperparam_combo"] = (
            self._param_combos[combo_idx] if self._param_combos else {}
        )
        attempt.notes["hyperparam_original"] = {}
        return attempt

    def _generator_precall_hook(self, generator, attempt=None) -> None:
        """Apply the attempt's parameter combo to the generator."""
        if attempt is None:
            return
        combo = attempt.notes.get("hyperparam_combo", {})
        original: dict = attempt.notes.get("hyperparam_original", {})
        for param, value in combo.items():
            if hasattr(generator, param):
                original[param] = getattr(generator, param)
                setattr(generator, param, value)
        attempt.notes["hyperparam_original"] = original

    def _postprocess_hook(self, attempt: Attempt) -> Attempt:
        """Restore the generator's original parameter values after each attempt."""
        original = attempt.notes.get("hyperparam_original", {})
        for param, value in original.items():
            if hasattr(self.generator, param):
                setattr(self.generator, param, value)
        return attempt

    def _build_prompt_list(self) -> list:
        """Return the cross-product of prompts × parameter combos."""
        expanded: list = []
        for combo in self._param_combos:
            for prompt in self.prompts:
                expanded.append((prompt, combo))
        return expanded

    def probe(self, generator) -> Iterable[Attempt]:
        """Probe by sweeping inference parameters across all prompts.

        Validates that every parameter in ``param_space`` exists on ``generator``
        before starting the sweep, raising ``PluginConfigurationError`` if not.
        The implementation expands the prompt list to prompts × param_combos,
        then delegates to the standard ``Probe.probe()`` machinery so that all
        existing hooks (buffs, detectors, etc.) apply normally.
        """
        if not self.prompts or not self._param_combos:
            logging.warning(
                "%s: no prompts or param combos — set source_probe and param_space",
                self.__class__.__name__,
            )
            return []

        self._validate_params_against_generator(generator)

        pairs = self._build_prompt_list()
        original_prompts = self.prompts
        original_combos = list(self._param_combos)

        # Expand so that each combo is sequenced through the prompt list
        self.prompts = [p for p, _ in pairs]
        self._param_combos = [c for _, c in pairs]

        try:
            result = list(super().probe(generator))
        finally:
            self.prompts = original_prompts
            self._param_combos = original_combos

        if not (hasattr(_config, "system") and getattr(_config.system, "narrow_output", False)):
            try:
                report = getattr(_config.transient, "report_filename", None)
            except AttributeError:
                report = None
            report_hint = f" --report {report}" if report else ""
            print(
                f"\n{self.__class__.__name__}: run"
                f" `python -m garak.analyze.hyperparam_summary{report_hint}`"
                " to view per-combo results."
            )
        return result
