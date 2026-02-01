# SPDX-FileCopyrightText: Portions Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import uuid
import json
import os
from colorama import Fore, Style
from garak import _config, _plugins
from garak.harnesses.base import Harness

logger = logging.getLogger(__name__)


class OutputMock:
    def __init__(self, text):
        self.text = text if isinstance(text, str) else str(text)
        self.prompt = self.text
        self.status = "success"
        self.lang = "en"
        self.data_path = None
        self.data_type = None
        self.data_checksum = None
        self.notes = None


class AttemptMock:
    def __init__(self, outputs, probename, prompt=None, seq=0):
        self.all_outputs = [
            OutputMock(output)
            for output in (outputs if isinstance(outputs, list) else [outputs])
        ]
        self.probename = probename
        self.probe_classname = ".".join(
            probename.split(".")[1:]
        )  # Changed to "category.Class" format, e.g., "xss.ColabAIDataLeakage"
        self.prompt = (
            prompt
            if prompt
            else {
                "turns": [
                    {
                        "role": "user",
                        "content": {"text": prompt or "", "lang": "en", "notes": {}},
                    }
                ]
            }
        )
        self.status = "success"
        self.detector_results = {}
        self.notes = {"terms": ["summary", "conversation"]}
        self.outputs = [output.text for output in self.all_outputs]
        self.uuid = str(uuid.uuid4())
        self.seq = seq
        self.probe_params = {}
        self.targets = []
        self.conversations = [
            {
                "turns": [
                    {
                        "role": "user",
                        "content": {"text": prompt or "", "lang": "en", "notes": {}},
                    },
                    {
                        "role": "assistant",
                        "content": {"text": output.text, "lang": "en", "notes": {}},
                    },
                ]
            }
            for output in self.all_outputs
        ]
        self.reverse_translation_outputs = []


class ProbewiseHarness(Harness):
    def _load_detector(self, detector_name: str):
        logger.debug(f"Attempting to load detector: {detector_name}")
        try:
            detector = _plugins.load_plugin(
                "detectors." + detector_name, break_on_fail=False
            )
            if detector:
                logger.debug(f"Successfully loaded detector: {detector_name}")
                return detector
            else:
                logger.error(f"Detector load failed: {detector_name}, skipping")
                print(f"Error: Detector {detector_name} failed to load, skipping")
        except Exception as e:
            logger.error(f"Exception loading detector {detector_name}: {str(e)}")
            print(f"Error: Failed to load detector {detector_name}: {str(e)}")
        return None

    def _find_incomplete_attempts(self, probename: str, resume_point: int):
        """Find attempts that have status=1 but missing status=2 in the report.

        These are attempts that were executed but interrupted before detectors ran.

        Args:
            probename: Full probe name (e.g., "probes.av_spam_scanning.GTUBE")
            resume_point: The prompt index we're resuming from

        Returns:
            List of attempt objects that need detector evaluation
        """
        import json
        import garak.attempt

        probe_classname = probename.replace("probes.", "")
        status1_attempts = {}  # seq -> attempt dict
        status2_seqs = set()  # seqs that have status=2

        # Get report filename to read separately
        report_path = _config.transient.report_filename
        if not report_path or not os.path.exists(report_path):
            return []

        # Open a separate read handle (main file is open in append mode)
        try:
            with open(report_path, "r", encoding="utf-8") as read_handle:
                for line in read_handle:
                    try:
                        entry = json.loads(line.strip())
                        if (
                            entry.get("entry_type") == "attempt"
                            and entry.get("probe_classname") == probe_classname
                        ):
                            seq = entry.get("seq")
                            status = entry.get("status")

                            if status == 1 and seq < resume_point:
                                # This is a status=1 entry for an attempt before resume point
                                status1_attempts[seq] = entry
                            elif status == 2 and seq < resume_point:
                                # This attempt has status=2, mark it as complete
                                status2_seqs.add(seq)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error(f"Error reading report for incomplete attempts: {e}")
            return []

        # Find attempts with status=1 but no status=2
        incomplete_seqs = set(status1_attempts.keys()) - status2_seqs
        incomplete_attempts = []

        for seq in sorted(incomplete_seqs):
            entry = status1_attempts[seq]

            # Create a minimal Attempt-like object with as_dict() method
            # We don't need full Attempt validation since these were already validated
            class MinimalAttempt:
                def __init__(self, data):
                    self.uuid = data.get("uuid", "")
                    self.seq = data.get("seq", 0)
                    self.status = 1  # Was executed
                    self.probe_classname = data.get("probe_classname", "")
                    self.probe_params = data.get("probe_params", {})
                    self.targets = data.get("targets", [])
                    self.notes = data.get("notes", {})
                    self.goal = data.get("goal", "")
                    self.detector_results = data.get("detector_results", {})
                    self.conversations = data.get("conversations", [])
                    self.reverse_translation_outputs = data.get(
                        "reverse_translation_outputs", []
                    )
                    # Store prompt and outputs as-is (already serialized)
                    self._prompt_data = data.get("prompt", {})
                    self._outputs_data = data.get("outputs", [])
                    # Cache outputs as Message objects for evaluator
                    self._outputs_cache = None
                    self._prompt_cache = None

                @property
                def prompt(self):
                    """Return prompt as Conversation object (for evaluator)"""
                    if self._prompt_cache is None:
                        from garak.attempt import Conversation

                        # Reconstruct Conversation from the stored dict
                        if isinstance(self._prompt_data, dict):
                            self._prompt_cache = Conversation.from_dict(
                                self._prompt_data
                            )
                        else:
                            # Fallback to empty conversation
                            self._prompt_cache = Conversation([])
                    return self._prompt_cache

                @property
                def outputs(self):
                    """Return output messages as a list (for evaluator)"""
                    if self._outputs_cache is None:
                        from garak.attempt import Message

                        messages = []
                        if isinstance(self._outputs_data, list):
                            for output in self._outputs_data:
                                if isinstance(output, dict):
                                    msg = Message(
                                        text=output.get("text", ""),
                                        lang=output.get("lang", "en"),
                                        data_path=output.get("data_path"),
                                        data_type=output.get("data_type"),
                                        data_checksum=output.get("data_checksum"),
                                        notes=output.get("notes", {}),
                                    )
                                    messages.append(msg)
                                elif isinstance(output, str):
                                    messages.append(Message(text=output, lang="en"))
                        self._outputs_cache = messages
                    return self._outputs_cache

                def as_dict(self):
                    """Return dictionary representation for report writing"""
                    return {
                        "entry_type": "attempt",
                        "uuid": self.uuid,
                        "seq": self.seq,
                        "status": self.status,
                        "probe_classname": self.probe_classname,
                        "probe_params": self.probe_params,
                        "targets": self.targets,
                        "prompt": self._prompt_data,
                        "outputs": self._outputs_data,
                        "detector_results": self.detector_results,
                        "notes": self.notes,
                        "goal": self.goal,
                        "conversations": self.conversations,
                        "reverse_translation_outputs": self.reverse_translation_outputs,
                    }

                def outputs_for(self, lang_spec):
                    """Return output messages for detector evaluation"""
                    # Reconstruct Message objects from outputs_data
                    from garak.attempt import Message

                    messages = []
                    if isinstance(self._outputs_data, list):
                        for output in self._outputs_data:
                            if isinstance(output, dict):
                                msg = Message(
                                    text=output.get("text", ""),
                                    lang=output.get("lang", lang_spec),
                                    data_path=output.get("data_path"),
                                    data_type=output.get("data_type"),
                                    data_checksum=output.get("data_checksum"),
                                    notes=output.get("notes", {}),
                                )
                                messages.append(msg)
                            elif isinstance(output, str):
                                messages.append(Message(text=output, lang=lang_spec))
                    return messages

            attempt = MinimalAttempt(entry)
            incomplete_attempts.append(attempt)

        logger.info(
            f"[RESUME] Found {len(incomplete_attempts)} incomplete attempts for {probename}"
        )
        return incomplete_attempts

    def run(self, model, probenames, evaluator, buff_names=None):
        if buff_names is None:
            buff_names = []

        self._load_buffs(buff_names)
        probenames = sorted(probenames)

        # RESUME SUPPORT: Initialize or resume run
        from garak import resumeservice

        logger.info(
            f"Resume setup: enabled={resumeservice.enabled()}, resumable={_config.run.resumable}"
        )
        if not resumeservice.enabled():
            # New run - initialize if resumable
            if _config.run.resumable:
                logger.info(
                    f"Initializing new resumable run with granularity={resumeservice.get_granularity()}"
                )
                # Pass existing transient.run_id to maintain consistency across reports/hitlog
                existing_uuid = (
                    str(_config.transient.run_id) if _config.transient.run_id else None
                )
                run_id = resumeservice.initialize_new_run(
                    probenames, model, existing_run_uuid=existing_uuid
                )
                # Extract UUID from full run_id - it should match the existing UUID we passed in
                uuid_part = resumeservice.extract_uuid_from_run_id(run_id)
                _config.transient.run_id = uuid_part
                granularity = resumeservice.get_granularity()
                logger.info(f"Initialized run {run_id} with granularity={granularity}")
                print(f"🆔 Run ID: {run_id} ({granularity}-level resume enabled)")
                print(f"   Use --resume {run_id} to continue if interrupted")
        else:
            # Resume mode - load the state
            logger.info(
                f"Loading resume state for run {_config.transient.resume_run_id}"
            )
            resumeservice.load()
            # Note: start_msg() is already called and printed by base.py service initialization
            # CRITICAL: Don't override transient.run_id on resume - it was set in cli.py from state
            # This ensures hitlog uses the same run_id across all files

        print(
            f"🕵️ queue of {Style.BRIGHT}{Fore.LIGHTYELLOW_EX}probes:{Style.RESET_ALL} "
            + ", ".join([name.replace("probes.", "") for name in probenames])
        )

        for probename in probenames:
            # RESUME SUPPORT: Skip completed probes in BOTH probe and attempt-level granularity
            # A completed probe means ALL its attempts are done, so always skip it
            if resumeservice.should_skip_probe(probename):
                logger.info(f"Skipping completed probe: {probename}")
                print(f"⏭️  Skipping completed: {probename}")
                continue

            logger.debug(f"Loading probe: {probename}")
            probe = _plugins.load_plugin(probename)
            if not probe:
                logger.warning(f"Probe {probename} failed to load, skipping")
                print(f"failed to load probe {probename}")
                continue

            detectors = []
            if probe.primary_detector:
                d = self._load_detector(probe.primary_detector)
                if d:
                    detectors.append(d)
                else:
                    logger.warning(
                        f"Primary detector {probe.primary_detector} failed for {probename}"
                    )
                if _config.plugins.extended_detectors is True:
                    for detector_name in sorted(probe.extended_detectors):
                        d = self._load_detector(detector_name)
                        if d:
                            detectors.append(d)
                        else:
                            logger.warning(
                                f"Extended detector {detector_name} failed for {probename}"
                            )
            else:
                logger.debug(
                    "deprecation warning - probe %s using recommended_detector instead of primary_detector",
                    probename,
                )
                for detector_name in sorted(probe.recommended_detector):
                    d = self._load_detector(detector_name)
                    if d:
                        detectors.append(d)
                    else:
                        logger.warning(
                            f"Recommended detector {detector_name} failed for {probename}"
                        )

            if not detectors:
                logger.error(f"No detectors loaded for {probename}, skipping")
                print(f"Error: No detectors loaded for {probename}, skipping")
                continue

            logger.info(
                f"Running probe {probename} with detectors: {[d.__class__.__name__ for d in detectors]}"
            )
            print(
                f"Running probe {probename} with detectors: {[d.__class__.__name__ for d in detectors]}"
            )

            # RESUME SUPPORT: For attempt-level granularity, check if probe is already complete BEFORE generating attempts
            # This prevents unnecessary HTTP calls for completed probes
            probe_short_name = probename.replace("probes.", "")
            if resumeservice.get_granularity() == "attempt":
                # Check if we have saved state for this probe
                saved_probe_state = resumeservice.get_probe_state(probe_short_name)
                if saved_probe_state:
                    resume_point = saved_probe_state.get("prompt_index", -1) + 1
                    total_prompts_saved = saved_probe_state.get("total_prompts", 0)

                    # If all attempts were completed, skip this probe entirely
                    if resume_point >= total_prompts_saved and total_prompts_saved > 0:
                        logger.info(
                            f"All {total_prompts_saved} attempts for {probename} already completed (from saved state), skipping probe"
                        )
                        print(
                            f"✅ All {total_prompts_saved} attempts for {probename} already completed"
                        )
                        # Mark probe as complete and continue to next probe
                        resumeservice.mark_probe_complete(probename)
                        continue

            try:
                # RESUME: On resume, check for incomplete attempts (status=1 without status=2)
                # These are attempts that were executed but interrupted before detectors ran
                incomplete_attempts = []
                probe_short_name = probename.replace("probes.", "")
                if (
                    resumeservice.enabled()
                    and resumeservice.get_granularity() == "attempt"
                ):
                    resume_point = resumeservice.get_resume_point(probe_short_name)
                    if resume_point > 0:
                        # This is a resumed run - check report for incomplete attempts
                        logger.info(
                            f"[RESUME] Checking report for incomplete attempts for {probe_short_name}"
                        )
                        incomplete_attempts = self._find_incomplete_attempts(
                            probename, resume_point
                        )
                        if incomplete_attempts:
                            logger.info(
                                f"[RESUME] Found {len(incomplete_attempts)} incomplete attempts (status=1 without status=2)"
                            )
                            print(
                                f"🔄 Completing detector evaluation for {len(incomplete_attempts)} interrupted attempts"
                            )

                logger.info(f"Calling probe.probe() for {probename}")
                attempts = probe.probe(model)
                logger.info(f"probe.probe() returned for {probename}")
                if not attempts:
                    logger.error(f"Probe {probename} returned no attempts, skipping")
                    print(f"Probe {probename} returned no attempts, skipping")
                    continue

                # Convert to list to get total count
                attempts = list(attempts)

                # RESUME: Merge incomplete attempts with new attempts
                # Incomplete attempts need detector evaluation but not re-execution
                if incomplete_attempts:
                    # Combine: incomplete attempts first (need detectors only), then new attempts (freshly executed)
                    all_attempts = incomplete_attempts + attempts
                    logger.info(
                        f"[RESUME] Processing {len(incomplete_attempts)} incomplete + {len(attempts)} new attempts"
                    )
                else:
                    all_attempts = attempts

                # Get total_prompts - either from state if resuming, or from current attempts
                saved_state = resumeservice.get_probe_state(probe_short_name)
                if saved_state and "total_prompts" in saved_state:
                    total_prompts = saved_state["total_prompts"]
                else:
                    # First run or no state - get from returned attempts
                    # Note: if resuming, attempts are already filtered by Probe base class
                    if len(all_attempts) > 0:
                        # Check if this is a resumed run with filtered attempts
                        resume_point = resumeservice.get_resume_point(probe_short_name)
                        if resume_point > 0:
                            # Total = resume_point + remaining attempts
                            total_prompts = resume_point + len(
                                attempts
                            )  # Use 'attempts' not 'all_attempts'
                        else:
                            total_prompts = len(all_attempts)
                    else:
                        total_prompts = 0

                logger.info(
                    f"Probe {probename}: {len(all_attempts)} attempts to process (total: {total_prompts})"
                )

                if not all_attempts:
                    logger.info(
                        f"All attempts for {probename} already completed, skipping probe"
                    )
                    print(f"✅ All attempts for {probename} already completed")
                    resumeservice.mark_probe_complete(probename)
                    continue

                # Evaluate attempts with detectors - use original interface that passes Attempt objects
                probe_category = (
                    probename.split(".")[1]
                    if len(probename.split(".")) > 1
                    else probename
                )
                probe_short_name = probename.replace("probes.", "")
                logger.info(
                    f"Starting to process {len(all_attempts)} attempts for {probe_short_name}"
                )
                # FIXED: Collect attempts with detector results for evaluator
                attempts_with_results = []
                for attempt in all_attempts:
                    logger.info(
                        f"[RESUME DEBUG] Processing attempt {attempt.seq} for {probe_short_name}"
                    )
                    for detector in detectors:
                        logger.debug(
                            f"Evaluating with detector {detector.__class__.__name__}"
                        )
                        detector_module = detector.__class__.__module__.split(".")[-1]
                        detector_key = (
                            f"{detector_module}.{detector.__class__.__name__}"
                        )

                        # FIXED: Use original detector interface - pass Attempt object, not individual outputs
                        try:
                            # Pass the full Attempt object to the detector (original Garak behavior)
                            detector_result = detector.detect(attempt)

                            # Store the result - convert to list if needed
                            if not hasattr(attempt, "detector_results"):
                                attempt.detector_results = {}
                            # Ensure detector_result is a list
                            if not isinstance(detector_result, list):
                                detector_result = list(detector_result)
                            attempt.detector_results[detector_key] = detector_result

                            logger.debug(
                                f"Detector {detector.__class__.__name__} result for {detector_key}: {detector_result}"
                            )

                        except Exception as det_e:
                            logger.error(
                                f"Detector {detector.__class__.__name__} failed for {probename}: {det_e}"
                            )
                            if hasattr(attempt, "all_outputs") and attempt.all_outputs:
                                attempt.detector_results[detector_key] = [0.0] * len(
                                    attempt.all_outputs
                                )
                            else:
                                attempt.detector_results[detector_key] = [0.0]

                    # Add attempt to list for evaluator after all its detectors complete
                    attempts_with_results.append(attempt)

                    # Write attempt with detector results to report (status=2)
                    try:
                        if hasattr(attempt, "as_dict"):
                            d = attempt.as_dict()
                        else:
                            d = {
                                "entry_type": "attempt",
                                "uuid": getattr(attempt, "uuid", ""),
                                "seq": getattr(attempt, "seq", 0),
                                "status": getattr(attempt, "status", 1),
                                "probe_classname": (
                                    ".".join(probename.split(".")[1:])
                                    if probename
                                    else ""
                                ),
                                "probe_params": getattr(attempt, "probe_params", {}),
                                "targets": getattr(attempt, "targets", []),
                                "prompt": getattr(attempt, "prompt", {}),
                                "outputs": getattr(attempt, "outputs", []),
                                "detector_results": getattr(
                                    attempt, "detector_results", {}
                                ),
                                "notes": getattr(attempt, "notes", {}),
                                "goal": getattr(attempt, "goal", None),
                                "conversations": getattr(attempt, "conversations", []),
                                "reverse_translation_outputs": getattr(
                                    attempt, "reverse_translation_outputs", []
                                ),
                            }

                        d["status"] = 2

                        _config.transient.reportfile.write(
                            json.dumps(d, ensure_ascii=False) + "\n"
                        )
                        _config.transient.reportfile.flush()

                    except Exception as write_e:
                        logger.exception(
                            f"Failed to write attempt entry for probe {probename}: {write_e}"
                        )

                # Pass attempts to evaluator after all attempts are written
                logger.debug(
                    f"Calling evaluator.evaluate for {probename} with {len(attempts_with_results)} attempts"
                )
                # Set evaluator.probename to module.class format
                evaluator.probename = (
                    probename  # Changed to probename for report compatibility
                )
                evaluator.evaluate(attempts_with_results)
                logger.debug(
                    f"Evaluated attempts for {probename}: {[attempt.detector_results for attempt in attempts_with_results]}"
                )

                logger.info(f"Probe {probename} executed successfully")

                # RESUME SUPPORT: Mark probe complete
                from garak import resumeservice

                resumeservice.mark_probe_complete(probename)

            except Exception as e:
                logger.error(
                    f"Error or interruption during probe {probename}: {str(e)}"
                )
                print(f"Error or interruption during probe {probename}: {str(e)}")
                raise

        # RESUME SUPPORT: Mark run complete after all probes finish
        from garak import resumeservice

        resumeservice.mark_run_complete()
