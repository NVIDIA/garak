#!/usr/bin/env python

"""
Weights & Biases integration manager for Garak
"""

import logging
from typing import Dict, Any, Optional, Union, List
import matplotlib.pyplot as plt
import numpy as np

from garak import _config
from garak.attempt import Attempt
import plotly.graph_objects as go


class WandBManager:
    """Manages Weights & Biases integration for Garak"""

    def __init__(self):
        self._is_initialized = False
        self._pending_attempts = []  # Store attempts temporarily
        self._pending_evaluations = []  # Store evaluations temporarily
        self.generator_name = ""

    def init_wandb(
        self, model_name: str, probe_names: List[str], detector_names: List[str]
    ) -> None:
        """Initialize W&B if enabled in config and not already initialized"""
        if self._is_initialized:
            return

        # Check if W&B is enabled in config
        if (
            not hasattr(_config.system, "wandb_enabled")
            or not _config.system.wandb_enabled
        ):
            return

        try:
            import wandb

            if not wandb.run:
                project_name = getattr(
                    _config.system, "wandb_project", "garak-evaluations"
                )
                wandb.init(
                    project=project_name,
                    config={
                        "model": model_name,
                        "probes": probe_names,
                        "detectors": detector_names,
                        "seed": _config.run.seed,
                        "generations": _config.run.generations,
                    },
                )
                self._is_initialized = True
                logging.info(f"W&B initialized with project: {project_name}")
        except ImportError:
            logging.debug("W&B not installed, skipping initialization")
        except Exception as e:
            logging.warning(f"Failed to initialize W&B: {e}")

    def log_attempt(self, attempt: Attempt) -> None:
        """Store attempt data temporarily"""
        if not self._is_initialized:
            return

        try:
            # Store attempt for later batch processing
            self._pending_attempts.append(attempt)
        except Exception as e:
            logging.debug(f"Failed to store attempt: {e}")

    def flush_attempts(self) -> None:
        """Process all stored attempts and log them to W&B"""
        if not self._is_initialized or not self._pending_attempts:
            return

        try:
            import wandb

            if not wandb.run:
                return

            detailed_data = []
            for attempt in self._pending_attempts:
                triggers = attempt.notes.get("triggers", None)
                for idx, output in enumerate(attempt.outputs):
                    row_data = {
                        "probe": str(attempt.probe_classname),
                        "output_idx": idx,
                        "output_text": output,
                        "reverse_translation": (
                            attempt.reverse_translation_outputs[idx]
                            if attempt.reverse_translation_outputs
                            and idx < len(attempt.reverse_translation_outputs)
                            else None
                        ),
                        "original_prompt": (
                            attempt.notes.get("pre_translation_prompt", "")
                            if "pre_translation_prompt" in attempt.notes
                            else None
                        ),
                        "prompt": (
                            str(attempt.prompt) if attempt.prompt else None
                        ),
                        "status": str(attempt.status),
                        "goal": str(attempt.goal),
                        "language": str(attempt.lang),
                        "triggers": str(triggers),
                    }

                    for detector_name, scores in attempt.detector_results.items():
                        row_data[f"detector_{detector_name}"] = (
                            scores[idx] if idx < len(scores) else None
                        )

                    detailed_data.append(row_data)

            if detailed_data:
                columns = [
                    "probe",
                    "output_idx",
                    "output_text",
                    "reverse_translation",
                    "original_prompt",
                    "prompt",
                    "status",
                    "goal",
                    "language",
                    "triggers",
                ]
                detector_columns = set()
                for row in detailed_data:
                    detector_columns.update(
                        [col for col in row.keys() if col.startswith("detector_")]
                    )
                columns.extend(sorted(detector_columns))

                table_data = []
                for row in detailed_data:
                    table_row = [row.get(col, None) for col in columns]
                    table_data.append(table_row)

                detailed_table = wandb.Table(columns=columns, data=table_data)
                wandb.log(
                    {f"{attempt.probe_classname}_attempts_detailed": detailed_table}
                )

            # Clear the stored attempts after successful logging
            self._pending_attempts = []

        except Exception as e:
            logging.debug(f"W&B batch attempt logging failed: {e}")

    def log_evaluation(
        self,
        evaluator_class_name: str,
        probe_name: str,
        detector_name: str,
        passed: int,
        total: int,
    ) -> None:
        """Store evaluation results temporarily

        Args:
            evaluator_class_name: Name of the evaluator class
            probe_name: Name of the probe
            detector_name: Name of the detector
            passed: Number of passed tests
            total: Total number of tests
            data: Additional data to log (optional)
        """
        if not self._is_initialized:
            return

        try:
            evaluation_data = {
                "evaluator": evaluator_class_name,
                "probe": probe_name,
                "detector": detector_name,
                "passed": passed,
                "total": total,
                "pass_rate": float(passed / total) if total else 0.0,
                "generator_name": self.generator_name,
            }

            self._pending_evaluations.append(evaluation_data)

        except Exception as e:
            logging.debug(f"Failed to store evaluation: {e}")

    def _create_radar_chart(self, data: dict, title: str) -> go.Figure:
        """Create a radar chart using plotly

        Args:
            data: Dictionary of labels and values
            title: Chart title

        Returns:
            plotly Figure object
        """

        labels = list(data.keys())
        values = list(data.values())

        # Close the loop by appending first value
        labels.append(labels[0])
        values.append(values[0])

        fig = go.Figure(
            data=go.Scatterpolar(
                r=values, theta=labels, fill="toself", name="Pass Rate"
            )
        )

        fig.update_layout(
            title=f"{self.generator_name} {title}",
            polar=dict(
                radialaxis=dict(visible=True, range=[0, 1])  # パスレートは0-1の範囲
            ),
            showlegend=True,
        )

        return fig

    def flush_evaluations(self) -> None:
        """Process all stored evaluations and log them to W&B"""
        if not self._is_initialized or not self._pending_evaluations:
            return

        try:
            import wandb

            if not wandb.run:
                return

            # Get all columns (including any additional data columns)
            columns = [
                "evaluator",
                "probe",
                "detector",
                "passed",
                "total",
                "pass_rate",
                "generator_name",
            ]
            additional_columns = set()
            for eval_data in self._pending_evaluations:
                additional_columns.update(
                    [col for col in eval_data.keys() if col not in columns]
                )
            columns.extend(sorted(additional_columns))

            # Create table data
            table_data = []
            radar_data = {}
            probe_data = {}
            average_probe_data = {}
            for eval_data in self._pending_evaluations:
                row = [eval_data.get(col, None) for col in columns]
                table_data.append(row)
                # Collect data for probe averages
                probe_name = eval_data["probe"]
                parent_probe_name = probe_name.split(".")[0]
                if probe_name not in probe_data:
                    probe_data[probe_name] = {"total_rate": 0.0, "count": 0}
                if parent_probe_name not in average_probe_data:
                    average_probe_data[parent_probe_name] = {
                        "total_rate": 0.0,
                        "count": 0,
                    }
                probe_data[probe_name]["total_rate"] += eval_data["pass_rate"]
                probe_data[probe_name]["count"] += 1
                average_probe_data[parent_probe_name]["total_rate"] += eval_data[
                    "pass_rate"
                ]
                average_probe_data[parent_probe_name]["count"] += 1

            # Create and log the table
            evaluation_table = wandb.Table(columns=columns, data=table_data)
            wandb.log({"evaluations_summary": evaluation_table})

            each_probe_pass_rates = {
                probe: data["total_rate"] / data["count"]
                for probe, data in probe_data.items()
            }

            each_probe_pass_rates_fig = self._create_radar_chart(
                each_probe_pass_rates, "Each Probe Pass Rates"
            )
            # wandb.log({"each_probe_pass_rates": wandb.Image(each_probe_pass_rates_fig)})
            each_probe_pass_rates_fig_html = each_probe_pass_rates_fig.to_html(
                full_html=False, include_plotlyjs="cdn"
            )

            average_probe_pass_rates = {
                probe: data["total_rate"] / data["count"]
                for probe, data in average_probe_data.items()
            }

            average_probe_pass_rates_fig = self._create_radar_chart(
                average_probe_pass_rates, "Average Probe Pass Rates"
            )
            # wandb.log({"average_probe_pass_rates": wandb.Image(average_probe_pass_rates_fig)})
            average_probe_pass_rates_fig_html = average_probe_pass_rates_fig.to_html(
                full_html=False, include_plotlyjs="cdn"
            )
            wandb.log(
                {
                    "each_probe_pass_rates": wandb.Html(each_probe_pass_rates_fig_html),
                    "average_probe_pass_rates": wandb.Html(
                        average_probe_pass_rates_fig_html
                    ),
                }
            )

            # Clear the stored evaluations after successful logging
            self._pending_evaluations = []

        except Exception as e:
            logging.debug(f"W&B batch evaluation logging failed: {e}")

    def finish_wandb(self) -> None:
        """Flush remaining attempts and evaluations, then close the W&B run"""
        if not self._is_initialized:
            return

        try:
            # Flush any remaining data
            self.flush_evaluations()

            import wandb

            if wandb.run:
                wandb.finish()
            self._is_initialized = False
            self._pending_attempts = []
            self._pending_evaluations = []
        except Exception as e:
            logging.debug(f"Error closing W&B run: {e}")


# Create a singleton instance
wandb_manager = WandBManager()
