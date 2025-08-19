"""Defines the Report class and associated functions to process and export a native garak report"""

import importlib
import json
import numpy as np
import pandas as pd

from datetime import date
import avidtools.datamodels.report as ar
import avidtools.datamodels.components as ac
import avidtools.datamodels.enums as ae


# load up a .jsonl output file, take in eval and config rows
class Report:
    """A class defining a generic report object to store information in a garak report (typically named `garak.<uuid4>.report.jsonl`).

    :param report_location: location where the file is stored.
    :type report_location: str
    :param records: list of raw json records in the report file
    :type records: List[dict]
    :param metadata: report metadata, storing information about scanned model
    :type metadata: dict
    :param evaluations: evaluation information at probe level
    :type evaluations: pd.DataFrame
    :param scores: average pass percentage per probe
    :type scores: pd.DataFrame
    :param write_location: location where the output is written out.
    :type write_location: str
    """

    def __init__(
        self,
        report_location,
        records=None,
        metadata=None,
        evaluations=None,
        scores=None,
    ):
        self.report_location = report_location
        self.records = records
        self.metadata = metadata
        self.evaluations = evaluations
        self.scores = scores

        if self.records is None:
            self.records = []

    def load(self):
        """Loads a garak report."""
        with open(self.report_location, "r", encoding="utf-8") as reportfile:
            for line in reportfile:
                record = json.loads(line.strip())
                self.records.append(record)
        return self

    def get_evaluations(self):
        """Extracts evaluation information from a garak report."""
        evals = []

        for record in self.records:
            if record["entry_type"] == "eval":
                evals.append(record)
            elif record["entry_type"] == "config":
                self.metadata = record
        if len(evals) == 0:
            raise ValueError("No evaluations to report 🤷")

        # preprocess
        for i in range(len(evals)):
            module_name, plugin_class_name = evals[i]["probe"].split(".")
            mod = importlib.import_module(f"garak.probes.{module_name}")

            evals[i]["probe"] = f"{module_name}.{plugin_class_name}"
            plugin_instance = getattr(mod, plugin_class_name)()
            evals[i]["probe_tags"] = plugin_instance.tags

        self.evaluations = pd.DataFrame.from_dict(evals)
        self.evaluations["score"] = np.where(
            self.evaluations["total"] != 0,
            100 * self.evaluations["passed"] / self.evaluations["total"],
            0,
        )
        self.scores = self.evaluations[["probe", "score"]].groupby("probe").mean()
        return self

    def export(self):  # TODO: add html format
        """Writes out output in a specified format."""

        # set up a generic AVID report template
        report_template = ar.Report()
        if self.metadata is not None:
            report_template.affects = ac.Affects(
                developer=[],
                deployer=[self.metadata["model_type"]],
                artifacts=[
                    ac.Artifact(
                        type=ae.ArtifactTypeEnum.model, name=self.metadata["model_name"]
                    )
                ],
            )

        report_template.references = [
            ac.Reference(
                type="source",
                label="garak, an LLM vulnerability scanner",
                url="https://github.com/NVIDIA/garak",
            )
        ]
        report_template.reported_date = date.today()

        # now build all the reports
        all_reports = []
        for probe in self.scores.index:
            report = report_template.copy()
            probe_data = self.evaluations.query(f"probe=='{probe}'")

            report.description = ac.LangValue(
                lang="eng",
                value=f"The model {self.metadata['model_name']} from {self.metadata['model_type']} was evaluated by the Garak LLM Vunerability scanner using the probe `{probe}`.",
            )
            report.problemtype = ac.Problemtype(
                classof=ae.ClassEnum.llm,
                type=ae.TypeEnum.measurement,
                description=report.description,
            )
            report.metrics = [
                ac.Metric(
                    name="",
                    detection_method=ac.Detection(
                        type=ae.MethodEnum.thres, name="Count failed"
                    ),
                    results=probe_data[["detector", "passed", "total", "score"]]
                    .reset_index()
                    .to_dict(),
                )
            ]
            all_tags = probe_data.iloc[0]["probe_tags"]
            if all_tags == all_tags:  # check for NaN
                tags_split = [
                    tag.split(":") for tag in all_tags if tag.startswith("avid")
                ]  # supports only avid taxonomy for now
                report.impact = ac.Impact(
                    avid=ac.AvidTaxonomy(
                        risk_domain=pd.Series([tag[1].title() for tag in tags_split])
                        .drop_duplicates()
                        .tolist(),  # unique values
                        sep_view=[ae.SepEnum[tag[2]] for tag in tags_split],
                        lifecycle_view=[ae.LifecycleEnum["L05"]],
                        taxonomy_version="",
                    )
                )
            all_reports.append(report)

        # save final output
        self.write_location = self.report_location.replace(".report", ".avid")
        with open(self.write_location, "w", encoding="utf-8") as f:
            f.writelines(r.json() + "\n" for r in all_reports)
