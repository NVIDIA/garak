#!/usr/bin/env python

"""Generate reports from garak report JSONL"""

from collections import defaultdict
import importlib
import json
import markdown
import os
import pprint
import re
import statistics
import sys

import jinja2
import sqlite3

from garak import _config
from garak.data import path as data_path
import garak.analyze
import garak.analyze.calibration


if not _config.loaded:
    _config.load_config()

templateLoader = jinja2.FileSystemLoader(
    searchpath=_config.transient.package_dir / "analyze" / "templates"
)
templateEnv = jinja2.Environment(loader=templateLoader)

header_template = templateEnv.get_template("digest_header.jinja")
footer_template = templateEnv.get_template("digest_footer.jinja")
group_template = templateEnv.get_template("digest_group.jinja")
probe_template = templateEnv.get_template("digest_probe.jinja")
detector_template = templateEnv.get_template("digest_detector.jinja")
end_module = templateEnv.get_template("digest_end_module.jinja")
about_z_template = templateEnv.get_template("digest_about_z.jinja")


misp_resource_file = data_path / "misp_descriptions.tsv"
misp_descriptions = {}
if os.path.isfile(misp_resource_file):
    with open(misp_resource_file, "r", encoding="utf-8") as f:
        for line in f:
            key, title, descr = line.strip().split("\t")
            misp_descriptions[key] = (title, descr)


def map_score(score):
    """assign a defcon class (i.e. 1-5, 1=worst) to a %age score 0.0-100.0"""
    if score < garak.analyze.SCORE_DEFCON_BOUNDS.TERRIBLE * 100.0:
        return 1
    if score < garak.analyze.SCORE_DEFCON_BOUNDS.BELOW_AVG * 100.0:
        return 2
    if score < garak.analyze.SCORE_DEFCON_BOUNDS.ABOVE_AVG * 100.0:
        return 3
    if score < garak.analyze.SCORE_DEFCON_BOUNDS.EXCELLENT * 100.0:
        return 4
    return 5


def plugin_docstring_to_description(docstring):
    return docstring.split("\n")[0]


def compile_digest(
    report_path,
    taxonomy=_config.reporting.taxonomy,
    group_aggregation_function=_config.reporting.group_aggregation_function,
):
    evals = []
    payloads = []
    setup = defaultdict(str)
    with open(report_path, "r", encoding="utf-8") as reportfile:
        for line in reportfile:
            record = json.loads(line.strip())
            if record["entry_type"] == "eval":
                evals.append(record)
            elif record["entry_type"] == "init":
                garak_version = record["garak_version"]
                start_time = record["start_time"]
                run_uuid = record["run"]
            elif record["entry_type"] == "start_run setup":
                setup = record
            elif record["entry_type"] == "payload_init":
                payloads.append(
                    record["payload_name"]
                    + "  "
                    + pprint.pformat(record, sort_dicts=True, width=60)
                )

    calibration = garak.analyze.calibration.Calibration()
    calibration_used = False

    digest_content = header_template.render(
        {
            "reportfile": report_path.split(os.sep)[-1],
            "garak_version": garak_version,
            "start_time": start_time,
            "run_uuid": run_uuid,
            "setup": pprint.pformat(setup, sort_dicts=True, width=60),
            "probespec": setup["plugins.probe_spec"],
            "model_type": setup["plugins.model_type"],
            "model_name": setup["plugins.model_name"],
            "payloads": payloads,
            "group_aggregation_function": _config.reporting.group_aggregation_function,
        }
    )

    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    # build a structured obj: probemodule.probeclass.detectorname = %

    create_table = """create table results(
        probe_module VARCHAR(255) not null,
        probe_group VARCHAR(255) not null,
        probe_class VARCHAR(255) not null,
        detector VARCHAR(255) not null, 
        score FLOAT not null,
        instances INT not null
    );"""

    cursor.execute(create_table)

    for eval in evals:
        eval["probe"] = eval["probe"].replace("probes.", "")
        pm, pc = eval["probe"].split(".")
        detector = eval["detector"].replace("detector.", "")
        score = eval["passed"] / eval["total"] if eval["total"] else 0
        instances = eval["total"]
        groups = []
        if taxonomy is not None:
            # get the probe tags
            m = importlib.import_module(f"garak.probes.{pm}")
            tags = getattr(m, pc).tags
            for tag in tags:
                if tag.split(":")[0] == taxonomy:
                    groups.append(":".join(tag.split(":")[1:]))
            if groups == []:
                groups = ["other"]
        else:
            groups = [pm]
        # add a row for each group
        for group in groups:
            cursor.execute(
                f"insert into results values ('{pm}', '{group}', '{pc}', '{detector}', '{score}', '{instances}')"
            )

    # calculate per-probe scores

    res = cursor.execute(
        "select distinct probe_group from results order by probe_group"
    )
    group_names = [i[0] for i in res.fetchall()]

    # top score: % of passed probes
    # probe score: mean of detector scores

    # let's build a dict of per-probe score

    for probe_group in group_names:

        group_score = None  # range 0.0--100.0
        res = cursor.execute(
            f"select score*100 as s from results where probe_group = '{probe_group}';"
        )
        probe_scores = [i[0] for i in res.fetchall()]

        # main aggregation function here
        match group_aggregation_function:
            # get all the scores

            case "mean":
                group_score = statistics.mean(probe_scores)
            case "minimum":
                group_score = min(probe_scores)
            case "median":
                group_score = statistics.median(probe_scores)
            case "lower_quartile":
                group_score = statistics.quantiles(probe_scores, method="inclusive")[0]
            case "mean_minus_sd":
                group_score = statistics.mean(probe_scores) - statistics.stdev(
                    probe_scores
                )
            case "proportion_passing":
                group_score = 100.0 * (
                    len([p for p in probe_scores if p > 40]) / len(probe_scores)
                )
            case _:
                group_score = min(probe_scores)  # minimum as default
                group_aggregation_function += " (unrecognised, used 'minimum')"

        group_doc = f"Probes tagged {probe_group}"
        group_link = ""

        probe_group_name = probe_group
        if taxonomy is None:
            probe_module = re.sub("[^0-9A-Za-z_]", "", probe_group)
            m = importlib.import_module(f"garak.probes.{probe_module}")
            group_doc = markdown.markdown(plugin_docstring_to_description(m.__doc__))
            group_link = (
                f"https://reference.garak.ai/en/latest/garak.probes.{probe_group}.html"
            )
        elif probe_group != "other":
            probe_group_name = f"{taxonomy}:{probe_group}"
            if probe_group_name in misp_descriptions:
                probe_group_name, group_doc = misp_descriptions[probe_group_name]
        else:
            probe_group_name = "Uncategorized"

        digest_content += group_template.render(
            {
                "group": probe_group_name,
                "show_top_group_score": _config.reporting.show_top_group_score,
                "group_score": f"{group_score:.1f}%",
                "severity": map_score(group_score),
                "doc": group_doc,
                "group_link": group_link,
                "group_aggregation_function": group_aggregation_function,
            }
        )

        if group_score < 100.0 or _config.reporting.show_100_pass_modules:
            res = cursor.execute(
                f"select probe_module, probe_class, avg(score)*100 as s from results where probe_group='{probe_group}' group by probe_class order by s asc, probe_class asc;"
            )
            for probe_module, probe_class, score in res.fetchall():
                pm = importlib.import_module(f"garak.probes.{probe_module}")
                probe_description = plugin_docstring_to_description(
                    getattr(pm, probe_class).__doc__
                )
                digest_content += probe_template.render(
                    {
                        "plugin_name": f"{probe_module}.{probe_class}",
                        "plugin_score": f"{score:.1f}%",
                        "severity": map_score(score),
                        "plugin_descr": probe_description,
                    }
                )
                # print(f"\tplugin: {probe_module}.{probe_class} - {score:.1f}%")
                if score < 100.0 or _config.reporting.show_100_pass_modules:
                    res = cursor.execute(
                        f"select detector, score*100 from results where probe_group='{probe_group}' and probe_class='{probe_class}' order by score asc, detector asc;"
                    )
                    for detector, score in res.fetchall():
                        detector = re.sub(r"[^0-9A-Za-z_.]", "", detector)
                        detector_module, detector_class = detector.split(".")
                        dm = importlib.import_module(
                            f"garak.detectors.{detector_module}"
                        )
                        detector_description = plugin_docstring_to_description(
                            getattr(dm, detector_class).__doc__
                        )

                        zscore = calibration.get_z_score(
                            probe_module,
                            probe_class,
                            detector_module,
                            detector_class,
                            score / 100,
                        )

                        if zscore is None:
                            zscore_defcon, zscore_comment = None, None
                            zscore = "n/a"

                        else:
                            zscore_defcon, zscore_comment = (
                                calibration.defcon_and_comment(zscore)
                            )
                            zscore = f"{zscore:+.1f}"
                            calibration_used = True

                        digest_content += detector_template.render(
                            {
                                "detector_name": detector,
                                "detector_score": f"{score:.1f}%",
                                "severity": map_score(score),
                                "detector_description": detector_description,
                                "zscore": zscore,
                                "zscore_defcon": zscore_defcon,
                                "zscore_comment": zscore_comment,
                            }
                        )
                        # print(f"\t\tdetector: {detector} - {score:.1f}%")

        digest_content += end_module.render()

    conn.close()

    if calibration_used:
        calibration_date, calibration_model_count, calibration_model_list = "", "?", ""
        if calibration.metadata is not None:
            calibration_date = calibration.metadata["date"]
            calibration_models = calibration.metadata["filenames"]
            calibration_models = [
                s.replace(".report.jsonl", "") for s in calibration_models
            ]
            calibration_model_list = ", ".join(sorted(calibration_models))
            calibration_model_count = len(calibration_models)

        digest_content += about_z_template.render(
            {
                "calibration_date": calibration_date,
                "model_count": calibration_model_count,
                "model_list": calibration_model_list,
            }
        )

    digest_content += footer_template.render()

    return digest_content


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    report_path = sys.argv[1]
    taxonomy = None
    if len(sys.argv) == 3:
        taxonomy = sys.argv[2]
    digest_content = compile_digest(report_path, taxonomy=taxonomy)
    print(digest_content)
