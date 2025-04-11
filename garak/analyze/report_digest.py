#!/usr/bin/env python

"""Generate reports from garak report JSONL"""

from collections import defaultdict
import importlib
import json
import markdown
import os
import pprint
import re
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
    """assign a defcon class to a %age score 0.0-100.0"""
    if score < garak.analyze.SCORE_DEFCON_BOUNDS[0] * 100.0:
        return 1
    if score < garak.analyze.SCORE_DEFCON_BOUNDS[1] * 100.0:
        return 2
    if score < garak.analyze.SCORE_DEFCON_BOUNDS[2] * 100.0:
        return 3
    if score < garak.analyze.SCORE_DEFCON_BOUNDS[3] * 100.0:
        return 4
    return 5


def plugin_docstring_to_description(docstring):
    return docstring.split("\n")[0]


def compile_digest(report_path, taxonomy=_config.reporting.taxonomy):
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
        sql = f"select avg(score)*100 as s from results where probe_group = '{probe_group}' order by s asc, probe_class asc;"
        # sql = f"select probe_module || '.' || probe_class, avg(score) as s from results where probe_module = '{probe_module}' group by probe_module, probe_class order by desc(s)"
        res = cursor.execute(sql)
        # probe_scores = res.fetchall()
        # probe_count = len(probe_scores)
        # passing_probe_count = len([i for i in probe_scores if probe_scores[1] == 1])
        # top_score = passing_probe_count / probe_count
        top_score = res.fetchone()[0]

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
                "module": probe_group_name,
                "module_score": f"{top_score:.1f}%",
                "severity": map_score(top_score),
                "module_doc": group_doc,
                "group_link": group_link,
            }
        )

        if top_score < 100.0 or _config.reporting.show_100_pass_modules:
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
