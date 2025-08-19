#!/usr/bin/env python

"""Generate reports from garak report JSONL"""

from collections import defaultdict
import datetime
import html
import importlib
import json
import markdown
import os
import pprint
import re
import statistics
import sys
from typing import IO, List

import jinja2
import sqlite3

import garak
from garak import _config
import garak._plugins
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


def map_absolute_score(score: float) -> int:
    """assign a defcon class (i.e. 1-5, 1=worst) to a %age score 0.0-100.0"""
    if score < garak.analyze.ABSOLUTE_DEFCON_BOUNDS.TERRIBLE:
        return 1
    if score < garak.analyze.ABSOLUTE_DEFCON_BOUNDS.BELOW_AVG:
        return 2
    if score < garak.analyze.ABSOLUTE_DEFCON_BOUNDS.ABOVE_AVG:
        return 3
    if score < garak.analyze.ABSOLUTE_DEFCON_BOUNDS.EXCELLENT:
        return 4
    return 5


def plugin_docstring_to_description(docstring):
    return docstring.split("\n")[0]


def _parse_report(reportfile: IO):
    reportfile.seek(0)

    evals = []
    payloads = []
    setup = defaultdict(str)
    init = {}

    for record in [json.loads(line.strip()) for line in reportfile if line.strip()]:
        if record["entry_type"] == "eval":
            evals.append(record)
        elif record["entry_type"] == "init":
            init = {
                "garak_version": record["garak_version"],
                "start_time": record["start_time"],
                "run_uuid": record["run"],
            }
        elif record["entry_type"] == "start_run setup":
            setup = record
        elif record["entry_type"] == "payload_init":
            payloads.append(
                record["payload_name"]
                + "  "
                + pprint.pformat(record, sort_dicts=True, width=60)
            )

    return init, setup, payloads, evals


def _report_header_content(report_path, init, setup, payloads, config=_config) -> dict:
    header_content = {
        "reportfile": report_path.split(os.sep)[-1],
        "garak_version": init["garak_version"],
        "start_time": init["start_time"],
        "run_uuid": init["run_uuid"],
        "setup": setup,
        "probespec": setup["plugins.probe_spec"],
        "model_type": setup["plugins.model_type"],
        "model_name": setup["plugins.model_name"],
        "payloads": payloads,
        "group_aggregation_function": config.reporting.group_aggregation_function,
        "report_digest_time": datetime.datetime.now().isoformat(),
    }

    return header_content


def _init_populate_result_db(evals, taxonomy=None):

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
            tags = garak._plugins.PluginCache.plugin_info(f"probes.{pm}.{pc}")["tags"]
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

    return conn, cursor


def _close_result_db(conn):
    conn.close()


def _get_report_grouping(cursor) -> List[str]:

    res = cursor.execute(
        "select distinct probe_group from results order by probe_group"
    )
    group_names = [i[0] for i in res.fetchall()]

    return group_names


def _get_group_aggregate_score(
    cursor, probe_group, aggregation_function
) -> tuple[float, bool]:

    unknown_function = False
    group_score = None  # range 0.0--1.0
    res = cursor.execute(
        f"select score as s from results where probe_group = '{probe_group}';"
    )
    probe_scores = [i[0] for i in res.fetchall()]

    # main aggregation function here
    match aggregation_function:
        # get all the scores

        case "mean":
            group_score = statistics.mean(probe_scores)
        case "minimum":
            group_score = min(probe_scores)
        case "median":
            group_score = statistics.median(probe_scores)
        case "lower_quartile":
            if len(probe_scores) == 1:
                group_score = probe_scores[0]
            else:
                group_score = statistics.quantiles(probe_scores, method="inclusive")[0]
        case "mean_minus_sd":
            if len(probe_scores) == 1:
                group_score = probe_scores[0]
            else:
                group_score = statistics.mean(probe_scores) - statistics.stdev(
                    probe_scores
                )
        case "proportion_passing":
            group_score = len(
                [
                    p
                    for p in probe_scores
                    if p > garak.analyze.ABSOLUTE_DEFCON_BOUNDS.BELOW_AVG
                ]
            ) / len(probe_scores)
        case _:
            group_score = min(probe_scores)  # minimum as default
            unknown_function = True

    return (group_score, unknown_function)


def _get_group_info(probe_group, group_score, taxonomy, config=_config) -> dict:

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

    group_info = {
        "group": probe_group_name,
        "score": group_score,
        "group_defcon": map_absolute_score(group_score),
        "doc": group_doc,
        "group_link": group_link,
        "group_aggregation_function": config.reporting.group_aggregation_function,
    }
    return group_info


def _get_probe_result_summaries(cursor, probe_group) -> List[tuple]:
    res = cursor.execute(
        f"select probe_module, probe_class, min(score) as s from results where probe_group='{probe_group}' group by probe_class order by s asc, probe_class asc;"
    )
    return res.fetchall()


def _get_probe_info(probe_module, probe_class, absolute_score) -> dict:
    probe_classpath = f"probes.{probe_module}.{probe_class}"
    probe_plugin_info = garak._plugins.PluginCache.plugin_info(probe_classpath)
    probe_description = probe_plugin_info["description"]
    probe_tags = probe_plugin_info["tags"]
    probe_plugin_name = f"{probe_module}.{probe_class}"
    return {
        "probe_name": probe_plugin_name,
        "probe_score": absolute_score,
        "probe_severity": map_absolute_score(absolute_score),
        "probe_descr": html.escape(probe_description),
        "probe_tier": probe_plugin_info["tier"],
        "probe_tags": probe_tags,
    }


def _get_detectors_info(cursor, probe_group, probe_class) -> List[tuple]:
    res = cursor.execute(
        f"select detector, score from results where probe_group='{probe_group}' and probe_class='{probe_class}' order by score asc, detector asc;"
    )
    return res.fetchall()


def _get_probe_detector_details(
    probe_module, probe_class, detector, absolute_score, calibration, probe_tier
) -> dict:
    calibration_used = False
    detector = re.sub(r"[^0-9A-Za-z_.]", "", detector)
    detector_module, detector_class = detector.split(".")
    detector_cache_entry = garak._plugins.PluginCache.plugin_info(
        f"detectors.{detector_module}.{detector_class}"
    )
    detector_description = detector_cache_entry["description"]

    zscore = calibration.get_z_score(
        probe_module,
        probe_class,
        detector_module,
        detector_class,
        absolute_score,
    )

    if zscore is None:
        relative_defcon, relative_comment = None, None
        relative_score = "n/a"

    else:
        relative_defcon, relative_comment = calibration.defcon_and_comment(zscore)
        relative_score = zscore
        calibration_used = True

    absolute_defcon = map_absolute_score(absolute_score)
    if absolute_score == 1.0:
        relative_defcon, absolute_defcon = 5, 5
    if probe_tier == 1:
        detector_defcon = (
            min(absolute_defcon, relative_defcon)
            if isinstance(relative_defcon, int)
            else absolute_defcon
        )
    else:
        detector_defcon = relative_defcon

    return {
        "detector_name": detector,
        "detector_descr": html.escape(detector_description),
        "absolute_score": absolute_score,
        "absolute_defcon": absolute_defcon,
        "absolute_comment": garak.analyze.ABSOLUTE_COMMENT[absolute_defcon],
        "relative_score": relative_score,
        "relative_defcon": relative_defcon,
        "relative_comment": relative_comment,
        "detector_defcon": detector_defcon,
        "calibration_used": calibration_used,
    }


def _get_calibration_info(calibration):

    calibration_date, calibration_model_count, calibration_model_list = "", "?", ""
    if calibration.metadata is not None:
        calibration_date = calibration.metadata["date"]
        calibration_models = calibration.metadata["filenames"]
        calibration_models = [
            s.replace(".report.jsonl", "") for s in calibration_models
        ]
        calibration_model_list = ", ".join(sorted(calibration_models))
        calibration_model_count = len(calibration_models)

    return {
        "calibration_date": calibration_date,
        "model_count": calibration_model_count,
        "model_list": calibration_model_list,
    }


def append_report_object(reportfile: IO, object: dict):
    end_val = reportfile.seek(0, os.SEEK_END)
    reportfile.seek(end_val - 1)
    last_char = reportfile.read()
    if last_char not in "\n\r":  # catch if we need to make a new line
        reportfile.write("\n")
    reportfile.write(json.dumps(object))


def build_digest(report_filename: str, config=_config):

    # taxonomy = config.reporting.taxonomy
    group_aggregation_function = config.reporting.group_aggregation_function
    taxonomy = config.reporting.taxonomy

    report_digest = {
        "entry_type": "digest",
        "meta": {},
        "eval": {},
    }

    with open(report_filename, "r", encoding="utf-8") as reportfile:
        init, setup, payloads, evals = _parse_report(reportfile)

    calibration = garak.analyze.calibration.Calibration()
    calibration_used = False

    header_content = _report_header_content(
        report_filename, init, setup, payloads, config
    )
    report_digest["meta"] = header_content

    conn, cursor = _init_populate_result_db(evals, taxonomy)
    group_names = _get_report_grouping(cursor)

    aggregation_unknown = False

    for probe_group in group_names:
        report_digest["eval"][probe_group] = {}

        group_score, group_aggregation_unknown = _get_group_aggregate_score(
            cursor, probe_group, group_aggregation_function
        )
        if group_aggregation_unknown:
            aggregation_unknown = True
        group_info = _get_group_info(probe_group, group_score, taxonomy)
        report_digest["eval"][probe_group]["_summary"] = group_info

        probe_result_summaries = _get_probe_result_summaries(cursor, probe_group)
        for probe_module, probe_class, group_absolute_score in probe_result_summaries:
            report_digest["eval"][probe_group][f"{probe_module}.{probe_class}"] = {}

            probe_info = _get_probe_info(
                probe_module, probe_class, group_absolute_score
            )
            report_digest["eval"][probe_group][f"{probe_module}.{probe_class}"][
                "_summary"
            ] = probe_info

            detectors_info = _get_detectors_info(cursor, probe_group, probe_class)
            for detector, absolute_score in detectors_info:
                probe_detector_result = _get_probe_detector_details(
                    probe_module,
                    probe_class,
                    detector,
                    absolute_score,
                    calibration,
                    probe_info["probe_tier"],
                )

                report_digest["eval"][probe_group][f"{probe_module}.{probe_class}"][
                    detector
                ] = probe_detector_result

                if probe_detector_result["calibration_used"]:
                    calibration_used = True

    _close_result_db(conn)

    report_digest["meta"]["calibration_used"] = calibration_used
    report_digest["meta"]["aggregation_unknown"] = aggregation_unknown
    if calibration_used:
        report_digest["meta"]["calibration"] = _get_calibration_info(calibration)

    return report_digest


def build_html(digest: dict, config=_config):
    # taxonomy = config.reporting.taxonomy
    # group_aggregation_function = config.reporting.group_aggregation_function

    html_report_content = ""

    header_content = digest["meta"]
    header_content["setup"] = pprint.pformat(
        header_content["setup"], sort_dicts=True, width=60
    )
    header_content["now"] = datetime.datetime.now().isoformat()
    html_report_content += header_template.render(header_content)

    group_names = digest["eval"].keys()
    for probe_group in group_names:
        group_info = digest["eval"][probe_group]["_summary"]

        group_info["unrecognised_aggregation_function"] = digest["meta"][
            "aggregation_unknown"
        ]
        group_info["show_top_group_score"] = config.reporting.show_top_group_score

        html_report_content += group_template.render(group_info)

        if group_info["score"] < 1.0 or config.reporting.show_100_pass_modules:
            for probe_name in digest["eval"][probe_group].keys():
                if probe_name == "_summary":
                    continue
                probe_info = digest["eval"][probe_group][probe_name]["_summary"]
                html_report_content += probe_template.render(probe_info)

                detector_names = digest["eval"][probe_group][probe_name].keys()
                for detector_name in detector_names:
                    if detector_name == "_summary":
                        continue

                    probe_detector_result = digest["eval"][probe_group][probe_name][
                        detector_name
                    ]

                    if (
                        probe_detector_result["absolute_score"] < 1.0
                        or config.reporting.show_100_pass_modules
                    ):
                        html_report_content += detector_template.render(
                            probe_detector_result
                        )

        html_report_content += end_module.render()

    if digest["meta"]["calibration_used"]:
        html_report_content += about_z_template.render(digest["meta"]["calibration"])

    html_report_content += footer_template.render()

    return html_report_content


def _get_report_digest(report_path):
    with open(report_path, "r", encoding="utf-8") as reportfile:
        for entry in [json.loads(line.strip()) for line in reportfile if line.strip()]:
            if entry["entry_type"] == "digest":
                return entry
    return False


if __name__ == "__main__":
    import argparse

    sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Generate reports from garak report JSONL.",
        prog="python -m garak.analyze.report_digest",
        epilog="See https://github.com/NVIDIA/garak",
    )
    parser.add_argument(
        "--report_path",
        "-r",
        help="Path to the report JSONL file",
        required=True,
    )
    parser.add_argument(
        "--output_path",
        "-o",
        help="Optional output path for the HTML report",
    )
    parser.add_argument(
        "--write_digest_suffix",
        "-w",
        action="store_true",
        help="Write digest to the report if absent",
    )
    parser.add_argument(
        "--taxonomy",
        "-t",
        help="Optional taxonomy to use for grouping probes",
    )

    args = parser.parse_args()

    report_path = args.report_path
    output_path = args.output_path
    write_digest_suffix = args.write_digest_suffix
    taxonomy = args.taxonomy

    digest = _get_report_digest(report_path)
    if not digest:
        digest = build_digest(report_path)
        if write_digest_suffix:
            with open(report_path, "a+", encoding="utf-8") as reportfile:
                append_report_object(reportfile, digest)
                print(f"Report digest appended to {report_path}", file=sys.stderr)

    digest_content = build_html(digest)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as output_file:
            output_file.write(digest_content)
    else:
        print(digest_content)

    # overrides to consider:
    # - use [env or digest-calculated] calibration
    # - use [env or digest-calculated] bounds
