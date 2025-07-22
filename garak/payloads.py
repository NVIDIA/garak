# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

""" Management of payloads.

"""

from __future__ import annotations

import json
import jsonschema
import logging
import pathlib
from typing import Generator, List, Union


import garak._config
import garak.exception
from garak.data import path as data_path


PAYLOAD_SCHEMA = {
    "type": "object",
    "properties": {
        "garak_payload_name": {"type": "string"},
        "payload_types": {"type": "array", "items": {"type": "string"}},
        "detector_name": {"type": "string"},
        "detector_config": {"type": "object"},
        "payloads": {"type": "array", "items": {"type": "string"}},
        "lang": {"type": "string"},
    },
    "required": [
        "garak_payload_name",
        "payload_types",
        "payloads",
    ],
}

PAYLOAD_DIR = data_path / "payloads"


def _validate_payload(payload_json):
    try:
        jsonschema.validate(instance=payload_json, schema=PAYLOAD_SCHEMA)
    except jsonschema.ValidationError as ve:
        return ve
    return True


class PayloadGroup:
    """Represents a configured group of payloads for use with garak
    probes. Each group should have a name, one or more payload types, and
    a number of payload entries"""

    def _load(self):
        logging.debug("payload: Loading payload %s from %s", self.name, self.path)
        try:
            with open(self.path, "r", encoding="utf-8") as payloadfile:
                loaded_payload = json.load(payloadfile)

        except FileNotFoundError as fnfe:
            msg = "payload: file not found:" + str(self.path)
            logging.error(msg, exc_info=fnfe)
            raise garak.exception.PayloadFailure(msg) from fnfe

        except json.JSONDecodeError as jde:
            msg = "payload: JSON error:" + str(jde)
            logging.error(msg, exc_info=jde)
            raise garak.exception.PayloadFailure("Payload JSON error") from jde

        validation_result = _validate_payload(loaded_payload)
        if validation_result is not True:
            msg = "payload: JSON schema mismatch:" + str(validation_result)
            logging.error(msg, exc_info=validation_result)
            raise garak.exception.PayloadFailure(
                "Payload didn't match schema"
            ) from validation_result

        self.types = loaded_payload["payload_types"]
        self.payloads = [str(p) for p in loaded_payload["payloads"]]

        self.detector_name = None
        if "detector_name" in loaded_payload:
            self.detector_name = str(loaded_payload["detector_name"])

        self.detector_config = None
        if "detector_config" in loaded_payload:
            try:
                self.detector_config = dict(loaded_payload["detector_config"])

            except TypeError as te:
                msg = "payload: detector_config must be a dict, got: " + repr(
                    loaded_payload["detector_config"]
                )
                logging.warning(msg, exc_info=te)
                raise garak.exception.PayloadFailure(msg) from te

        if (
            garak._config.transient.reportfile is not None
            and not garak._config.transient.reportfile.closed
        ):
            payload_stat = pathlib.Path(self.path).stat()
            garak._config.transient.reportfile.write(
                json.dumps(
                    {
                        "entry_type": "payload_init",
                        "loading_complete": "payload",
                        "payload_name": str(self.name),
                        "payload_path": str(self.path),
                        "entries": len(self.payloads),
                        "filesize": int(payload_stat.st_size),
                        "mtime": str(payload_stat.st_mtime),
                    }
                )
                + "\n"
            )
        self._loaded = True

    def __init__(self, name: str, path) -> None:
        self.name = str(name)
        self.path = path
        self.types = None
        self.payloads = None
        self.detector_name = None
        self.detector_config = None
        self._loaded = False
        self._load()


class Director:
    """The payload Director manages payload groups. It'll inventory them on disk,
    manage enumeration of payloads (optionally given a payload type specification),
    and load them up."""

    payload_list = None

    def _scan_payload_dir(self, dir) -> dict:
        """Look for .json entries in a dir, load them, check which are
        payloads, return name:path dict. optionally filter by type prefixes"""

        payloads_found = {}
        dir = dir
        if not dir.is_dir():
            logging.debug("payload scan: skipping %s, not dir" % dir)
            return {}

        logging.debug("payload scan: %s" % dir)

        entries = dir.glob("**/*.[jJ][sS][oO][nN]")
        for payload_path in entries:
            with open(str(payload_path), "r", encoding="utf-8") as payload_path_file:
                try:
                    payload_decoded = json.load(payload_path_file)
                    payload_types = payload_decoded["payload_types"]
                except (json.JSONDecodeError, KeyError) as exc:
                    msg = f"payload scan: Invalid payload, skipping: {payload_path}"
                    logging.debug(msg, exc_info=exc)
                    # raise garak.exception.PayloadFailure(msg) from exc

                payload_name = payload_path.stem

                payloads_found[payload_name] = {
                    "path": payload_path,
                    "types": payload_types,
                }

        return payloads_found

    def _refresh_payloads(self) -> None:
        """Scan resources/payloads and the XDG_DATA_DIR/payloads for
        payload objects, and refresh self.payload_list"""
        self.__class__.payload_list = self._scan_payload_dir(PAYLOAD_DIR)

    def search(
        self, types: Union[List[str], None] = None, include_children=True
    ) -> Generator[str, None, None]:
        """Return list of payload names, optionally filtered by types"""
        for payload in self.__class__.payload_list:
            if types is None:
                yield payload
            else:
                if include_children is False:
                    matches = [
                        payload_type == type_prefix
                        for payload_type in self.__class__.payload_list[payload][
                            "types"
                        ]
                        for type_prefix in types
                    ]
                else:
                    matches = [
                        payload_type.startswith(type_prefix)
                        for payload_type in self.__class__.payload_list[payload][
                            "types"
                        ]
                        for type_prefix in types
                    ]
                if any(matches):
                    yield payload

    @staticmethod
    def _load_payload(
        name: str, path: Union[str, pathlib.Path, None] = None
    ) -> PayloadGroup:
        if path is None:
            path = PAYLOAD_DIR / f"{name}.json"
        return PayloadGroup(name, path)

    def load(self, name) -> PayloadGroup:
        """Return a PayloadGroup"""
        try:
            path = self.__class__.payload_list[name]["path"]
            p = self._load_payload(name, path)  # or raise KeyError

        except KeyError as ke:
            msg = (
                f"payload: Requested payload {name} is not registered in this Director"
            )
            logging.error(msg, exc_info=ke)
            raise garak.exception.PayloadFailure(msg) from ke

        except garak.exception.GarakException as ge:
            msg = f"payload: Requested payload {name} not found at expected path {path}"
            logging.error(msg, exc_info=ge)
            raise garak.exception.PayloadFailure(msg) from ge

        return p

    def __init__(self) -> None:
        if self.__class__.payload_list is None:
            self._refresh_payloads()


@staticmethod
def search(
    types: Union[List[str], None] = None, include_children=True
) -> Generator[str, None, None]:
    return Director().search(types, include_children)


def load(name: str) -> PayloadGroup:
    return Director().load(name)
