# SPDX-FileCopyrightText: Portions Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import binascii
import contextlib
import glob
from pathlib import Path
import pickle
import tempfile

import pytest

from garak.attempt import Attempt, Message
import garak.detectors.base
import garak.detectors.fileformats


def test_possiblepickle_init():
    d = garak.detectors.fileformats.PossiblePickleName()
    assert isinstance(d, garak.detectors.base.Detector)


possible_pickles = [
    ("config.json", 0.0),
    ("file.onnx", 0.0),
    ("file.pth", 0.0),
    ("model.pkl", 1.0),
    ("model.pickle", 1.0),
]


@pytest.mark.parametrize("possible_pickle", possible_pickles)
def test_possiblepickle_filenames(possible_pickle):
    d = garak.detectors.fileformats.PossiblePickleName()
    assert d._test_file(possible_pickle[0]) == possible_pickle[1]


def test_fileispickled_invalid_format():
    d = garak.detectors.fileformats.FileIsPickled()
    plain_attempt = Attempt(prompt="")
    plain_attempt.outputs = [Message(s) for s in ["a", "b", "c"]]
    with pytest.raises(
        ValueError
    ) as exc_info:  # should not process attempts without correct "format" note
        l = list(d.detect(plain_attempt))


def test_fileispickled_valid_format():
    d = garak.detectors.fileformats.FileIsPickled()
    file_attempt = Attempt(prompt="")
    file_attempt.notes["format"] = "local filename"
    file_attempt.outputs = [Message("")]
    l = list(d.detect(file_attempt))
    assert l == []


def test_fileispickled_nonpickle():
    d = garak.detectors.fileformats.FileIsPickled()
    nonpickle_file_attempt = Attempt(prompt="")
    nonpickle_file_attempt.notes["format"] = "local filename"
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as nonpickle_file:
        nonpickle_file.write(
            "Do you know what the sad part is, Odo? I'm a very good tailor."
        )
        nonpickle_file.close()
        nonpickle_file_attempt.outputs = [Message(nonpickle_file.name)]
        l = list(d.detect(nonpickle_file_attempt))
        assert l == [0.0]


def test_fileispickled_pickle_default():
    d = garak.detectors.fileformats.FileIsPickled()
    pickle_file_attempt = Attempt(prompt="")
    pickle_file_attempt.notes["format"] = "local filename"
    with tempfile.NamedTemporaryFile(mode="wb+", delete=False) as pickle_file:
        test_data_struct = {"key": ["value", 37176]}
        pickle.dump(test_data_struct, pickle_file)
        pickle_file.close()
        pickle_file_attempt.outputs = [Message(pickle_file.name)]
        l = list(d.detect(pickle_file_attempt))
        assert l == [1.0]


pickle_versions = [0, 1, 2, 3, 4, 5]


@pytest.mark.parametrize("pickle_ver", pickle_versions)
def test_fileispickled_pickle_versioned(pickle_ver):
    d = garak.detectors.fileformats.FileIsPickled()
    pickle_file_attempt = Attempt(prompt="")
    pickle_file_attempt.notes["format"] = "local filename"
    with tempfile.NamedTemporaryFile(mode="wb+", delete=False) as pickle_file:
        test_data_struct = {"key": ["value", 37176]}
        pickle.Pickler(pickle_file, pickle_ver).dump(test_data_struct)
        pickle_file.close()
        pickle_file_attempt.outputs = [Message(pickle_file.name)]
        l = list(d.detect(pickle_file_attempt))
        assert l == [1.0]


def test_fileisexectuable_nonexec():
    exec_attempt = garak.attempt.Attempt(prompt="")
    exec_attempt.notes["format"] = "local filename"
    d = garak.detectors.fileformats.FileIsExecutable()
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as test_file:
        test_file.write("I'm a very good tailor.")
        test_file.close()
        exec_attempt.outputs = [Message(test_file.name)]
        results = d.detect(exec_attempt)
        assert list(results) == [0.0]


path_prefix = Path("tests/data/fileformats/exec_files/")


@pytest.fixture
def decoded_filename(request, encoded_exec_filename):
    with open(encoded_exec_filename, "r", encoding="utf-8") as encodedfile:
        with tempfile.NamedTemporaryFile(mode="wb+", delete=False) as binfile:
            binfile.write(binascii.a2b_base64(encodedfile.read()))
            binfile.flush()
            yield binfile.name

    def remove_decoded():
        with contextlib.suppress(FileNotFoundError):
            Path(binfile.name).unlink()

    request.addfinalizer(remove_decoded)


try:
    import magic
except ImportError as e:
    magic = None


@pytest.mark.skipif(magic is None, reason="libmagic not available")
@pytest.mark.parametrize(
    "encoded_exec_filename", glob.glob(str(path_prefix / "*.base64"))
)
def test_fileisexectuable_exec(decoded_filename):
    exec_attempt = garak.attempt.Attempt(prompt="")
    exec_attempt.notes["format"] = "local filename"

    d = garak.detectors.fileformats.FileIsExecutable()
    exec_attempt.outputs = [Message(decoded_filename)]
    results = d.detect(exec_attempt)
    assert list(results) == [1.0]
