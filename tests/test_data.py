# SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import pytest
import random
import tempfile
import os

from pathlib import Path
from garak import _config
from garak.exception import GarakException
from garak.data import path as data_path
from garak.data import LocalDataPath


@pytest.fixture
def random_resource_filename(request) -> None:
    with tempfile.NamedTemporaryFile(
        dir=LocalDataPath.ORDERED_SEARCH_PATHS[-1], mode="w", delete=False
    ) as tmpfile:
        tmpfile.write("file data")

    def remove_files():
        for path in LocalDataPath.ORDERED_SEARCH_PATHS:
            rem_path = path / os.path.basename(tmpfile.name)
            if rem_path.exists():
                rem_path.unlink()

    request.addfinalizer(remove_files)

    return os.path.basename(tmpfile.name)


def test_no_relative_escape():
    with pytest.raises(GarakException) as exc_info:
        data_path / ".."
    assert "does not refer to a valid path" in str(exc_info.value)


def test_no_relative_escape_extended():
    autodan_path = data_path / "autodan"
    with pytest.raises(GarakException) as exc_info:
        autodan_path / ".." / ".." / "configs"
    assert "does not refer to a valid path" in str(exc_info.value)


def test_allow_relative_in_path():
    source = data_path / "autodan" / ".." / "gcg"
    assert source.name == "gcg"


def test_known_resource_found():
    known_filename = "tags.misp.tsv"
    source = data_path / known_filename
    assert source.name == known_filename


def test_local_override(random_resource_filename):
    source = data_path / random_resource_filename
    assert _config.transient.package_dir in source.parents

    data_root_path = _config.transient.data_dir / "data"
    data_root_path.mkdir(parents=True, exist_ok=True)
    with open(
        data_root_path / random_resource_filename, encoding="utf-8", mode="w"
    ) as f:
        f.write("fake data")

    source = data_path / random_resource_filename
    assert _config.transient.data_dir in source.parents


@pytest.fixture
def random_file_tree(request) -> None:
    files = []
    temp_dir = tempfile.mkdtemp(dir=LocalDataPath.ORDERED_SEARCH_PATHS[-1])
    temp_dirname = os.path.basename(temp_dir)
    temp_dir = Path(temp_dir)
    data_dir = LocalDataPath.ORDERED_SEARCH_PATHS[0] / temp_dirname
    data_dir.mkdir()
    testing_temp_dir = temp_dir / "testing"
    testing_temp_dir.mkdir()
    testing_data_dir = data_dir / "testing"
    testing_data_dir.mkdir()

    for i in range(random.randint(1, 10)):
        with tempfile.NamedTemporaryFile(
            dir=testing_temp_dir, suffix=".test", mode="w", delete=False
        ) as tmpfile:
            tmpfile.write("file data")
            files.append(os.path.basename(tmpfile.name))

    override_files = []
    for i in range(random.randint(1, len(files))):
        with open(testing_data_dir / files[i], mode="w") as over_file:
            over_file.write("override data")
            override_files.append(os.path.basename(over_file.name))

    def remove_files():
        for path in LocalDataPath.ORDERED_SEARCH_PATHS:
            for file in files:
                rem_path = path / temp_dirname / "testing" / os.path.basename(file)
                if rem_path.exists():
                    rem_path.unlink()
            rem_path.parent.rmdir()
            rem_path.parent.parent.rmdir()

    request.addfinalizer(remove_files)

    return (temp_dirname, files, override_files)


def test_consolidated_glob(random_file_tree):
    dirname, files, override_files = random_file_tree
    glob_files = (data_path / dirname / "testing").glob("*.test")
    found_override_files = []
    for file in glob_files:
        if LocalDataPath.ORDERED_SEARCH_PATHS[0] in file.parents:
            found_override_files.append(file)

    assert len(glob_files) == len(files)
    assert len(found_override_files) == len(override_files)


def test_consolidated_rglob(random_file_tree):
    dirname, files, override_files = random_file_tree
    glob_files = (data_path / dirname).rglob("*.test")
    found_override_files = []
    for file in glob_files:
        if file.is_file() and LocalDataPath.ORDERED_SEARCH_PATHS[0] in file.parents:
            found_override_files.append(file)

    assert len(glob_files) == len(files)
    assert len(found_override_files) == len(override_files)
