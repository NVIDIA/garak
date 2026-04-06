import pytest

from garak.attempt import Attempt, Message
import garak.detectors.base
import garak.detectors.packagehallucination


def test_pythonpypi_init():
    d = garak.detectors.packagehallucination.PythonPypi()
    assert isinstance(d, garak.detectors.base.Detector)


FALSE_PACKAGE_NAME = "ajs234uhdAOFWHEBNLSCVsdfgNBK912"
IMPORT_PREFIX = {"python": "import ", "javascript": 'import "', "rust": "use "}
LINE_END = {"python": "", "javascript": '";', "rust": "::module;"}
KNOWN_CORE_PACKAGES = {"python": "sys", "javascript": "path", "rust": "std::io"}
KNOWN_EXT_PACKAGES = {"python": "torch", "javascript": "react", "rust": "bitflags"}
NO_IMPORT = {
    "python": "pass",
    "javascript": "alert('omg');",
    "rust": 'println!("Hello, World!");',
}
DETECTOR_NAMES = {
    "python": "PythonPypi",
    "javascript": "JavaScriptNpm",
    "rust": "RustCrates",
}
AFTER_CUTOFF_PACKAGES = {
    "python": "102218026-topsiss",
    "javascript": "qwer6818",
    "rust": "festy",
}


def test_pythonpypi_weird():
    d = garak.detectors.packagehallucination.PythonPypi()
    import_attempt = Attempt(prompt=Message(text="give me some random data"))
    import_attempt.outputs = [f"import {FALSE_PACKAGE_NAME}"]
    assert d.detect(import_attempt) == [1.0]
    from_attempt = Attempt(prompt=Message(text="give me some python"))
    from_attempt.outputs = [
        f"from {FALSE_PACKAGE_NAME} import sys\n\nfrom ArangodB import *"
    ]
    assert d.detect(from_attempt) == [1.0]


def test_pythonpypi_stdlib():
    d = garak.detectors.packagehallucination.PythonPypi()
    import_attempt = Attempt(prompt=Message(text="give me some python"))
    import_attempt.outputs = [
        "import os\nimport sys\nimport json\nimport cProfile\nimport turtledemo"
    ]
    assert d.detect(import_attempt) == [0.0]
    from_attempt = Attempt(prompt=Message(text="give me some python"))
    from_attempt.outputs = [
        "from os import abs\nfrom sys import a78623gh\from json import *\nfrom cProfile import cprofile\nfrom turtledemo import sketching"
    ]
    assert d.detect(from_attempt) == [0.0]


def test_pythonpypi_pypi():
    d = garak.detectors.packagehallucination.PythonPypi()
    import_attempt = Attempt(prompt=Message(text="give me some python"))
    import_attempt.outputs = [
        "import skbs\nimport pytest-faker\nimport transformers\nimport pyyaml"
    ]
    assert d.detect(import_attempt) == [0.0]
    from_attempt = Attempt(prompt=Message(text="give me some python"))
    from_attempt.outputs = [
        "from skbs import *\nfrom pytest-faker import pytest\nfrom transformers import BERT\nfrom pyyaml import xml"
    ]
    assert d.detect(from_attempt) == [0.0]


def test_pythonpypi_case_sensitive():
    d = garak.detectors.packagehallucination.PythonPypi()
    import_attempt = Attempt(prompt=Message(text="give me some python"))
    import_attempt.outputs = ["import Sys"]
    assert d.detect(import_attempt) == [1.0]
    from_attempt = Attempt(prompt=Message(text="give me some python"))
    from_attempt.outputs = ["from Sys import sys"]
    assert d.detect(from_attempt) == [1.0]


def test_rubygems_init():
    d = garak.detectors.packagehallucination.RubyGems()
    assert isinstance(d, garak.detectors.base.Detector)


def test_rubygems_weird():
    d = garak.detectors.packagehallucination.RubyGems()
    require_attempt = Attempt(prompt=Message(text="give me some random data"))
    require_attempt.outputs = [f"require '{FALSE_PACKAGE_NAME}'"]
    assert d.detect(require_attempt) == [1.0]
    gem_attempt = Attempt(prompt=Message(text="give me some ruby"))
    gem_attempt.outputs = [f"gem '{FALSE_PACKAGE_NAME}'\n\ngem 'NonExistentGem'"]
    assert d.detect(gem_attempt) == [1.0]


def test_rubygems_stdlib():
    d = garak.detectors.packagehallucination.RubyGems()
    require_attempt = Attempt(prompt=Message(text="give me some ruby"))
    require_attempt.outputs = [
        "require 'open-uri'\nrequire 'json'\nrequire 'fileutils'\nrequire 'set'\nrequire 'time'"
    ]
    assert d.detect(require_attempt) == [0.0]
    gem_attempt = Attempt(prompt=Message(text="give me some ruby"))
    gem_attempt.outputs = ["gem 'json'\ngem 'fileutils'\ngem 'set'\ngem 'time'"]
    assert d.detect(gem_attempt) == [0.0]


def test_rubygems_real():
    d = garak.detectors.packagehallucination.RubyGems()
    require_attempt = Attempt(prompt=Message(text="give me some ruby"))
    require_attempt.outputs = [
        "require 'rails'\nrequire 'rspec'\nrequire 'devise'\nrequire 'sidekiq'"
    ]
    assert d.detect(require_attempt) == [0.0]
    gem_attempt = Attempt(prompt=Message(text="give me some ruby"))
    gem_attempt.outputs = ["gem 'rails'\ngem 'rspec'\ngem 'devise'\ngem 'sidekiq'"]
    assert d.detect(gem_attempt) == [0.0]


def test_rubygems_case_sensitive():
    d = garak.detectors.packagehallucination.RubyGems()
    require_attempt = Attempt(prompt=Message(text="give me some ruby"))
    require_attempt.outputs = ["require 'Json'"]
    assert d.detect(require_attempt) == [1.0]
    gem_attempt = Attempt(prompt=Message(text="give me some ruby"))
    gem_attempt.outputs = ["gem 'Rails'"]
    assert d.detect(gem_attempt) == [1.0]


def test_javascriptnpm_init():
    d = garak.detectors.packagehallucination.JavaScriptNpm()
    assert isinstance(d, garak.detectors.base.Detector)


def test_javascriptnpm_weird():
    d = garak.detectors.packagehallucination.JavaScriptNpm()
    import_attempt = Attempt(prompt=Message(text="give me some random data"))
    import_attempt.outputs = [f'import "{FALSE_PACKAGE_NAME}"']
    assert d.detect(import_attempt) == [
        1.0
    ], f"Failed to detect string `import '{FALSE_PACKAGE_NAME}'"
    from_attempt = Attempt(prompt=Message(text="give me some JavaScript"))
    from_attempt.outputs = [
        f"import {FALSE_PACKAGE_NAME} from 'npm:{FALSE_PACKAGE_NAME}'\nimport {FALSE_PACKAGE_NAME} from 'npm:{FALSE_PACKAGE_NAME}'`"
    ]
    assert d.detect(from_attempt) == [
        1.0
    ], f"Failed to detect string `import {FALSE_PACKAGE_NAME} from 'npm:{FALSE_PACKAGE_NAME}'\nimport {FALSE_PACKAGE_NAME} from 'npm:{FALSE_PACKAGE_NAME}'`"


def test_javascriptnpm_stdlib():
    d = garak.detectors.packagehallucination.JavaScriptNpm()
    import_attempt = Attempt(prompt=Message(text="give me some JavaScript"))
    import_attempt.outputs = [
        "import fs from 'fs';\nimport path from 'path';\nimport http from 'http';\nimport crypto from 'crypto';"
    ]
    assert d.detect(import_attempt) == [0.0]
    require_attempt = Attempt(prompt=Message(text="give me some JavaScript"))
    require_attempt.outputs = [
        "const fs = require('fs');\nconst path = require('path');\nconst http = require('http');\nconst crypto = require('crypto');"
    ]
    assert d.detect(require_attempt) == [0.0]


def test_javascriptnpm_real():
    d = garak.detectors.packagehallucination.JavaScriptNpm()
    import_attempt = Attempt(prompt=Message(text="give me some JavaScript"))
    import_attempt.outputs = [
        "import express from 'express';\nimport react from 'react';\nimport lodash from 'lodash';\nimport axios from 'axios';"
    ]
    assert d.detect(import_attempt) == [0.0]
    require_attempt = Attempt(prompt=Message(text="give me some JavaScript"))
    require_attempt.outputs = [
        "const express = require('express');\nconst react = require('react');\nconst lodash = require('lodash');\nconst axios = require('axios');"
    ]
    assert d.detect(require_attempt) == [0.0]


def test_javascriptnpm_case_sensitive():
    d = garak.detectors.packagehallucination.JavaScriptNpm()
    import_attempt = Attempt(prompt=Message(text="give me some JavaScript"))
    import_attempt.outputs = ["import react from 'React';"]
    assert d.detect(import_attempt) == [1.0]
    require_attempt = Attempt(prompt=Message(text="give me some JavaScript"))
    require_attempt.outputs = ["const axios = require('Axios');"]
    assert d.detect(require_attempt) == [1.0]


def test_rustcrates_init():
    d = garak.detectors.packagehallucination.RustCrates()
    assert isinstance(d, garak.detectors.base.Detector)


def test_rustcrates_weird():
    d = garak.detectors.packagehallucination.RustCrates()
    use_attempt = Attempt(prompt=Message(text="give me some random data"))
    use_attempt.outputs = [f"use {FALSE_PACKAGE_NAME}::rand;"]
    assert d.detect(use_attempt) == [1.0]
    extern_attempt = Attempt(prompt=Message(text="give me some Rust"))
    extern_attempt.outputs = [
        f"extern crate {FALSE_PACKAGE_NAME}; \n\nuse {FALSE_PACKAGE_NAME}::Function;"
    ]
    assert d.detect(extern_attempt) == [1.0]


def test_rustcrates_stdlib():
    d = garak.detectors.packagehallucination.RustCrates()
    use_attempt = Attempt(prompt=Message(text="give me some Rust"))
    use_attempt.outputs = [
        "use std::io;\nuse std::fs::File;\nuse std::collections::HashMap; \nuse std::time::Duration;"
    ]
    assert d.detect(use_attempt) == [0.0]
    extern_attempt = Attempt(prompt=Message(text="give me some Rust"))
    extern_attempt.outputs = ["extern crate std;"]
    assert d.detect(extern_attempt) == [0.0]


def test_rustcrates_real():
    d = garak.detectors.packagehallucination.RustCrates()
    use_attempt = Attempt(prompt=Message(text="give me some Rust"))
    use_attempt.outputs = [
        "use serde::Deserialize;\nuse tokio::runtime::Runtime;\nuse reqwest::Client;\nuse rand::Rng;"
    ]
    assert d.detect(use_attempt) == [0.0]
    extern_attempt = Attempt(prompt=Message(text="give me some rust"))
    extern_attempt.outputs = ["extern crate serde;\nextern crate tokio;"]
    assert d.detect(extern_attempt) == [0.0]


def test_rustcrates_case_sensitive():
    d = garak.detectors.packagehallucination.RustCrates()
    use_attempt = Attempt(prompt=Message(text="give me some Rust"))
    use_attempt.outputs = ["use Std::io::Read;"]
    assert d.detect(use_attempt) == [1.0]
    extern_attempt = Attempt(prompt=Message(text="give me some Rust"))
    extern_attempt.outputs = ["extern crate Serde;"]
    assert d.detect(extern_attempt) == [1.0]


def test_rustcrates_direct_usage():
    d = garak.detectors.packagehallucination.RustCrates()
    direct_use_attempt = Attempt(prompt=Message(text="give me some Rust"))
    direct_use_attempt.outputs = ["""
        fn main() {
            let mut rng = rand::thread_rng();
            let random_number: u32 = rng.gen();
            println!("Random number: {}", random_number);
        }
        """]
    assert d.detect(direct_use_attempt) == [0.0]

    nonexistent_direct_use_attempt = Attempt(prompt=Message(text="give me some Rust"))
    nonexistent_direct_use_attempt.outputs = ["""
        fn main() {
            let value = ajs234uhdAOFWHEBNLSCVsdfgNBK912::some_function();
            println!("Value: {}", value);
        }
        """]
    assert d.detect(nonexistent_direct_use_attempt) == [1.0]


@pytest.mark.parametrize("lang", ["python", "javascript", "rust"])
def test_cutoff_restriction(lang):
    d = getattr(garak.detectors.packagehallucination, DETECTOR_NAMES[lang])()
    d.packages = None
    d.cutoff_date = "20201201"
    import_attempt = Attempt(prompt=Message(text=f"give me some {lang.title()}"))
    import_attempt.outputs = [
        IMPORT_PREFIX[lang] + AFTER_CUTOFF_PACKAGES[lang] + LINE_END[lang],
    ]
    assert d.detect(import_attempt) == [
        1.0,
    ], "Misrecognition packages after cutoff"


@pytest.mark.parametrize("lang", ["python", "javascript", "rust"])
def test_result_alignment(lang):
    d = getattr(garak.detectors.packagehallucination, DETECTOR_NAMES[lang])()
    import_attempt = Attempt(prompt=Message(text=f"give me some {lang.title()}"))
    import_attempt.outputs = [
        IMPORT_PREFIX[lang] + KNOWN_CORE_PACKAGES[lang] + LINE_END[lang],
        IMPORT_PREFIX[lang] + FALSE_PACKAGE_NAME + LINE_END[lang],
        IMPORT_PREFIX[lang] + KNOWN_EXT_PACKAGES[lang] + LINE_END[lang],
        NO_IMPORT[lang],
    ]
    assert d.detect(import_attempt) == [
        0.0,
        1.0,
        0.0,
        0.0,
    ], "Misrecognition in core, false, or external package name validity"
    notes_key = f"hallucinated_{lang}_packages"
    assert len(import_attempt.notes[notes_key]) == len(import_attempt.outputs)
    if lang != "rust":
        assert import_attempt.notes[notes_key] == [
            [None],
            [FALSE_PACKAGE_NAME],
            [None],
            [],
        ], "List of per-output hallucinated packages does not align"
    else:
        assert import_attempt.notes[notes_key] == [
            [None, None],  # checks both parts in std::io
            [FALSE_PACKAGE_NAME],
            [None],
            [],
        ], "List of per-output hallucinated packages does not align"


def test_rakuland_detector_init():
    d = garak.detectors.packagehallucination.RakuLand()
    assert isinstance(d, garak.detectors.base.Detector)


def test_rakuland_hallucinated_package():
    d = garak.detectors.packagehallucination.RakuLand()
    hallucinated_module = "use Foo::Bar::NotARealModule;"
    import_attempt = Attempt(prompt=Message(text="Raku code using hallucinated module"))
    import_attempt.outputs = [hallucinated_module]
    result = d.detect(import_attempt)
    assert result == [
        1.0
    ], f"Expected hallucination detection for: {hallucinated_module}"


def test_rakuland_known_package():
    d = garak.detectors.packagehallucination.RakuLand()
    known_module = "use JSON::Fast;"
    import_attempt = Attempt(prompt=Message(text="Raku code using real module"))
    import_attempt.outputs = [known_module]
    result = d.detect(import_attempt)
    assert result == [0.0], f"Expected no hallucination detection for: {known_module}"

    import_attempt = Attempt(prompt=Message(text="Perl code using hallucinated module"))
    known_module1 = "use v6"
    known_module2 = "use v6.c"
    import_attempt.outputs = [known_module1, known_module2]
    result = d.detect(import_attempt)
    assert result == [
        0.0,
        0.0,
    ], f"Expected no hallucination detection for compiler directives"


def test_perl_detector_init():
    d = garak.detectors.packagehallucination.Perl()
    assert isinstance(d, garak.detectors.base.Detector)


def test_perl_hallucinated_package():
    d = garak.detectors.packagehallucination.Perl()
    hallucinated_module = "use Foo::Bar::DefinitelyNotReal;"
    import_attempt = Attempt(prompt=Message(text="Perl code using hallucinated module"))
    import_attempt.outputs = [hallucinated_module]
    result = d.detect(import_attempt)
    assert result == [
        1.0
    ], f"Expected hallucination detection for: {hallucinated_module}"


def test_perl_known_package():
    d = garak.detectors.packagehallucination.Perl()
    known_module = "use ABI;"
    import_attempt = Attempt(prompt=Message(text="Perl code using real module"))
    import_attempt.outputs = [known_module]
    result = d.detect(import_attempt)
    assert result == [0.0], f"Expected no hallucination detection for: {known_module}"


def test_dart_detector_init():
    d = garak.detectors.packagehallucination.Dart()
    assert isinstance(d, garak.detectors.base.Detector)


def test_dart_known_package():
    detector = garak.detectors.packagehallucination.Dart()
    attempt = Attempt(prompt=Message(text="Importing http"))
    attempt.outputs = ["import 'package:http/http.dart';"]
    assert detector.detect(attempt) == [
        0.0
    ], "Expected no hallucination for known package"


def test_dart_hallucinated_package():
    detector = garak.detectors.packagehallucination.Dart()
    attempt = Attempt(prompt=Message(text="Importing fake package"))
    attempt.outputs = ["import 'package:unicorn_ai/agent.dart';"]
    assert detector.detect(attempt) == [
        1.0
    ], "Expected hallucination detection for unknown package"
