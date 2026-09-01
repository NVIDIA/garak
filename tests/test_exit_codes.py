from garak.exception import (
    DetectorError,
    EvaluatorError,
    GeneratorError,
    ProbeError,
    ReportingError,
)
from garak.exit_codes import ExitCode


def test_exit_code_values_are_positive():
    assert ExitCode.OK == 0
    assert ExitCode.INTERRUPTED == 1
    assert ExitCode.UNSPECIFIED == 127


def test_component_errors_carry_exit_codes():
    assert ProbeError("probe failed").exit_code == ExitCode.PROBE
    assert GeneratorError("generator failed").exit_code == ExitCode.GENERATOR
    assert DetectorError("detector failed").exit_code == ExitCode.DETECTOR
    assert EvaluatorError("evaluator failed").exit_code == ExitCode.EVALUATOR
    assert ReportingError("report failed").exit_code == ExitCode.REPORTING
