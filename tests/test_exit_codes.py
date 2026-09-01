from garak.exit_codes import ExitCode


def test_exit_code_values_are_positive():
    assert ExitCode.OK == 0
    assert ExitCode.INTERRUPTED == 1
    assert ExitCode.UNSPECIFIED == 127
