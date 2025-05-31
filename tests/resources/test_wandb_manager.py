import pytest
from unittest.mock import MagicMock, patch
from garak.resources.wandb_manager import WandBManager
from garak.attempt import Attempt


@pytest.fixture
def wandb_manager():
    manager = WandBManager()
    manager._is_initialized = True
    manager.generator_name = "test-generator"
    return manager


@pytest.fixture
def mock_config():
    return {
        "system": MagicMock(wandb_enabled=True, wandb_project="test-project"),
        "run": MagicMock(seed=42, generations=10),
    }


@pytest.fixture
def sample_attempt():
    attempt = Attempt()
    attempt.probe_classname = "TestProbe"
    # Add messages before setting outputs
    attempt.messages = [{"role": "user", "content": "test prompt"}]
    attempt.outputs = ["test output"]
    attempt.detector_results = {"detector1": [0.5]}
    attempt.status = "success"
    attempt.goal = "test goal"
    attempt.lang = "en"
    attempt.notes = {"triggers": "test trigger"}
    attempt.reverse_translator_outputs = ["reversed output"]
    return attempt


@patch("garak.resources.wandb_manager._config", MagicMock())
@patch("wandb.init")
def test_init_wandb(mock_wandb_init):
    manager = WandBManager()
    manager.init_wandb("test-model", ["probe1"], ["detector1"])

    mock_wandb_init.assert_called_once()
    assert manager._is_initialized == True


def test_log_attempt(wandb_manager, sample_attempt):
    wandb_manager._is_initialized = True
    wandb_manager.log_attempt(sample_attempt)

    assert len(wandb_manager._pending_attempts) == 1
    stored_attempt = wandb_manager._pending_attempts[0]
    assert stored_attempt.probe_classname == "TestProbe"
    assert stored_attempt.outputs == ["test output"]


@patch("wandb.log")
def test_flush_attempts(mock_wandb_log, wandb_manager, sample_attempt):
    wandb_manager._is_initialized = True
    wandb_manager.log_attempt(sample_attempt)

    mock_table = MagicMock()
    with patch("wandb.Table", return_value=mock_table):
        wandb_manager.flush_attempts()

    assert len(wandb_manager._pending_attempts) == 1


@patch("wandb.log")
def test_log_evaluation(mock_wandb_log, wandb_manager):
    wandb_manager.log_evaluation(
        "TestEvaluator", "TestProbe", "TestDetector", passed=8, total=10
    )

    assert len(wandb_manager._pending_evaluations) == 1
    eval_data = wandb_manager._pending_evaluations[0]
    assert eval_data["pass_rate"] == 0.8
    assert eval_data["generator_name"] == "test-generator"
    assert eval_data["evaluator"] == "TestEvaluator"
    assert eval_data["probe"] == "TestProbe"
    assert eval_data["detector"] == "TestDetector"


@patch("garak.resources.wandb_manager.WandBManager.log_evaluation")
def test_flush_evaluations(mock_wandb_log, wandb_manager):
    # Add multiple evaluations with different probes
    test_data = [
        ("TestEvaluator", "group1.probe1", "TestDetector", 8, 10),
        ("TestEvaluator", "group1.probe2", "TestDetector", 7, 10),
        ("TestEvaluator", "group2.probe1", "TestDetector", 9, 10),
    ]

    for evaluator, probe, detector, passed, total in test_data:
        wandb_manager.log_evaluation(evaluator, probe, detector, passed, total)

    # Make sure wandb_manager is initialized
    wandb_manager._is_initialized = True
    wandb_manager.flush_evaluations()

    mock_wandb_log.assert_called()
    assert len(wandb_manager._pending_evaluations) == 0


@patch("garak.resources.wandb_manager.WandBManager.finish_wandb")
def test_finish_wandb(mock_wandb_finish, wandb_manager):
    # Make sure wandb_manager is initialized
    wandb_manager._is_initialized = True
    wandb_manager.finish_wandb()

    mock_wandb_finish.assert_called_once()
    assert wandb_manager._is_initialized == True
    assert len(wandb_manager._pending_attempts) == 0
    assert len(wandb_manager._pending_evaluations) == 0


def test_wandb_manager_not_initialized(wandb_manager):
    wandb_manager._is_initialized = False

    # These operations should not raise errors when W&B is not initialized
    wandb_manager.log_attempt(MagicMock())
    wandb_manager.flush_attempts()
    wandb_manager.log_evaluation("test", "test", "test", 1, 1)
    wandb_manager.flush_evaluations()
    wandb_manager.finish_wandb()


@pytest.mark.parametrize(
    "passed,total,expected_rate",
    [
        (8, 10, 0.8),
        (0, 10, 0.0),
        (10, 10, 1.0),
        (0, 0, 0.0),  # Edge case
    ],
)
def test_evaluation_pass_rates(wandb_manager, passed, total, expected_rate):
    wandb_manager.log_evaluation(
        "TestEvaluator", "TestProbe", "TestDetector", passed=passed, total=total
    )

    eval_data = wandb_manager._pending_evaluations[0]
    assert eval_data["pass_rate"] == expected_rate
