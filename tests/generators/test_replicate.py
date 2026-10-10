from unittest.mock import Mock

from garak.attempt import Conversation, Message, Turn
from garak.generators.replicate import InferenceEndpoint


def test_replicate_inference_endpoint_returns_single_message():
    generator = InferenceEndpoint.__new__(InferenceEndpoint)
    generator.client = Mock()
    generator.name = "owner/private-endpoint"
    generator.max_tokens = 20
    generator.temperature = 0.7
    generator.top_p = 0.9
    generator.repetition_penalty = 1.1

    prediction = Mock()
    prediction.output = ["hello", " world"]
    deployment = Mock()
    deployment.predictions.create.return_value = prediction
    generator.client.deployments.get.return_value = deployment

    conv = Conversation([Turn("user", Message("test prompt"))])

    output = generator._call_model(conv)

    assert output == [Message("hello world")]
    prediction.wait.assert_called_once_with()
