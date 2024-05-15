import pytest
import os
from dataclasses import dataclass


@dataclass
class MockApi:
    completion: dict
    chat: dict
    auth_fail: dict
    models: dict


@pytest.fixture
def openai_compat_mocks():
    """Mock responses for OpenAI compatible endpoints"""

    return MockApi(
        completion={
            "code": 200,
            "json": {
                "id": "cmpl-uqkvlQyYK7bGYrRHQ0eXlWi7",
                "object": "text_completion",
                "created": 1589478378,
                "model": "gpt-3.5-turbo-instruct",
                "system_fingerprint": "fp_44709d6fcb",
                "choices": [
                    {
                        "text": "This is indeed a test",
                        "index": 0,
                        "logprobs": None,
                        "finish_reason": "length",
                    }
                ],
                "usage": {
                    "prompt_tokens": 5,
                    "completion_tokens": 7,
                    "total_tokens": 12,
                },
            },
        },
        chat={
            "code": 200,
            "json": {
                "id": "chatcmpl-abc123",
                "object": "chat.completion",
                "created": 1677858242,
                "model": "gpt-3.5-turbo-0613",
                "usage": {
                    "prompt_tokens": 13,
                    "completion_tokens": 7,
                    "total_tokens": 20,
                },
                "choices": [
                    {
                        "message": {"role": "assistant", "content": "This is a test!"},
                        "logprobs": None,
                        "finish_reason": "stop",
                        "index": 0,
                    }
                ],
            },
        },
        auth_fail={
            "code": 401,
            "json": {
                "error": {
                    "message": "Incorrect API key provided: invalid_***_key. You can find your API key at https://platform.openai.com/account/api-keys.",
                    "type": "invalid_request_error",
                    "param": None,
                    "code": "invalid_api_key",
                }
            },
        },
        models={
            "code": 200,
            "json": {
                "object": "list",
                "data": [
                    {
                        "id": "model-id-0",
                        "object": "model",
                        "created": 1686935002,
                        "owned_by": "organization-owner",
                    },
                    {
                        "id": "model-id-1",
                        "object": "model",
                        "created": 1686935002,
                        "owned_by": "organization-owner",
                    },
                    {
                        "id": "model-id-2",
                        "object": "model",
                        "created": 1686935002,
                        "owned_by": "openai",
                    },
                ],
                "object": "list",
            },
        },
    )
