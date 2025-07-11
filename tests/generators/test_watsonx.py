from garak.generators.watsonx import WatsonXGenerator
import os
import pytest
import requests_mock


DEFAULT_DEPLOYMENT_NAME = "ibm/granite-3-8b-instruct"


@pytest.fixture
def set_fake_env(request) -> None:
    stored_env = {
        WatsonXGenerator.ENV_VAR: os.getenv(WatsonXGenerator.ENV_VAR, None),
        WatsonXGenerator.PID_ENV_VAR: os.getenv(WatsonXGenerator.PID_ENV_VAR, None),
        WatsonXGenerator.URI_ENV_VAR: os.getenv(WatsonXGenerator.URI_ENV_VAR, None),
        WatsonXGenerator.DID_ENV_VAR: os.getenv(WatsonXGenerator.DID_ENV_VAR, None),
    }

    def restore_env():
        for k, v in stored_env.items():
            if v is not None:
                os.environ[k] = v
            else:
                del os.environ[k]

    os.environ[WatsonXGenerator.ENV_VAR] = "XXXXXXXXXXXXX"
    os.environ[WatsonXGenerator.PID_ENV_VAR] = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
    os.environ[WatsonXGenerator.DID_ENV_VAR] = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
    os.environ[WatsonXGenerator.URI_ENV_VAR] = "https://garak.example.com/"
    request.addfinalizer(restore_env)


@pytest.mark.usefixtures("set_fake_env")
def test_bearer_token(watsonx_compat_mocks):
    with requests_mock.Mocker() as m:
        mock_response = watsonx_compat_mocks["watsonx_bearer_token"]

        extended_request = "identity/token"

        m.post(
            "https://garak.example.com/" + extended_request, json=mock_response["json"]
        )

        granite_llm = WatsonXGenerator(DEFAULT_DEPLOYMENT_NAME)
        token = granite_llm._set_bearer_token(
            iam_url="https://garak.example.com/identity/token"
        )

        assert granite_llm.bearer_token == (
            "Bearer " + mock_response["json"]["access_token"]
        )


@pytest.mark.usefixtures("set_fake_env")
def test_project(watsonx_compat_mocks):
    with requests_mock.Mocker() as m:
        mock_response = watsonx_compat_mocks["watsonx_generation"]
        extended_request = "/ml/v1/text/generation?version=2023-05-29"

        m.post(
            "https://garak.example.com/" + extended_request, json=mock_response["json"]
        )

        granite_llm = WatsonXGenerator(DEFAULT_DEPLOYMENT_NAME)
        response = granite_llm._generate_with_project("What is this?")

        assert granite_llm.name == response["model_id"]


@pytest.mark.usefixtures("set_fake_env")
def test_deployment(watsonx_compat_mocks):
    with requests_mock.Mocker() as m:
        mock_response = watsonx_compat_mocks["watsonx_generation"]
        extended_request = "/ml/v1/deployments/"
        extended_request += "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
        extended_request += "/text/generation?version=2023-05-29"

        m.post(
            "https://garak.example.com/" + extended_request, json=mock_response["json"]
        )

        granite_llm = WatsonXGenerator(DEFAULT_DEPLOYMENT_NAME)
        response = granite_llm._generate_with_deployment("What is this?")

        assert granite_llm.name == response["model_id"]
