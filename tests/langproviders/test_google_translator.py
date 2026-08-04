from types import ModuleType, SimpleNamespace

import pytest


def _install_google_stubs(monkeypatch, client_cls, malformed_error_cls):
    translate_module = ModuleType("google.cloud.translate_v2")
    translate_module.Client = client_cls

    cloud_module = ModuleType("google.cloud")
    cloud_module.translate_v2 = translate_module

    exceptions_module = ModuleType("google.auth.exceptions")
    exceptions_module.MalformedError = malformed_error_cls

    auth_module = ModuleType("google.auth")
    auth_module.exceptions = exceptions_module

    google_module = ModuleType("google")
    google_module.cloud = cloud_module
    google_module.auth = auth_module

    ftfy_module = ModuleType("ftfy")

    monkeypatch.setitem(__import__("sys").modules, "google", google_module)
    monkeypatch.setitem(__import__("sys").modules, "google.cloud", cloud_module)
    monkeypatch.setitem(
        __import__("sys").modules, "google.cloud.translate_v2", translate_module
    )
    monkeypatch.setitem(__import__("sys").modules, "google.auth", auth_module)
    monkeypatch.setitem(
        __import__("sys").modules, "google.auth.exceptions", exceptions_module
    )
    monkeypatch.setitem(__import__("sys").modules, "ftfy", ftfy_module)

    return ftfy_module


def test_google_translator_service_account_auth_without_project_id(monkeypatch):
    from garak.langproviders.remote import GoogleTranslator

    calls = []
    service_account_client = SimpleNamespace(name="service-account")

    class FakeMalformedError(Exception):
        pass

    class FakeClient:
        @classmethod
        def from_service_account_json(cls, *args, **kwargs):
            calls.append((args, kwargs))
            return service_account_client

    ftfy_module = _install_google_stubs(monkeypatch, FakeClient, FakeMalformedError)

    translator = GoogleTranslator.__new__(GoogleTranslator)
    translator.api_key = "/tmp/service-account.json"
    translator.project_id = None
    translator._tested = True

    translator._load_langprovider()

    assert calls == [(("/tmp/service-account.json",), {})]
    assert translator.client is service_account_client
    assert translator.ftfy is ftfy_module


def test_google_translator_raises_on_malformed_service_account(monkeypatch, caplog):
    from garak.langproviders.remote import GoogleTranslator

    fallback_calls = []

    class FakeMalformedError(Exception):
        pass

    class FakeClient:
        @classmethod
        def from_service_account_json(cls, *args, **kwargs):
            raise FakeMalformedError("bad service account")

        def __new__(cls, *args, **kwargs):
            fallback_calls.append((args, kwargs))
            return SimpleNamespace(name="general-auth")

    _install_google_stubs(monkeypatch, FakeClient, FakeMalformedError)

    translator = GoogleTranslator.__new__(GoogleTranslator)
    translator.api_key = "/tmp/service-account.json"
    translator.project_id = None
    translator._tested = True

    with pytest.raises(FakeMalformedError, match="bad service account"):
        translator._load_langprovider()

    assert fallback_calls == []
    assert not hasattr(translator, "client")
    assert "Service account auth failed: bad service account" in caplog.text
    assert "attempting fallback" not in caplog.text
