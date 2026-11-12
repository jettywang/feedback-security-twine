import base64
import getpass
import json
import logging
import platform
import re
import time
import typing as t

import pytest
import requests.auth
from id import AmbientCredentialError

from twine import auth
from twine import exceptions
from twine import utils


@pytest.fixture
def config() -> utils.RepositoryConfig:
    return dict(repository="system")


def test_get_username_keyring_defers_to_prompt(monkeypatch, entered_username, config):
    class MockKeyring:
        @staticmethod
        def get_credential(system, user):
            return None

    monkeypatch.setattr(auth, "keyring", MockKeyring)

    username = auth.Resolver(config, auth.CredentialInput()).username
    assert username == "entered user"


def test_get_username_keyring_not_installed_defers_to_prompt(
    monkeypatch, entered_username, config
):
    monkeypatch.setattr(auth, "keyring", None)

    username = auth.Resolver(config, auth.CredentialInput()).username
    assert username == "entered user"


def test_get_password_keyring_defers_to_prompt(monkeypatch, entered_password, config):
    class MockKeyring:
        @staticmethod
        def get_password(system, user):
            return None

    monkeypatch.setattr(auth, "keyring", MockKeyring)

    pw = auth.Resolver(config, auth.CredentialInput("user")).password
    assert pw == "entered pw"


def test_get_password_keyring_not_installed_defers_to_prompt(
    monkeypatch, entered_password, config
):
    monkeypatch.setattr(auth, "keyring", None)

    pw = auth.Resolver(config, auth.CredentialInput("user")).password
    assert pw == "entered pw"


def test_no_password_defers_to_prompt(monkeypatch, entered_password, config):
    config.update(password=None)
    pw = auth.Resolver(config, auth.CredentialInput("user")).password
    assert pw == "entered pw"


def test_empty_password_bypasses_prompt(monkeypatch, entered_password, config):
    config.update(password="")
    pw = auth.Resolver(config, auth.CredentialInput("user")).password
    assert pw == ""


def test_no_username_non_interactive_aborts(config):
    with pytest.raises(exceptions.NonInteractive):
        auth.Private(config, auth.CredentialInput()).username


def test_no_password_non_interactive_aborts(config):
    with pytest.raises(exceptions.NonInteractive):
        auth.Private(config, auth.CredentialInput("user")).password


def test_get_username_and_password_keyring_overrides_prompt(
    monkeypatch, config, caplog
):
    caplog.set_level(logging.INFO, "twine")

    class MockKeyring:
        @staticmethod
        def get_credential(system, user):
            return auth.CredentialInput(
                "real_user", f"real_user@{system} sekure pa55word"
            )

        @staticmethod
        def get_password(system, user):
            cred = MockKeyring.get_credential(system, user)
            if user != cred.username:
                raise RuntimeError("unexpected username")
            return cred.password

    monkeypatch.setattr(auth, "keyring", MockKeyring)

    res = auth.Resolver(config, auth.CredentialInput())

    assert res.username == "real_user"
    assert res.password == "real_user@system sekure pa55word"

    assert caplog.messages == [
        "Querying keyring for username",
        "username set from keyring",
        "Querying keyring for password",
        "password set from keyring",
    ]


@pytest.fixture
def keyring_missing_get_credentials(monkeypatch):
    """Simulate keyring prior to 15.2 that does not have the 'get_credential' API."""
    monkeypatch.delattr(auth.keyring, "get_credential")


@pytest.fixture
def entered_username(monkeypatch):
    monkeypatch.setattr(auth, "input", lambda prompt: "entered user", raising=False)


def test_get_username_keyring_missing_get_credentials_prompts(
    entered_username, keyring_missing_get_credentials, config
):
    assert auth.Resolver(config, auth.CredentialInput()).username == "entered user"


def test_get_username_keyring_missing_non_interactive_aborts(
    entered_username, keyring_missing_get_credentials, config
):
    with pytest.raises(exceptions.NonInteractive):
        auth.Private(config, auth.CredentialInput()).username


def test_get_password_keyring_missing_non_interactive_aborts(
    entered_username, keyring_missing_get_credentials, config
):
    with pytest.raises(exceptions.NonInteractive):
        auth.Private(config, auth.CredentialInput("user")).password


def test_get_username_keyring_runtime_error_logged(
    entered_username, monkeypatch, config, caplog
):
    class FailKeyring:
        """Simulate missing keyring backend raising RuntimeError on get_credential."""

        @staticmethod
        def get_credential(system, username):
            raise RuntimeError("fail!")

    monkeypatch.setattr(auth, "keyring", FailKeyring)

    assert auth.Resolver(config, auth.CredentialInput()).username == "entered user"

    assert re.search(
        r"Error getting username from keyring.+Traceback.+RuntimeError: fail!",
        caplog.text,
        re.DOTALL,
    )


def test_get_password_keyring_runtime_error_logged(
    entered_username, entered_password, monkeypatch, config, caplog
):
    class FailKeyring:
        """Simulate missing keyring backend raising RuntimeError on get_password."""

        @staticmethod
        def get_password(system, username):
            raise RuntimeError("fail!")

    monkeypatch.setattr(auth, "keyring", FailKeyring)

    assert auth.Resolver(config, auth.CredentialInput()).password == "entered pw"

    assert re.search(
        r"Error getting password from keyring.+Traceback.+RuntimeError: fail!",
        caplog.text,
        re.DOTALL,
    )


def _raise_home_key_error():
    """Simulate environment from https://github.com/pypa/twine/issues/889."""
    try:
        raise KeyError("HOME")
    except KeyError:
        raise KeyError("uid not found: 999")


def test_get_username_keyring_key_error_logged(
    entered_username, monkeypatch, config, caplog
):
    class FailKeyring:
        @staticmethod
        def get_credential(system, username):
            _raise_home_key_error()

    monkeypatch.setattr(auth, "keyring", FailKeyring)

    assert auth.Resolver(config, auth.CredentialInput()).username == "entered user"

    assert re.search(
        r"Error getting username from keyring"
        r".+Traceback"
        r".+KeyError: 'HOME'"
        r".+KeyError: 'uid not found: 999'",
        caplog.text,
        re.DOTALL,
    )


def test_get_password_keyring_key_error_logged(
    entered_username, entered_password, monkeypatch, config, caplog
):
    class FailKeyring:
        @staticmethod
        def get_password(system, username):
            _raise_home_key_error()

    monkeypatch.setattr(auth, "keyring", FailKeyring)

    assert auth.Resolver(config, auth.CredentialInput()).password == "entered pw"

    assert re.search(
        r"Error getting password from keyring"
        r".+Traceback"
        r".+KeyError: 'HOME'"
        r".+KeyError: 'uid not found: 999'",
        caplog.text,
        re.DOTALL,
    )


def test_logs_cli_values(caplog, config):
    caplog.set_level(logging.INFO, "twine")

    res = auth.Resolver(config, auth.CredentialInput("username", "password"))

    assert res.username == "username"
    assert res.password == "password"

    assert caplog.messages == [
        "username set by command options",
        "password set by command options",
    ]


def test_logs_config_values(config, caplog):
    caplog.set_level(logging.INFO, "twine")

    config.update(username="username", password="password")
    res = auth.Resolver(config, auth.CredentialInput())

    assert res.username == "username"
    assert res.password == "password"

    assert caplog.messages == [
        "username set from config file",
        "password set from config file",
    ]


@pytest.mark.parametrize(
    "password, warning",
    [
        ("", "Your password is empty"),
        ("\x16", "Your password contains control characters"),
        ("entered\x16pw", "Your password contains control characters"),
    ],
)
def test_warns_for_empty_password(
    password,
    warning,
    monkeypatch,
    entered_username,
    config,
    caplog,
):
    # Avoiding additional warning "No recommended backend was available"
    monkeypatch.setattr(auth.keyring, "get_password", lambda system, user: None)

    monkeypatch.setattr(getpass, "getpass", lambda prompt: password)

    assert auth.Resolver(config, auth.CredentialInput()).password == password

    assert caplog.messages[0].startswith(warning)


@pytest.mark.skipif(
    platform.machine() in {"ppc64le", "s390x"},
    reason="keyring module is optional on ppc64le and s390x",
)
def test_keyring_module():
    assert auth.keyring is not None


def test_resolver_authenticator_config_authentication(config):
    config.update(username="username", password="password")
    res = auth.Resolver(config, auth.CredentialInput())
    assert isinstance(res.authenticator, requests.auth.HTTPBasicAuth)


def test_resolver_authenticator_credential_input_authentication(config):
    res = auth.Resolver(config, auth.CredentialInput("username", "password"))
    assert isinstance(res.authenticator, requests.auth.HTTPBasicAuth)


def test_resolver_authenticator_trusted_publishing_authentication(config):
    res = auth.Resolver(
        config, auth.CredentialInput(username="__token__", password="skip-stdin")
    )
    res._tp_token = auth.TrustedPublishingToken(
        success=True,
        token="fake-tp-token",
    )
    assert isinstance(res.authenticator, auth.TrustedPublishingAuthenticator)


class MockResponse:
    def __init__(self, status_code: int, json: t.Any) -> None:
        self.status_code = status_code
        self._json = json

    def json(self, *args, **kwargs) -> t.Any:
        return self._json

    def raise_for_status(self) -> None:
        if 400 <= self.status_code:
            raise requests.exceptions.HTTPError()

    @property
    def ok(self) -> bool:
        return self.status_code < 400


class MockSession:
    def __init__(
        self,
        get_response_list: t.List[MockResponse],
        post_response_list: t.List[MockResponse],
    ) -> None:
        self.post_counter = self.get_counter = 0
        self.get_response_list = get_response_list
        self.post_response_list = post_response_list

    def get(self, url: str, **kwargs) -> MockResponse:
        response = self.get_response_list[self.get_counter]
        self.get_counter += 1
        return response

    def post(self, url: str, **kwargs) -> MockResponse:
        response = self.post_response_list[self.post_counter]
        self.post_counter += 1
        return response


def test_trusted_publish_authenticator_refreshes_token(monkeypatch, config):
    def make_session():
        return MockSession(
            get_response_list=[
                MockResponse(status_code=200, json={"audience": "fake-aud"})
            ],
            post_response_list=[
                MockResponse(
                    status_code=200,
                    json={
                        "success": True,
                        "token": "new-token",
                        "expires": int(time.time()) + 900,
                    },
                ),
            ],
        )

    def detect_credential(*args, **kwargs) -> str:
        return "fake-oidc-token"

    config.update({"repository": utils.TEST_REPOSITORY})
    res = auth.Resolver(config, auth.CredentialInput(username="__token__"))
    res._tp_token = auth.TrustedPublishingToken(
        success=True,
        token="expiring-tp-token",
    )
    res._expires = int(time.time()) + 4 * 60
    monkeypatch.setattr(auth, "detect_credential", detect_credential)
    monkeypatch.setattr(auth.utils, "make_requests_session", make_session)
    authenticator = auth.TrustedPublishingAuthenticator(resolver=res)
    prepped_req = requests.models.PreparedRequest()
    prepped_req.prepare_headers({})
    request = authenticator(prepped_req)
    assert (
        request.headers["Authorization"]
        == f"Basic {base64.b64encode(b'__token__:new-token').decode()}"
    )


def test_trusted_publish_authenticator_reuses_token(monkeypatch, config):
    def make_session():
        return MockSession(
            get_response_list=[
                MockResponse(status_code=200, json={"audience": "fake-aud"})
            ],
            post_response_list=[
                MockResponse(
                    status_code=200,
                    json={
                        "success": True,
                        "token": "new-token",
                        "expires": int(time.time()) + 900,
                    },
                ),
            ],
        )

    def detect_credential(*args, **kwargs) -> str:
        return "fake-oidc-token"

    config.update({"repository": utils.TEST_REPOSITORY})
    res = auth.Resolver(config, auth.CredentialInput(username="__token__"))
    res._tp_token = auth.TrustedPublishingToken(
        success=True,
        token="valid-tp-token",
    )
    res._expires = int(time.time()) + 900
    monkeypatch.setattr(auth, "detect_credential", detect_credential)
    monkeypatch.setattr(auth.utils, "make_requests_session", make_session)
    authenticator = auth.TrustedPublishingAuthenticator(resolver=res)
    prepped_req = requests.models.PreparedRequest()
    prepped_req.prepare_headers({})
    request = authenticator(prepped_req)
    assert (
        request.headers["Authorization"]
        == f"Basic {base64.b64encode(b'__token__:valid-tp-token').decode()}"
    )


def test_inability_to_make_token_raises_error():
    class MockResolver:
        def make_trusted_publishing_token(self) -> None:
            return None

    authenticator = auth.TrustedPublishingAuthenticator(
        resolver=MockResolver(),
    )
    with pytest.raises(exceptions.TrustedPublishingFailure):
        authenticator(None)


class RecordingKeyring:
    """Fake keyring that records every lookup instead of returning a secret."""

    def __init__(self) -> None:
        self.calls: t.List[t.Tuple[str, str, t.Any]] = []

    def get_credential(self, system, user):
        self.calls.append(("get_credential", system, user))
        return None

    def get_password(self, system, user):
        self.calls.append(("get_password", system, user))
        return None


def _pypi_config() -> utils.RepositoryConfig:
    return dict(repository=utils.TEST_REPOSITORY)


def _minting_session(
    get_responses: t.Optional[t.List[MockResponse]] = None,
    post_responses: t.Optional[t.List[MockResponse]] = None,
) -> t.Callable[[], MockSession]:
    get_responses = get_responses or [
        MockResponse(status_code=200, json={"audience": "fake-aud"})
    ]
    post_responses = post_responses or [
        MockResponse(
            status_code=200,
            json={
                "success": True,
                "token": "minted-tp-token",
                "expires": int(time.time()) + 900,
            },
        )
    ]

    def make_session() -> MockSession:
        return MockSession(
            get_response_list=list(get_responses),
            post_response_list=list(post_responses),
        )

    return make_session


def _restricted_resolver(
    config: utils.RepositoryConfig,
    monkeypatch: pytest.MonkeyPatch,
    **input_kwargs: t.Any,
) -> auth.Resolver:
    monkeypatch.setattr(
        auth.utils,
        "make_requests_session",
        _minting_session(
            input_kwargs.pop("get_responses", None),
            input_kwargs.pop("post_responses", None),
        ),
    )
    monkeypatch.setattr(auth, "detect_credential", lambda *a, **k: "fake-oidc-token")
    return auth.Resolver(
        config,
        auth.CredentialInput(**input_kwargs),
        credential_source=auth.TRUSTED_PUBLISHING,
    )


def test_credential_source_restriction_mints_token_without_keyring(
    monkeypatch, caplog
):
    caplog.set_level(logging.INFO, "twine")
    keyring = RecordingKeyring()
    monkeypatch.setattr(auth, "keyring", keyring)
    resolver = _restricted_resolver(_pypi_config(), monkeypatch)

    assert resolver.username == "__token__"
    assert resolver.password == "minted-tp-token"
    assert keyring.calls == []
    assert "keyring and prompts are disabled" in caplog.text


def test_credential_source_restriction_uses_token_authenticator(monkeypatch):
    resolver = _restricted_resolver(_pypi_config(), monkeypatch)
    assert isinstance(resolver.authenticator, auth.TrustedPublishingAuthenticator)


def test_credential_source_restriction_ignores_keyring_password(monkeypatch):
    keyring = RecordingKeyring()
    monkeypatch.setattr(auth, "keyring", keyring)
    resolver = _restricted_resolver(_pypi_config(), monkeypatch)

    assert resolver.password == "minted-tp-token"
    assert keyring.calls == []


def test_credential_source_restriction_rejects_static_password(monkeypatch):
    monkeypatch.setattr(auth, "keyring", RecordingKeyring())
    resolver = _restricted_resolver(
        _pypi_config(), monkeypatch, username="__token__", password="fallback-secret"
    )
    with pytest.raises(exceptions.InvalidConfiguration, match="credential source"):
        resolver.password


def test_credential_source_restriction_rejects_config_password(monkeypatch):
    config = _pypi_config()
    config["password"] = "pypirc-secret"
    resolver = _restricted_resolver(config, monkeypatch)
    with pytest.raises(exceptions.InvalidConfiguration, match="credential source"):
        resolver.password


def test_credential_source_restriction_unsupported_repository(monkeypatch):
    resolver = _restricted_resolver(
        dict(repository="https://upload.example.org/legacy/"), monkeypatch
    )
    with pytest.raises(exceptions.InvalidConfiguration, match="only supported"):
        resolver.password


def test_credential_source_restriction_fails_at_audience_stage(monkeypatch):
    resolver = _restricted_resolver(
        _pypi_config(),
        monkeypatch,
        get_responses=[MockResponse(status_code=503, json={})],
    )
    with pytest.raises(exceptions.CredentialSourceUnavailable) as exc_info:
        resolver.password
    assert exc_info.value.stage == auth.STAGE_AUDIENCE
    assert exc_info.value.source == auth.TRUSTED_PUBLISHING


def test_credential_source_restriction_fails_at_oidc_stage(monkeypatch):
    monkeypatch.setattr(
        auth.utils,
        "make_requests_session",
        _minting_session(),
    )

    def no_ambient_credential(*args, **kwargs) -> None:
        return None

    monkeypatch.setattr(auth, "detect_credential", no_ambient_credential)
    resolver = auth.Resolver(
        _pypi_config(),
        auth.CredentialInput(),
        credential_source=auth.TRUSTED_PUBLISHING,
    )
    with pytest.raises(exceptions.CredentialSourceUnavailable) as exc_info:
        resolver.password
    assert exc_info.value.stage == auth.STAGE_OIDC_TOKEN


def test_credential_source_restriction_ambient_error_reports_oidc_stage(monkeypatch):
    monkeypatch.setattr(
        auth.utils,
        "make_requests_session",
        _minting_session(),
    )

    def raise_ambient_error(*args, **kwargs) -> str:
        raise AmbientCredentialError("CI platform rejected the request")

    monkeypatch.setattr(auth, "detect_credential", raise_ambient_error)
    resolver = auth.Resolver(
        _pypi_config(),
        auth.CredentialInput(),
        credential_source=auth.TRUSTED_PUBLISHING,
    )
    with pytest.raises(exceptions.CredentialSourceUnavailable) as exc_info:
        resolver.password
    assert exc_info.value.stage == auth.STAGE_OIDC_TOKEN
    assert "CI platform rejected" in str(exc_info.value)


def test_credential_source_restriction_fails_at_exchange_stage(monkeypatch):
    resolver = _restricted_resolver(
        _pypi_config(),
        monkeypatch,
        post_responses=[
            MockResponse(
                status_code=403,
                json={
                    "errors": [
                        {
                            "code": "invalid-token",
                            "description": "the OIDC token was not accepted",
                        }
                    ]
                },
            )
        ],
    )
    with pytest.raises(exceptions.CredentialSourceUnavailable) as exc_info:
        resolver.password
    assert exc_info.value.stage == auth.STAGE_TOKEN_EXCHANGE
    assert "invalid-token" in str(exc_info.value)


def test_credential_source_restriction_fails_at_response_stage(monkeypatch):
    class InvalidJsonResponse(MockResponse):
        def json(self, *args, **kwargs) -> t.Any:
            raise json.JSONDecodeError("Expecting value", "doc", 0)

    resolver = _restricted_resolver(
        _pypi_config(),
        monkeypatch,
        post_responses=[InvalidJsonResponse(status_code=200, json={})],
    )
    with pytest.raises(exceptions.CredentialSourceUnavailable) as exc_info:
        resolver.password
    assert exc_info.value.stage == auth.STAGE_TOKEN_RESPONSE


def test_credential_source_restriction_never_prompts(monkeypatch):
    monkeypatch.setattr(
        auth.utils,
        "make_requests_session",
        _minting_session(
            get_responses=[MockResponse(status_code=500, json={})],
        ),
    )
    monkeypatch.setattr(auth, "detect_credential", lambda *a, **k: "fake-oidc-token")

    def fail_prompt(*args, **kwargs) -> str:
        raise AssertionError("a prompt should never be reached")

    monkeypatch.setattr(auth.getpass, "getpass", fail_prompt)
    monkeypatch.setattr(auth, "input", fail_prompt, raising=False)

    resolver = auth.Private(
        _pypi_config(),
        auth.CredentialInput(),
        credential_source=auth.TRUSTED_PUBLISHING,
    )
    with pytest.raises(exceptions.CredentialSourceUnavailable) as exc_info:
        resolver.password
    assert exc_info.value.stage == auth.STAGE_AUDIENCE


def test_unknown_credential_source_rejected(config):
    with pytest.raises(exceptions.InvalidConfiguration, match="Unsupported"):
        auth.Resolver(
            config,
            auth.CredentialInput(),
            credential_source="keyring",
        )


def test_default_lookup_order_prefers_keyring_over_trusted_publishing(
    monkeypatch, caplog
):
    caplog.set_level(logging.INFO, "twine")
    keyring = RecordingKeyring()

    class KeyringWithSecret(RecordingKeyring):
        def get_password(self, system, user):
            super().get_password(system, user)
            return "keyring-secret"

    recording = KeyringWithSecret()
    monkeypatch.setattr(auth, "keyring", recording)

    def fail_session() -> MockSession:
        raise AssertionError("trusted publishing must not be attempted")

    monkeypatch.setattr(auth.utils, "make_requests_session", fail_session)

    resolver = auth.Resolver(_pypi_config(), auth.CredentialInput("__token__"))
    assert resolver.password == "keyring-secret"
    assert recording.calls == [("get_password", utils.TEST_REPOSITORY, "__token__")]
    assert "password set from keyring" in caplog.messages


def test_default_lookup_order_falls_back_to_trusted_publishing(monkeypatch):
    monkeypatch.setattr(auth, "keyring", RecordingKeyring())
    monkeypatch.setattr(
        auth.utils,
        "make_requests_session",
        _minting_session(),
    )
    monkeypatch.setattr(auth, "detect_credential", lambda *a, **k: "fake-oidc-token")

    resolver = auth.Resolver(_pypi_config(), auth.CredentialInput("__token__"))
    assert resolver.password == "minted-tp-token"


def test_default_lookup_order_without_restriction_prompts(
    monkeypatch, entered_password
):
    monkeypatch.setattr(auth, "keyring", RecordingKeyring())
    monkeypatch.setattr(
        auth.utils,
        "make_requests_session",
        _minting_session(),
    )

    def no_ambient_credential(*args, **kwargs) -> None:
        return None

    monkeypatch.setattr(auth, "detect_credential", no_ambient_credential)

    resolver = auth.Resolver(_pypi_config(), auth.CredentialInput("__token__"))
    assert resolver.password == "entered pw"


def test_unrestricted_failure_keeps_trusted_publishing_failure(monkeypatch):
    monkeypatch.setattr(
        auth.utils,
        "make_requests_session",
        _minting_session(
            get_responses=[MockResponse(status_code=503, json={})],
        ),
    )
    monkeypatch.setattr(auth, "detect_credential", lambda *a, **k: "fake-oidc-token")

    resolver = auth.Resolver(_pypi_config(), auth.CredentialInput("__token__"))
    with pytest.raises(requests.exceptions.HTTPError):
        resolver.password
