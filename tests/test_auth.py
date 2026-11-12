import base64
import getpass
import logging
import re
import typing as t

import pytest
import requests.auth

from twine import auth
from twine import exceptions
from twine import utils


@pytest.fixture
def config() -> utils.RepositoryConfig:
    return dict(repository="system")


@pytest.fixture
def entered_username(monkeypatch):
    monkeypatch.setattr(auth, "input", lambda prompt: "entered user", raising=False)


@pytest.fixture
def entered_password(monkeypatch):
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "entered pw")


class RecordingKeyring:
    """Recording double for the subset of the keyring API twine uses.

    Nothing here touches the host's real keyring service; every call is
    recorded so tests can assert how often credential sources are consulted.
    """

    def __init__(
        self,
        credential: t.Optional[auth.CredentialInput] = None,
        password: t.Optional[str] = None,
        get_credential_error: t.Optional[t.Callable[[], Exception]] = None,
        get_password_error: t.Optional[t.Callable[[], Exception]] = None,
    ) -> None:
        self._credential = credential
        self._password = password
        self._get_credential_error = get_credential_error
        self._get_password_error = get_password_error
        self.get_credential_calls: list[tuple[t.Any, t.Any]] = []
        self.get_password_calls: list[tuple[t.Any, t.Any]] = []

    def get_credential(
        self, system: str, username: t.Optional[str]
    ) -> t.Optional[auth.CredentialInput]:
        self.get_credential_calls.append((system, username))
        if self._get_credential_error is not None:
            raise self._get_credential_error()
        return self._credential

    def get_password(
        self, system: str, username: str
    ) -> t.Optional[str]:
        self.get_password_calls.append((system, username))
        if self._get_password_error is not None:
            raise self._get_password_error()
        return self._password


class LegacyKeyring:
    """Double for keyring prior to 15.2, which lacks ``get_credential``."""

    def __init__(self) -> None:
        self.get_password_calls: list[tuple[t.Any, t.Any]] = []

    def get_password(
        self, system: str, username: str
    ) -> t.Optional[str]:
        self.get_password_calls.append((system, username))
        return None


class MockResponse:
    def __init__(
        self,
        status_code: int,
        json: t.Any,
        error_payload: t.Optional[t.Any] = None,
    ) -> None:
        self.status_code = status_code
        self._json = json
        self._error_payload = error_payload

    def json(self, *args, **kwargs) -> t.Any:
        if self._error_payload is not None and not self.ok:
            return self._error_payload
        return self._json

    def raise_for_status(self) -> None:
        if 400 <= self.status_code:
            raise requests.exceptions.HTTPError()

    @property
    def ok(self) -> bool:
        return self.status_code < 400


class RecordingSession:
    """Requests session double that records every upstream interaction."""

    def __init__(
        self,
        get_response: MockResponse,
        post_responses: t.Optional[t.List[MockResponse]] = None,
    ) -> None:
        self.get_calls: list[tuple[t.Any, t.Any]] = []
        self.post_calls: list[t.Dict[str, t.Any]] = []
        self._get_response = get_response
        self._post_responses = post_responses or []

    def get(self, url: str, **kwargs) -> MockResponse:
        self.get_calls.append((url, kwargs))
        return self._get_response

    def post(self, url: str, **kwargs) -> MockResponse:
        self.post_calls.append({"url": url, **kwargs})
        if not self._post_responses:
            raise AssertionError("unexpected token mint request")
        return self._post_responses.pop(0)


class RecordingOidcProvider:
    """OIDC ambient-credential double that records the audiences requested."""

    def __init__(
        self, tokens: t.Optional[t.List[t.Optional[str]]] = None
    ) -> None:
        self._tokens = list(tokens or [])
        self.calls: list[str] = []

    def __call__(self, audience: str) -> t.Optional[str]:
        self.calls.append(audience)
        if not self._tokens:
            raise AssertionError("unexpected OIDC credential request")
        return self._tokens.pop(0)


class MutableClock:
    """Deterministic clock so renewal decisions never depend on wall time."""

    def __init__(self, now: int) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


def _basic_auth_header(token: str) -> str:
    return f"Basic {base64.b64encode(f'__token__:{token}'.encode()).decode()}"


def _trusted_publishing_resolver(
    config: utils.RepositoryConfig,
    session: RecordingSession,
    oidc_provider: RecordingOidcProvider,
    clock: MutableClock,
    monkeypatch: pytest.MonkeyPatch,
) -> auth.Resolver:
    config.update({"repository": utils.TEST_REPOSITORY})
    monkeypatch.setattr(auth.utils, "make_requests_session", lambda: session)
    resolver = auth.Resolver(
        config,
        auth.CredentialInput(username="__token__"),
        oidc_token_provider=oidc_provider,
        clock=clock,
    )
    return resolver


def _seed_token(resolver: auth.Resolver, token: str, issued_at: int) -> None:
    resolver._tp_token = auth.TrustedPublishingToken(
        success=True,
        token=token,
        expires=issued_at + 900,
    )
    resolver._expires = issued_at + 900


def test_get_username_keyring_defers_to_prompt(
    entered_username, config
):
    keyring = RecordingKeyring()

    username = auth.Resolver(
        config, auth.CredentialInput(), keyring_backend=keyring
    ).username
    assert username == "entered user"
    assert keyring.get_credential_calls == [("system", None)]


def test_get_username_without_keyring_defers_to_prompt(
    entered_username, config
):
    username = auth.Resolver(
        config, auth.CredentialInput(), keyring_backend=None
    ).username
    assert username == "entered user"


def test_get_password_keyring_defers_to_prompt(
    entered_password, config
):
    keyring = RecordingKeyring()

    pw = auth.Resolver(
        config, auth.CredentialInput("user"), keyring_backend=keyring
    ).password
    assert pw == "entered pw"
    assert keyring.get_password_calls == [("system", "user")]


def test_get_password_without_keyring_defers_to_prompt(
    entered_password, config
):
    pw = auth.Resolver(
        config, auth.CredentialInput("user"), keyring_backend=None
    ).password
    assert pw == "entered pw"


def test_no_password_defers_to_prompt(entered_password, config):
    config.update(password=None)
    pw = auth.Resolver(
        config, auth.CredentialInput("user"), keyring_backend=RecordingKeyring()
    ).password
    assert pw == "entered pw"


def test_empty_password_bypasses_prompt(entered_password, config):
    config.update(password="")
    pw = auth.Resolver(
        config, auth.CredentialInput("user"), keyring_backend=RecordingKeyring()
    ).password
    assert pw == ""


def test_no_username_non_interactive_aborts(config):
    with pytest.raises(exceptions.NonInteractive):
        auth.Private(
            config, auth.CredentialInput(), keyring_backend=RecordingKeyring()
        ).username


def test_no_password_non_interactive_aborts(config):
    with pytest.raises(exceptions.NonInteractive):
        auth.Private(
            config,
            auth.CredentialInput("user"),
            keyring_backend=RecordingKeyring(),
        ).password


def test_get_username_and_password_keyring_overrides_prompt(config, caplog):
    caplog.set_level(logging.INFO, "twine")

    keyring = RecordingKeyring(
        credential=auth.CredentialInput(
            "real_user", "real_user@system sekure pa55word"
        ),
        password="real_user@system sekure pa55word",
    )

    res = auth.Resolver(
        config, auth.CredentialInput(), keyring_backend=keyring
    )

    assert res.username == "real_user"
    assert res.password == "real_user@system sekure pa55word"

    assert keyring.get_credential_calls == [("system", None)]
    assert keyring.get_password_calls == [("system", "real_user")]

    assert caplog.messages == [
        "Querying keyring for username",
        "username set from keyring",
        "Querying keyring for password",
        "password set from keyring",
    ]


def test_keyring_credentials_are_resolved_only_once(config):
    """Repeated access must not re-query the keyring for plain credentials."""
    keyring = RecordingKeyring(
        credential=auth.CredentialInput("real_user", "real_password"),
        password="real_password",
    )
    res = auth.Resolver(
        config, auth.CredentialInput(), keyring_backend=keyring
    )

    assert res.username == "real_user"
    assert res.password == "real_password"
    assert res.username == "real_user"
    assert res.password == "real_password"

    assert len(keyring.get_credential_calls) == 1
    assert len(keyring.get_password_calls) == 1

    assert isinstance(res.authenticator, requests.auth.HTTPBasicAuth)
    assert res.authenticator.username == "real_user"
    assert res.authenticator.password == "real_password"


def test_get_username_keyring_missing_get_credentials_prompts(
    entered_username, config
):
    keyring = LegacyKeyring()

    assert (
        auth.Resolver(
            config, auth.CredentialInput(), keyring_backend=keyring
        ).username
        == "entered user"
    )


def test_get_username_keyring_missing_non_interactive_aborts(
    entered_username, config
):
    with pytest.raises(exceptions.NonInteractive):
        auth.Private(
            config,
            auth.CredentialInput(),
            keyring_backend=LegacyKeyring(),
        ).username


def test_get_password_keyring_missing_non_interactive_aborts(
    entered_username, config
):
    with pytest.raises(exceptions.NonInteractive):
        auth.Private(
            config,
            auth.CredentialInput(),
            keyring_backend=LegacyKeyring(),
        ).password


def test_get_username_keyring_runtime_error_logged(
    entered_username, config, caplog
):
    keyring = RecordingKeyring(
        get_credential_error=lambda: RuntimeError("fail!")
    )

    assert (
        auth.Resolver(
            config, auth.CredentialInput(), keyring_backend=keyring
        ).username
        == "entered user"
    )

    assert re.search(
        r"Error getting username from keyring.+Traceback.+RuntimeError: fail!",
        caplog.text,
        re.DOTALL,
    )


def test_get_password_keyring_runtime_error_logged(
    entered_username, entered_password, config, caplog
):
    keyring = RecordingKeyring(
        get_password_error=lambda: RuntimeError("fail!")
    )

    assert (
        auth.Resolver(
            config, auth.CredentialInput(), keyring_backend=keyring
        ).password
        == "entered pw"
    )

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
    entered_username, config, caplog
):
    keyring = RecordingKeyring(get_credential_error=_raise_home_key_error)

    assert (
        auth.Resolver(
            config, auth.CredentialInput(), keyring_backend=keyring
        ).username
        == "entered user"
    )

    assert re.search(
        r"Error getting username from keyring"
        r".+Traceback"
        r".+KeyError: 'HOME'"
        r".+KeyError: 'uid not found: 999'",
        caplog.text,
        re.DOTALL,
    )


def test_get_password_keyring_key_error_logged(
    entered_username, entered_password, config, caplog
):
    keyring = RecordingKeyring(get_password_error=_raise_home_key_error)

    assert (
        auth.Resolver(
            config, auth.CredentialInput(), keyring_backend=keyring
        ).password
        == "entered pw"
    )

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

    res = auth.Resolver(
        config,
        auth.CredentialInput("username", "password"),
        keyring_backend=RecordingKeyring(),
    )

    assert res.username == "username"
    assert res.password == "password"

    assert caplog.messages == [
        "username set by command options",
        "password set by command options",
    ]


def test_logs_config_values(config, caplog):
    caplog.set_level(logging.INFO, "twine")

    config.update(username="username", password="password")
    res = auth.Resolver(
        config, auth.CredentialInput(), keyring_backend=RecordingKeyring()
    )

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
    monkeypatch.setattr(getpass, "getpass", lambda prompt: password)

    assert (
        auth.Resolver(
            config,
            auth.CredentialInput(),
            keyring_backend=RecordingKeyring(),
        ).password
        == password
    )

    assert caplog.messages[0].startswith(warning)


def test_resolver_authenticator_config_authentication(config):
    config.update(username="username", password="password")
    res = auth.Resolver(
        config, auth.CredentialInput(), keyring_backend=RecordingKeyring()
    )
    assert isinstance(res.authenticator, requests.auth.HTTPBasicAuth)


def test_resolver_authenticator_credential_input_authentication(config):
    res = auth.Resolver(
        config,
        auth.CredentialInput("username", "password"),
        keyring_backend=RecordingKeyring(),
    )
    assert isinstance(res.authenticator, requests.auth.HTTPBasicAuth)


def test_resolver_authenticator_trusted_publishing_authentication(config):
    res = auth.Resolver(
        config,
        auth.CredentialInput(username="__token__", password="skip-stdin"),
        keyring_backend=RecordingKeyring(),
    )
    res._tp_token = auth.TrustedPublishingToken(
        success=True,
        token="fake-tp-token",
    )
    assert isinstance(res.authenticator, auth.TrustedPublishingAuthenticator)


def test_resolver_without_any_credentials_raises(config):
    class CredentiallessResolver(auth.Resolver):
        @property
        def username(self) -> t.Optional[str]:
            return None

        @property
        def password(self) -> t.Optional[str]:
            return None

    with pytest.raises(exceptions.InvalidConfiguration):
        CredentiallessResolver(
            config,
            auth.CredentialInput(),
            keyring_backend=RecordingKeyring(),
        ).authenticator


def test_private_resolver_without_credentials_raises_non_interactive(config):
    with pytest.raises(exceptions.NonInteractive):
        auth.Private(
            config,
            auth.CredentialInput(),
            keyring_backend=RecordingKeyring(),
        ).authenticator


def test_trusted_publish_authenticator_reuses_token_without_renewal(
    monkeypatch, config
):
    """A token still inside the renewal window must not touch the upstream."""
    now = 1_000_000
    clock = MutableClock(now)
    session = RecordingSession(
        get_response=MockResponse(200, {"audience": "fake-aud"}),
    )
    oidc = RecordingOidcProvider()
    resolver = _trusted_publishing_resolver(
        config, session, oidc, clock, monkeypatch
    )
    _seed_token(resolver, "valid-tp-token", issued_at=now)

    authenticator = auth.TrustedPublishingAuthenticator(resolver=resolver)
    prepped_req = requests.models.PreparedRequest()
    prepped_req.prepare_headers({})

    request = authenticator(prepped_req)

    assert request.headers["Authorization"] == _basic_auth_header(
        "valid-tp-token"
    )
    # Nothing was called: the cached token is still fresh.
    assert session.get_calls == []
    assert session.post_calls == []
    assert oidc.calls == []


def test_trusted_publish_authenticator_renews_expiring_token(
    monkeypatch, config
):
    """Once the current time enters the renewal window, fetch a new token."""
    now = 1_000_000
    clock = MutableClock(now)
    session = RecordingSession(
        get_response=MockResponse(200, {"audience": "fake-aud"}),
        post_responses=[
            MockResponse(
                200,
                {
                    "success": True,
                    "token": "new-token",
                    "expires": now + 900,
                },
            )
        ],
    )
    oidc = RecordingOidcProvider(tokens=["fake-oidc-token"])
    resolver = _trusted_publishing_resolver(
        config, session, oidc, clock, monkeypatch
    )
    # Token issued 11 minutes ago: past the 10 minute renewal threshold.
    _seed_token(resolver, "expiring-tp-token", issued_at=now - 11 * 60)

    authenticator = auth.TrustedPublishingAuthenticator(resolver=resolver)
    prepped_req = requests.models.PreparedRequest()
    prepped_req.prepare_headers({})

    request = authenticator(prepped_req)

    assert request.headers["Authorization"] == _basic_auth_header("new-token")
    assert len(oidc.calls) == 1
    assert len(session.get_calls) == 1
    assert len(session.post_calls) == 1
    assert session.post_calls[0]["json"] == {"token": "fake-oidc-token"}

    # A second request with time unchanged reuses the freshly minted token.
    second_prepped = requests.models.PreparedRequest()
    second_prepped.prepare_headers({})
    second_request = authenticator(second_prepped)
    assert second_request.headers["Authorization"] == _basic_auth_header(
        "new-token"
    )
    assert len(session.post_calls) == 1
    assert len(oidc.calls) == 1


def test_trusted_publish_renewal_failure_does_not_reuse_old_token(
    monkeypatch, config
):
    """A failed renewal must surface an error and never send the old token."""
    now = 1_000_000
    clock = MutableClock(now)
    session = RecordingSession(
        get_response=MockResponse(200, {"audience": "fake-aud"}),
        post_responses=[
            MockResponse(
                403,
                {},
                error_payload={
                    "errors": [
                        {
                            "code": "invalid-token",
                            "description": "the OIDC token was rejected",
                        }
                    ]
                },
            )
        ],
    )
    oidc = RecordingOidcProvider(tokens=["fake-oidc-token"])
    resolver = _trusted_publishing_resolver(
        config, session, oidc, clock, monkeypatch
    )
    _seed_token(resolver, "stale-tp-token", issued_at=now - 11 * 60)

    authenticator = auth.TrustedPublishingAuthenticator(resolver=resolver)
    prepped_req = requests.models.PreparedRequest()
    prepped_req.prepare_headers({})

    with pytest.raises(exceptions.TrustedPublishingFailure):
        authenticator(prepped_req)

    # The renewal really was attempted ...
    assert len(oidc.calls) == 1
    assert len(session.post_calls) == 1
    # ... and nothing attached the previous token to the outgoing request.
    assert "Authorization" not in prepped_req.headers
    assert "stale-tp-token" not in prepped_req.headers.get("Authorization", "")


def test_inability_to_make_token_raises_error():
    class MockResolver:
        def make_trusted_publishing_token(self) -> None:
            return None

    authenticator = auth.TrustedPublishingAuthenticator(
        resolver=MockResolver(),  # type: ignore[arg-type]
    )
    with pytest.raises(exceptions.TrustedPublishingFailure):
        authenticator(None)
