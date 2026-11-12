"""Logging contract tests for twine's error handling.

These tests pin down the conventions that the error-handling refactor must
preserve:

* every failure is locatable: the configured repository alias, the pipeline
  stage and the failure category are visible in the exception message, the
  logs and the rendered console output;
* secrets are never exposed: publishing credentials, OIDC/token-minting
  tokens and the request ``Authorization`` header must not appear in logs,
  standard output/error or exception messages.

All network endpoints are faked (``--disable-socket`` is enabled globally)
and every credential below is entirely fictional.
"""
import base64
import logging
import re
import sys
import typing as t

import pretend
import pytest
import requests

from twine import __main__ as dunder_main
from twine import auth
from twine import exceptions
from twine import repository as repository_module
from twine import settings
from twine import utils
from twine.commands import upload

from . import helpers

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")

# Distinct, fictional secrets. They are deliberately distinctive so that any
# accidental leak is detected by a plain substring search.
TP_REPO_ALIAS = "contract-trusted-publishing"
TP_OIDC_TOKEN = "fake-oidc-secret-contract-token"
TP_MINT_ERROR_CODE = "invalid-permission"
TP_MINT_ERROR_DESCRIPTION = "The submitted token is not accepted"

UP_REPO_ALIAS = "contract-third-party-index"
UP_USERNAME = "contract-publisher"
UP_PASSWORD = "fake-publish-secret-contract-password"
UP_REJECTION_REASON = "Invalid or non-existent authentication information"

CONN_REPO_ALIAS = "contract-flaky-index"
CONN_USERNAME = "contract-flaky-publisher"
CONN_PASSWORD = "fake-flaky-secret-contract-password"
CONN_ERROR_DETAIL = "Connection reset by fake peer"


def _strip_ansi(text: str) -> str:
    return ANSI_ESCAPE.sub("", text)


def _assert_no_secret_leak(secret: str, *, caplog, captured) -> None:
    """The same secret must be absent from every user-visible surface."""
    rendered_out = _strip_ansi(captured.out)
    rendered_err = _strip_ansi(captured.err)
    assert secret not in caplog.text
    assert secret not in rendered_out
    assert secret not in rendered_err


def _assert_locatable(
    *, alias: str, stage: str, category: str, caplog, captured
) -> None:
    rendered_out = _strip_ansi(captured.out)
    # The failure category (exception class name) identifies *what* failed.
    assert category in rendered_out
    # The repository alias and pipeline stage identify *where* it failed, in
    # the rendered console output.
    assert alias in rendered_out
    assert stage in rendered_out
    # caplog is re-initialised by the CLI's logging configuration, so it only
    # reliably contains records emitted before dispatch; assert the locator on
    # whichever surface actually captured it.
    assert alias in (rendered_out + caplog.text)
    assert stage in (rendered_out + caplog.text)


class FakeResponse:
    """Minimal stand-in for ``requests.Response`` used by the auth flow."""

    def __init__(self, status_code: int, payload: t.Any) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self, *args: t.Any, **kwargs: t.Any) -> t.Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    @property
    def ok(self) -> bool:
        return self.status_code < 400


class FakeAuthSession:
    """Records requests instead of performing them (identity exchange)."""

    def __init__(self, get_responses: list, post_responses: list) -> None:
        self._get_responses = get_responses
        self._post_responses = post_responses
        self.get_calls: list[tuple] = []
        self.post_calls: list[tuple] = []

    def get(self, url: str, **kwargs: t.Any) -> FakeResponse:
        self.get_calls.append((url, kwargs))
        return self._get_responses.pop(0)

    def post(self, url: str, **kwargs: t.Any) -> FakeResponse:
        self.post_calls.append((url, kwargs))
        return self._post_responses.pop(0)


class RecordingUploadSession:
    """Fake upload session that captures the Authorization header."""

    def __init__(self, response: requests.Response, failure: Exception | None = None):
        self.auth = None
        self.recorded_authorization: str | None = None
        self._response = response
        self._failure = failure

    def post(self, url: str, **kwargs: t.Any) -> requests.Response:
        # Mirror what requests does with a (username, password) session auth.
        if self.auth:
            prepared = requests.models.PreparedRequest()
            prepared.prepare_headers({})
            requests.auth.HTTPBasicAuth(*self.auth)(prepared)
            self.recorded_authorization = prepared.headers["Authorization"]
        if self._failure is not None:
            raise self._failure
        return self._response

    def close(self) -> None:
        pass


def _rejection_response() -> requests.Response:
    response = requests.Response()
    response.status_code = 403
    response.reason = UP_REJECTION_REASON
    response._content = UP_REJECTION_REASON.encode()
    response.url = "https://upload.example.org/legacy/"
    return response


def _make_upload_settings(write_config_file, alias: str, username: str, password: str):
    config_file = write_config_file(
        f"""
        [distutils]
        index-servers =
            {alias}

        [{alias}]
        repository: https://upload.example.org/legacy/
        username:{username}
        password:{password}
        """
    )
    upload_settings = settings.Settings(
        config_file=config_file,
        repository_name=alias,
        disable_progress_bar=True,
    )
    return upload_settings, config_file


def test_identity_exchange_failure_is_locatable_and_keeps_token_secret(
    monkeypatch, write_config_file, caplog, capsys
):
    """Trusted-publishing token exchange rejection (server-side failure)."""
    caplog.set_level(logging.DEBUG, "twine")
    monkeypatch.setattr(auth, "keyring", None)

    fake_session = FakeAuthSession(
        get_responses=[FakeResponse(200, {"audience": "fake-audience"})],
        post_responses=[
            FakeResponse(
                403,
                {
                    "errors": [
                        {
                            "code": TP_MINT_ERROR_CODE,
                            "description": TP_MINT_ERROR_DESCRIPTION,
                        }
                    ]
                },
            )
        ],
    )
    monkeypatch.setattr(auth.utils, "make_requests_session", lambda: fake_session)
    monkeypatch.setattr(
        auth, "detect_credential", lambda audience: TP_OIDC_TOKEN
    )

    config_file = write_config_file(
        f"""
        [distutils]
        index-servers =
            {TP_REPO_ALIAS}

        [{TP_REPO_ALIAS}]
        repository: {utils.TEST_REPOSITORY}
        username:__token__
        """
    )
    upload_settings = settings.Settings(
        config_file=config_file,
        repository_name=TP_REPO_ALIAS,
        non_interactive=True,
    )

    category = exceptions.TrustedPublishingFailure.__name__

    # Direct call: assert the exception contract.
    with pytest.raises(exceptions.TrustedPublishingFailure) as exc_info:
        upload_settings.password

    message = str(exc_info.value)
    assert TP_REPO_ALIAS in message
    assert auth.TRUSTED_PUBLISHING_STAGE in message
    assert TP_MINT_ERROR_CODE in message
    assert TP_OIDC_TOKEN not in message

    # The OIDC token was genuinely sent to the (fake) endpoint ...
    mint_url, mint_kwargs = fake_session.post_calls[0]
    assert mint_url.endswith("/_/oidc/mint-token")
    assert mint_kwargs["json"] == {"token": TP_OIDC_TOKEN}
    # ... but it must never be logged.
    assert TP_OIDC_TOKEN not in caplog.text

    # CLI entry point: run the real ``twine upload`` pipeline and raise an
    # annotated failure at repository creation, so no real network is used and
    # the exhausted fake session is not consulted again. Trusted-publishing
    # failures are raised by the Resolver, which attaches the locator fragment
    # before the exception reaches the CLI renderer.
    monkeypatch.setattr(
        settings.Settings,
        "create_repository",
        pretend.raiser(exceptions.TrustedPublishingFailure(message)),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "twine",
            "upload",
            "--config-file",
            str(config_file),
            "--repository",
            TP_REPO_ALIAS,
            "--non-interactive",
            helpers.WHEEL_FIXTURE,
        ],
    )
    assert dunder_main.main()

    captured = capsys.readouterr()
    _assert_locatable(
        alias=TP_REPO_ALIAS,
        stage=auth.TRUSTED_PUBLISHING_STAGE,
        category=category,
        caplog=caplog,
        captured=captured,
    )
    _assert_no_secret_leak(TP_OIDC_TOKEN, caplog=caplog, captured=captured)


def test_server_rejection_is_locatable_and_keeps_credentials_secret(
    monkeypatch, write_config_file, caplog, capsys
):
    """The index rejects the upload with an HTTP error status."""
    caplog.set_level(logging.DEBUG, "twine")
    monkeypatch.setattr(auth, "keyring", None)

    upload_settings, config_file = _make_upload_settings(
        write_config_file, UP_REPO_ALIAS, UP_USERNAME, UP_PASSWORD
    )
    # Verbose mode records the response body; it must still never contain the
    # credentials or the Authorization header.
    upload_settings.verbose = True

    fake_session = RecordingUploadSession(_rejection_response())
    repo = repository_module.Repository(
        "https://upload.example.org/legacy/",
        upload_settings.username,
        upload_settings.password,
        disable_progress_bar=True,
    )
    repo.session = fake_session
    fake_session.auth = (upload_settings.username, upload_settings.password)
    upload_settings.create_repository = lambda: repo

    package = helpers.WHEEL_FIXTURE
    expected_authorization = (
        "Basic "
        + base64.b64encode(f"{UP_USERNAME}:{UP_PASSWORD}".encode()).decode()
    )

    # Direct call: HTTPError keeps the response and gains the locator fragment.
    with pytest.raises(requests.HTTPError) as exc_info:
        upload.upload(upload_settings, [package])

    assert exc_info.value.response is not None
    assert exc_info.value.response.status_code == 403
    message = str(exc_info.value)
    assert UP_REPO_ALIAS in message
    assert upload.UPLOAD_STAGE in message
    assert UP_REJECTION_REASON in message

    # Credentials really were used on the wire ...
    assert fake_session.recorded_authorization == expected_authorization
    # ... but the header and password must not appear on any log/output surface.
    captured = capsys.readouterr()
    for secret in (UP_PASSWORD, expected_authorization):
        _assert_no_secret_leak(secret, caplog=caplog, captured=captured)
    assert UP_REJECTION_REASON in caplog.text

    # CLI entry point: rendered output carries category, alias and stage.
    # Run the real pipeline and only swap the HTTP session for a fake one, so
    # the upload command itself performs the response handling and wrapping.
    monkeypatch.setattr(
        repository_module,
        "make_requests_session",
        lambda: fake_session,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "twine",
            "upload",
            "--config-file",
            str(config_file),
            "--repository",
            UP_REPO_ALIAS,
            package,
        ],
    )
    assert dunder_main.main()

    captured = capsys.readouterr()
    _assert_locatable(
        alias=UP_REPO_ALIAS,
        stage=upload.UPLOAD_STAGE,
        category="HTTPError",
        caplog=caplog,
        captured=captured,
    )
    for secret in (UP_PASSWORD, expected_authorization):
        _assert_no_secret_leak(secret, caplog=caplog, captured=captured)


def test_connection_interruption_is_locatable_and_keeps_credentials_secret(
    monkeypatch, write_config_file, caplog, capsys
):
    """The connection breaks before the index can respond."""
    caplog.set_level(logging.DEBUG, "twine")
    monkeypatch.setattr(auth, "keyring", None)

    upload_settings, config_file = _make_upload_settings(
        write_config_file, CONN_REPO_ALIAS, CONN_USERNAME, CONN_PASSWORD
    )

    transport_failure = requests.ConnectionError(CONN_ERROR_DETAIL)
    fake_session = RecordingUploadSession(
        response=requests.Response(), failure=transport_failure
    )
    repo = repository_module.Repository(
        "https://upload.example.org/legacy/",
        upload_settings.username,
        upload_settings.password,
        disable_progress_bar=True,
    )
    repo.session = fake_session
    fake_session.auth = (upload_settings.username, upload_settings.password)
    upload_settings.create_repository = lambda: repo

    package = helpers.WHEEL_FIXTURE
    expected_authorization = (
        "Basic "
        + base64.b64encode(
            f"{CONN_USERNAME}:{CONN_PASSWORD}".encode()
        ).decode()
    )

    # Direct call: a transport error is wrapped, not a raw traceback.
    with pytest.raises(requests.ConnectionError) as exc_info:
        upload.upload(upload_settings, [package])

    message = str(exc_info.value)
    assert CONN_REPO_ALIAS in message
    assert upload.UPLOAD_STAGE in message
    assert CONN_ERROR_DETAIL in message
    assert CONN_PASSWORD not in message
    assert expected_authorization not in message

    assert fake_session.recorded_authorization == expected_authorization
    captured = capsys.readouterr()
    for secret in (CONN_PASSWORD, expected_authorization):
        _assert_no_secret_leak(secret, caplog=caplog, captured=captured)

    # CLI entry point: handled gracefully, with locator and failure category.
    # Run the real pipeline and only swap the HTTP session for the failing
    # fake one, so the upload command performs the connection-error wrapping.
    monkeypatch.setattr(
        repository_module,
        "make_requests_session",
        lambda: fake_session,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "twine",
            "upload",
            "--config-file",
            str(config_file),
            "--repository",
            CONN_REPO_ALIAS,
            package,
        ],
    )
    assert dunder_main.main()

    captured = capsys.readouterr()
    _assert_locatable(
        alias=CONN_REPO_ALIAS,
        stage=upload.UPLOAD_STAGE,
        category="ConnectionError",
        caplog=caplog,
        captured=captured,
    )
    for secret in (CONN_PASSWORD, expected_authorization):
        _assert_no_secret_leak(secret, caplog=caplog, captured=captured)


def test_authorization_header_is_never_logged_on_a_successful_post(
    monkeypatch, write_config_file, caplog, capsys
):
    """Baseline guard: a normal upload logs response data but not the header."""
    caplog.set_level(logging.DEBUG, "twine")
    monkeypatch.setattr(auth, "keyring", None)

    upload_settings, _config_file = _make_upload_settings(
        write_config_file, UP_REPO_ALIAS, UP_USERNAME, UP_PASSWORD
    )

    response = requests.Response()
    response.status_code = 200
    response.reason = "OK"
    response._content = b""
    response.url = "https://upload.example.org/legacy/"
    fake_session = RecordingUploadSession(response)

    repo = repository_module.Repository(
        "https://upload.example.org/legacy/",
        upload_settings.username,
        upload_settings.password,
        disable_progress_bar=True,
    )
    repo.session = fake_session
    fake_session.auth = (upload_settings.username, upload_settings.password)
    upload_settings.create_repository = lambda: repo

    expected_authorization = (
        "Basic "
        + base64.b64encode(f"{UP_USERNAME}:{UP_PASSWORD}".encode()).decode()
    )

    assert upload.upload(upload_settings, [helpers.WHEEL_FIXTURE]) is None
    assert fake_session.recorded_authorization == expected_authorization

    captured = capsys.readouterr()
    _assert_no_secret_leak(
        expected_authorization, caplog=caplog, captured=captured
    )
    _assert_no_secret_leak(UP_PASSWORD, caplog=caplog, captured=captured)
