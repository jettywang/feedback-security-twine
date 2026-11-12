"""Tests for the Settings class and module."""

# Copyright 2018 Ian Stapleton Cordasco
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
import logging

import pytest

from twine import exceptions
from twine import repository
from twine import settings


def test_settings_takes_no_positional_arguments():
    """Raise an exception when Settings is initialized without keyword arguments."""
    with pytest.raises(TypeError):
        settings.Settings("a", "b", "c")


def test_settings_transforms_repository_config_pypi(write_config_file):
    """Set repository config and defaults when .pypirc is provided.

    Ignores the username setting due to PyPI being the index.
    """
    config_file = write_config_file("""
        [pypi]
        repository: https://upload.pypi.org/legacy/
        username:this-is-ignored
        password:password
        """)

    s = settings.Settings(config_file=config_file)
    assert s.repository_config["repository"] == "https://upload.pypi.org/legacy/"
    assert s.sign is False
    assert s.sign_with == "gpg"
    assert s.identity is None
    assert s.username == "__token__"
    assert s.password == "password"
    assert s.cacert is None
    assert s.client_cert is None
    assert s.disable_progress_bar is False


def test_settings_transforms_repository_config_non_pypi(write_config_file):
    """Set repository config and defaults when .pypirc is provided."""
    config_file = write_config_file("""
        [distutils]
        index-servers =
            notpypi

        [notpypi]
        repository: https://upload.example.org/legacy/
        username:someusername
        password:password
        """)

    s = settings.Settings(config_file=config_file, repository_name="notpypi")
    assert s.repository_config["repository"] == "https://upload.example.org/legacy/"
    assert s.sign is False
    assert s.sign_with == "gpg"
    assert s.identity is None
    assert s.username == "someusername"
    assert s.password == "password"
    assert s.client_cert is None
    assert s.disable_progress_bar is False


def test_settings_verify_feature_compatibility() -> None:
    s = settings.Settings(skip_existing=True)
    s.repository_config = {"repository": repository.WAREHOUSE}
    try:
        s.verify_feature_capability()
    except exceptions.UnsupportedConfiguration as unexpected_exc:
        pytest.fail(
            "Expected feature capability to work with production PyPI"
            f" but got {unexpected_exc!r}"
        )

    s.repository_config["repository"] = repository.TEST_WAREHOUSE
    try:
        s.verify_feature_capability()
    except exceptions.UnsupportedConfiguration as unexpected_exc:
        pytest.fail(
            "Expected feature capability to work with TestPyPI but got"
            f" {unexpected_exc!r}"
        )

    s.repository_config["repository"] = "https://not-really-pypi.example.com/legacy"
    with pytest.raises(exceptions.UnsupportedConfiguration):
        s.verify_feature_capability()

    s.skip_existing = False
    try:
        s.verify_feature_capability()
    except exceptions.UnsupportedConfiguration as unexpected_exc:
        pytest.fail(
            "Expected an exception only when --skip-existing is provided"
            f" but got {unexpected_exc!r}"
        )


@pytest.mark.parametrize(
    "verbose, log_level", [(True, logging.INFO), (False, logging.WARNING)]
)
def test_setup_logging(verbose, log_level):
    """Set log level based on verbose field."""
    settings.Settings(verbose=verbose)

    logger = logging.getLogger("twine")

    assert logger.level == log_level


@pytest.mark.parametrize(
    "verbose",
    [True, False],
)
def test_print_config_path_if_verbose(config_file, caplog, make_settings, verbose):
    """Print the location of the .pypirc config used by the user."""
    make_settings(verbose=verbose)

    if verbose:
        assert caplog.messages == [f"Using configuration from {config_file}"]
    else:
        assert caplog.messages == []


def test_identity_requires_sign():
    """Raise an exception when user provides identity but doesn't require signing."""
    with pytest.raises(exceptions.InvalidSigningConfiguration):
        settings.Settings(sign=False, identity="fakeid")


@pytest.mark.parametrize("client_cert", [None, ""])
def test_password_is_required_if_no_client_cert(client_cert, entered_password):
    """Set password when client_cert is not provided."""
    settings_obj = settings.Settings(username="fakeuser", client_cert=client_cert)
    assert settings_obj.password == "entered pw"


def test_client_cert_and_password_both_set_if_given():
    """Set password and client_cert when both are provided."""
    client_cert = "/random/path"
    settings_obj = settings.Settings(
        username="fakeuser", password="anything", client_cert=client_cert
    )
    assert settings_obj.password == "anything"
    assert settings_obj.client_cert == client_cert


def test_password_required_if_no_client_cert_and_non_interactive():
    """Raise exception if no password or client_cert when non interactive."""
    settings_obj = settings.Settings(username="fakeuser", non_interactive=True)
    with pytest.raises(exceptions.NonInteractive):
        settings_obj.password


def test_no_password_prompt_if_client_cert_and_non_interactive(entered_password):
    """Don't prompt for password when client_cert is provided and non interactive."""
    client_cert = "/random/path"
    settings_obj = settings.Settings(
        username="fakeuser", client_cert=client_cert, non_interactive=True
    )
    assert not settings_obj.password


@pytest.mark.parametrize(
    "settings_kwargs, match",
    [
        ({"cacert": "/no/such/ca.pem"}, "CA bundle"),
        ({"client_cert": "/no/such/client.pem"}, "client certificate"),
    ],
)
def test_validate_certificate_paths_raises_for_missing_file(
    settings_kwargs, match
):
    """Raise before any request when a configured certificate path is missing."""
    settings_obj = settings.Settings(
        non_interactive=True, username="fakeuser", **settings_kwargs
    )
    with pytest.raises(exceptions.InvalidConfiguration, match=match):
        settings_obj.validate_certificate_paths()


def test_validate_certificate_paths_accepts_existing_files(tmp_path):
    """Accept certificate paths that point to real files."""
    cacert = tmp_path / "ca.pem"
    client_cert = tmp_path / "client.pem"
    cacert.write_text("ca")
    client_cert.write_text("client")

    settings_obj = settings.Settings(
        non_interactive=True,
        username="fakeuser",
        cacert=str(cacert),
        client_cert=str(client_cert),
    )
    # Should not raise.
    settings_obj.validate_certificate_paths()


def test_validate_certificate_paths_skips_unset_paths():
    """Default (no certificate configured) passes validation."""
    settings_obj = settings.Settings(non_interactive=True, username="fakeuser")
    settings_obj.validate_certificate_paths()


def test_create_repository_rejects_missing_certificate_before_request(monkeypatch):
    """Fail in create_repository without constructing a request session."""
    settings_obj = settings.Settings(
        non_interactive=True,
        username="fakeuser",
        cacert="/no/such/ca.pem",
    )

    def fail_if_called(*args, **kwargs):
        raise AssertionError("Repository must not be created for a bad cert path")

    monkeypatch.setattr(repository, "Repository", fail_if_called)

    with pytest.raises(exceptions.InvalidConfiguration, match="CA bundle"):
        settings_obj.create_repository()


def test_create_repository_applies_configured_certificates(tmp_path):
    """Pass configured certificate paths through to the created repository."""
    cacert = tmp_path / "ca.pem"
    client_cert = tmp_path / "client.pem"
    cacert.write_text("ca")
    client_cert.write_text("client")

    settings_obj = settings.Settings(
        non_interactive=True,
        username="fakeuser",
        password="password",
        cacert=str(cacert),
        client_cert=str(client_cert),
    )
    repo = settings_obj.create_repository()
    assert repo.session.verify == str(cacert)
    assert repo.session.cert == str(client_cert)
    repo.close()


class TestArgumentParsing:
    @staticmethod
    def parse_args(args):
        parser = argparse.ArgumentParser()
        settings.Settings.register_argparse_arguments(parser)
        return parser.parse_args(args)

    def test_non_interactive_flag(self):
        args = self.parse_args(["--non-interactive"])
        assert args.non_interactive

    def test_non_interactive_environment(self, monkeypatch):
        monkeypatch.setenv("TWINE_NON_INTERACTIVE", "1")
        args = self.parse_args([])
        assert args.non_interactive
        monkeypatch.setenv("TWINE_NON_INTERACTIVE", "0")
        args = self.parse_args([])
        assert not args.non_interactive

    def test_attestations_flag(self):
        args = self.parse_args(["--attestations"])
        assert args.attestations
