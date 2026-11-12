import pytest

from twine.commands import diagnose


@pytest.fixture(autouse=True)
def clear_twine_env(monkeypatch):
    monkeypatch.delenv("TWINE_REPOSITORY", raising=False)
    monkeypatch.delenv("TWINE_REPOSITORY_URL", raising=False)


@pytest.fixture
def migrated_config(write_config_file):
    return write_config_file(
        """
        [distutils]
        index-servers =
            old-alias
            new-alias

        [old-alias]
        repository: https://old.example.com/legacy/
        username: old-user
        password: old-secret

        [new-alias]
        repository: https://new.example.com/simple/
        username: new-user
        password: new-secret
        """
    )


def test_legacy_alias_from_command_line(migrated_config, capsys):
    failure = diagnose.main(["-r", "old-alias", "--config-file", str(migrated_config)])

    assert not failure
    output = capsys.readouterr().out
    assert "repository name: 'old-alias' (from command line)" in output
    assert "URL: https://old.example.com/legacy/" in output
    assert f"section [old-alias] in {migrated_config}" in output
    assert "selected via command line" in output


def test_default_target_without_config(config_file, capsys):
    failure = diagnose.main([])

    assert not failure
    output = capsys.readouterr().out
    assert "repository name: 'pypi' (from default)" in output
    assert "URL: https://upload.pypi.org/legacy/" in output


def test_explicit_repository_url_from_command_line(migrated_config, capsys):
    failure = diagnose.main(
        [
            "-r",
            "new-alias",
            "--repository-url",
            "https://cli.example.com/upload/",
            "--config-file",
            str(migrated_config),
        ]
    )

    assert not failure
    output = capsys.readouterr().out
    assert (
        "repository URL: 'https://cli.example.com/upload/' (from command line)"
        in output
    )
    assert "the repository name is ignored" in output
    assert "URL: https://cli.example.com/upload/" in output
    assert "repository URL overrides any config file section" in output
    assert "https://new.example.com/simple/" not in output


def test_environment_selects_repository(migrated_config, monkeypatch, capsys):
    monkeypatch.setenv("TWINE_REPOSITORY", "new-alias")

    failure = diagnose.main(["--config-file", str(migrated_config)])

    assert not failure
    output = capsys.readouterr().out
    assert (
        "repository name: 'new-alias' (from environment variable TWINE_REPOSITORY)"
        in output
    )
    assert "URL: https://new.example.com/simple/" in output
    assert "selected via environment variable TWINE_REPOSITORY" in output


def test_environment_repository_url_overrides_config(
    migrated_config, monkeypatch, capsys
):
    monkeypatch.setenv("TWINE_REPOSITORY", "new-alias")
    monkeypatch.setenv("TWINE_REPOSITORY_URL", "https://env.example.com/upload/")

    failure = diagnose.main(["--config-file", str(migrated_config)])

    assert not failure
    output = capsys.readouterr().out
    assert "(from environment variable TWINE_REPOSITORY_URL)" in output
    assert "URL: https://env.example.com/upload/" in output
    assert "https://new.example.com/simple/" not in output


def test_command_line_beats_environment(migrated_config, monkeypatch, capsys):
    monkeypatch.setenv("TWINE_REPOSITORY", "new-alias")
    monkeypatch.setenv("TWINE_REPOSITORY_URL", "https://env.example.com/upload/")

    failure = diagnose.main(
        [
            "--repository-url", "https://cli.example.com/upload/",
            "--config-file", str(migrated_config),
        ]
    )

    assert not failure
    output = capsys.readouterr().out
    assert (
        "repository URL: 'https://cli.example.com/upload/' (from command line)"
        in output
    )
    assert "URL: https://cli.example.com/upload/" in output
    assert "https://env.example.com/upload/" not in output


def test_missing_section_after_rename(migrated_config, caplog):
    failure = diagnose.main(
        ["-r", "removed-alias", "--config-file", str(migrated_config)]
    )

    assert failure
    assert "Missing 'removed-alias' section" in caplog.text
    assert "old-alias" in caplog.text
    assert "new-alias" in caplog.text


def test_passwords_are_never_printed(migrated_config, capsys):
    failure = diagnose.main(["-r", "old-alias", "--config-file", str(migrated_config)])

    assert not failure
    captured = capsys.readouterr()
    assert "old-secret" not in captured.out
    assert "old-secret" not in captured.err
    assert "password intentionally not loaded" in captured.out


def test_url_credentials_are_masked(migrated_config, capsys):
    failure = diagnose.main(
        [
            "--repository-url", "https://user:url-secret@example.com/upload/",
            "--config-file", str(migrated_config),
        ]
    )

    assert not failure
    captured = capsys.readouterr()
    assert "url-secret" not in captured.out
    assert "url-secret" not in captured.err
    assert "********" in captured.out


def test_legacy_pypi_url_warns(write_config_file, caplog):
    config = write_config_file(
        """
        [distutils]
        index-servers = legacy

        [legacy]
        repository: https://pypi.python.org/pypi
        """
    )

    failure = diagnose.main(["-r", "legacy", "--config-file", str(config)])

    assert failure
    assert "deprecated legacy PyPI endpoint" in caplog.text
