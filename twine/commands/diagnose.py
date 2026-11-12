"""Module containing the logic for ``twine diagnose``."""
import argparse
import configparser
import logging
import os
from typing import Dict, List, Optional, Tuple, cast

from rich import print
from rich.markup import escape

from twine import exceptions
from twine import repository
from twine import utils

logger = logging.getLogger(__name__)

_REPOSITORY_ENV = "TWINE_REPOSITORY"
_REPOSITORY_URL_ENV = "TWINE_REPOSITORY_URL"


def _resolve_option(
    cli_value: Optional[str], env_name: str, default: Optional[str]
) -> Tuple[Optional[str], str]:
    """Resolve an option the same way ``twine upload`` does, tracking the source.

    Command-line values win over environment variables, which win over the
    built-in default. This mirrors ``utils.EnvironmentDefault``.
    """
    if cli_value is not None:
        return cli_value, "command line"
    env_value = os.environ.get(env_name)
    if env_value:
        return env_value, f"environment variable {env_name}"
    return default, "default"


def _load_sections_without_secrets(
    config_file: str,
) -> Dict[str, utils.RepositoryConfig]:
    """Read the config file, discarding passwords before anything can use them.

    The diagnostic never retains, resolves (e.g. via keyring), or prints
    credentials; only the remaining, non-secret settings are returned.
    """
    config = utils.get_config(config_file)
    for section in config.values():
        section.pop("password", None)
    return config


def diagnose(
    repository_name: Optional[str] = None,
    repository_url: Optional[str] = None,
    config_file: str = utils.DEFAULT_CONFIG_FILE,
) -> bool:
    """Explain which repository an upload would target, and why.

    Resolve the upload target exactly like ``twine upload`` does, reporting
    the final URL and which configuration source (command line, environment
    variable, or config file section) supplied it. No credentials are loaded
    or displayed, so this is safe to run in CI during a migration of
    ``.pypirc`` section names.

    :param repository_name:
        The value of ``--repository``, if given on the command line.
    :param repository_url:
        The value of ``--repository-url``, if given on the command line.
    :param config_file:
        The path to the configuration file to use.

    :return:
        ``True`` if the target cannot be resolved, otherwise ``False``.
    """
    name, name_source = _resolve_option(repository_name, _REPOSITORY_ENV, "pypi")
    url, url_source = _resolve_option(repository_url, _REPOSITORY_URL_ENV, None)
    name = cast(str, name)

    print("Repository configuration sources:")
    print(f"  config file: {escape(str(config_file))}")
    print(f"  repository name: {escape(name)!r} (from {name_source})")
    if url:
        print(
            f"  repository URL: {escape(utils.sanitize_url(url))!r} "
            f"(from {url_source})"
        )
    else:
        print("  repository URL: not set")

    if url and (repository_name is not None or os.environ.get(_REPOSITORY_ENV)):
        print(
            "  note: the repository URL takes precedence; "
            "the repository name is ignored"
        )

    if url:
        try:
            config = utils.get_repository_from_config(config_file, name, url)
        except exceptions.TwineException as exc:
            logger.error(f"Invalid repository URL: {exc}")
            return True
        config.pop("password", None)
        target = cast(str, config["repository"])
        source = f"{url_source} (repository URL overrides any config file section)"
    else:
        try:
            sections = _load_sections_without_secrets(config_file)
        except (OSError, exceptions.TwineException) as exc:
            logger.error(f"Unable to read configuration: {exc}")
            return True
        except configparser.Error:
            logger.error(f"Malformed configuration in {config_file}.")
            return True

        if name not in sections:
            available = ", ".join(sorted(sections)) or "(none)"
            logger.error(
                f"Missing '{name}' section from {config_file}.\n"
                f"Available sections: {available}\n"
                "If this alias was renamed during migration, update the "
                "section name or select one of the available sections."
            )
            return True

        config = sections[name]
        target = utils.normalize_repository_url(cast(str, config["repository"]))
        source = f"section [{name}] in {config_file} (selected via {name_source})"

    print("Resolved upload target:")
    print(f"  URL: {escape(utils.sanitize_url(target))}")
    print(f"  source: {escape(source)}")
    if config.get("username"):
        print(
            f"  username: {escape(str(config['username']))} "
            "(password intentionally not loaded)"
        )
    else:
        print("  username: not configured (password intentionally not loaded)")

    failure = False
    if target.startswith((repository.LEGACY_PYPI, repository.LEGACY_TEST_PYPI)):
        logger.warning(
            "The resolved URL is a deprecated legacy PyPI endpoint; "
            f"use {utils.DEFAULT_REPOSITORY} or {utils.TEST_REPOSITORY} instead."
        )
        failure = True

    return failure


def main(args: List[str]) -> bool:
    """Execute the ``diagnose`` command.

    :param args:
        The command-line arguments.

    :return:
        The exit status of the ``diagnose`` command.
    """
    parser = argparse.ArgumentParser(
        prog="twine diagnose",
        description="Explain which repository an upload would target and which "
        "configuration source (command line, environment, or config file) "
        "decided it. No credentials are loaded or displayed.",
    )
    parser.add_argument(
        "-r",
        "--repository",
        default=None,
        help="The repository (package index) to upload to. Should be a "
        "section in the config file. (TWINE_REPOSITORY is honored, as in "
        "twine upload.)",
    )
    parser.add_argument(
        "--repository-url",
        default=None,
        required=False,
        help="The repository (package index) URL to upload to. This overrides "
        "--repository. (TWINE_REPOSITORY_URL is honored, as in twine upload.)",
    )
    parser.add_argument(
        "--config-file",
        default=utils.DEFAULT_CONFIG_FILE,
        help="The .pypirc config file to use.",
    )

    parsed_args = parser.parse_args(args)

    return diagnose(
        repository_name=parsed_args.repository,
        repository_url=parsed_args.repository_url,
        config_file=parsed_args.config_file,
    )
