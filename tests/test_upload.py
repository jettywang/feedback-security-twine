# Copyright 2014 Ian Cordasco
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
import hashlib
import os
import pathlib
import shutil

import pretend
import pytest
import requests

from twine import cli
from twine import exceptions
from twine import package as package_file
from twine.commands import upload

from . import helpers

RELEASE_URL = "https://pypi.org/project/twine/4.0.2/"
NEW_RELEASE_URL = "https://pypi.org/project/twine/6.2.0/"


@pytest.fixture
def stub_response():
    """Mock successful upload of a package."""
    return pretend.stub(
        is_redirect=False,
        url="https://test.pypi.org/legacy/",
        status_code=200,
        reason="OK",
        text=None,
        raise_for_status=lambda: None,
    )


@pytest.fixture
def stub_repository(stub_response):
    """Allow assertions on the uploaded package."""
    return pretend.stub(
        upload=pretend.call_recorder(lambda package: stub_response),
        close=lambda: None,
        release_urls=lambda packages: set(),
    )


@pytest.fixture
def upload_settings(make_settings, stub_repository):
    """Use the stub repository when uploading."""
    upload_settings = make_settings()
    upload_settings.create_repository = lambda: stub_repository
    return upload_settings


def test_make_package_pre_signed_dist(upload_settings, caplog):
    """Create a PackageFile and print path, size, and user-provided signature."""
    filename = helpers.WHEEL_FIXTURE
    expected_size = "35.5 KB"
    signed_filename = helpers.WHEEL_FIXTURE + ".asc"
    signatures = {os.path.basename(signed_filename): signed_filename}

    upload_settings.sign = True
    upload_settings.verbose = True

    package = upload._make_package(filename, signatures, [], upload_settings)

    assert package.filename == filename
    assert package.gpg_signature is not None
    assert package.attestations is None

    assert caplog.messages == [
        f"{filename} ({expected_size})",
        f"Signed with {signed_filename}",
    ]


def test_make_package_unsigned_dist(upload_settings, monkeypatch, caplog):
    """Create a PackageFile and print path, size, and Twine-generated signature."""
    filename = helpers.NEW_WHEEL_FIXTURE
    expected_size = "41.7 KB"
    signatures = {}

    upload_settings.sign = True
    upload_settings.verbose = True

    def stub_sign(package, *_):
        package.gpg_signature = (package.signed_basefilename, b"signature")

    monkeypatch.setattr(package_file.PackageFile, "sign", stub_sign)

    package = upload._make_package(filename, signatures, [], upload_settings)

    assert package.filename == filename
    assert package.gpg_signature is not None

    assert caplog.messages == [
        f"{filename} ({expected_size})",
        f"Signed with {package.signed_filename}",
    ]


def test_make_package_attestations_flagged_but_missing(upload_settings):
    """Fail when the user requests attestations but does not supply any attestations."""
    upload_settings.attestations = True

    with pytest.raises(
        exceptions.InvalidDistribution, match="Upload with attestations requested"
    ):
        upload._make_package(helpers.NEW_WHEEL_FIXTURE, {}, [], upload_settings)


def test_success_prints_release_urls(upload_settings, stub_repository, capsys):
    """Print PyPI release URLS for each uploaded package."""
    stub_repository.release_urls = lambda packages: {RELEASE_URL, NEW_RELEASE_URL}

    result = upload.upload(
        upload_settings,
        [
            helpers.WHEEL_FIXTURE,
            helpers.SDIST_FIXTURE,
            helpers.NEW_SDIST_FIXTURE,
            helpers.NEW_WHEEL_FIXTURE,
        ],
    )
    assert result is None

    captured = capsys.readouterr()
    assert captured.out.count(RELEASE_URL) == 1
    assert captured.out.count(NEW_RELEASE_URL) == 1


def test_print_packages_if_verbose(upload_settings, caplog):
    """Print the path and file size of each distribution attempting to be uploaded."""
    dists_to_upload = {
        helpers.WHEEL_FIXTURE: "35.5 KB",
        helpers.NEW_WHEEL_FIXTURE: "41.7 KB",
        helpers.SDIST_FIXTURE: "20.8 KB",
        helpers.NEW_SDIST_FIXTURE: "26.1 KB",
    }

    upload_settings.verbose = True

    result = upload.upload(upload_settings, dists_to_upload.keys())
    assert result is None

    assert [m for m in caplog.messages if m.endswith("KB)")] == [
        f"{filename} ({size})" for filename, size in dists_to_upload.items()
    ]


def test_print_response_if_verbose(upload_settings, stub_response, caplog):
    """Print details about the response from the repository."""
    upload_settings.verbose = True

    result = upload.upload(
        upload_settings,
        [helpers.WHEEL_FIXTURE, helpers.SDIST_FIXTURE],
    )
    assert result is None

    response_log = (
        f"Response from {stub_response.url}:\n"
        f"{stub_response.status_code} {stub_response.reason}"
    )

    assert caplog.messages.count(response_log) == 2


def test_success_with_pre_signed_distribution(upload_settings, stub_repository, caplog):
    """Add GPG signature provided by user to uploaded package."""
    # Upload a pre-signed distribution
    result = upload.upload(
        upload_settings, [helpers.WHEEL_FIXTURE, helpers.WHEEL_FIXTURE + ".asc"]
    )
    assert result is None

    # The signature should be added via package.add_gpg_signature()
    package = stub_repository.upload.calls[0].args[0]
    assert package.gpg_signature == (
        "twine-4.0.2-py3-none-any.whl.asc",
        b"signature",
    )

    # Ensure that a warning is emitted.
    assert (
        "One or more packages has an associated PGP signature; these will "
        "be silently ignored by the index" in caplog.messages
    )


def test_warns_potential_pgp_removal_on_3p_index(
    make_settings, stub_repository, caplog
):
    """Warn when a PGP signature is specified for upload to a third-party index."""
    upload_settings = make_settings("""
        [pypi]
        repository: https://example.com/not-a-real-index/
        username:foo
        password:bar
        """)
    upload_settings.create_repository = lambda: stub_repository

    # Upload a pre-signed distribution
    result = upload.upload(
        upload_settings, [helpers.WHEEL_FIXTURE, helpers.WHEEL_FIXTURE + ".asc"]
    )
    assert result is None

    # The signature should be added via package.add_gpg_signature()
    package = stub_repository.upload.calls[0].args[0]
    assert package.gpg_signature == (
        "twine-4.0.2-py3-none-any.whl.asc",
        b"signature",
    )

    # Ensure that a warning is emitted.
    assert (
        "One or more packages has an associated PGP signature; a future "
        "version of twine may silently ignore these. See "
        "https://github.com/pypa/twine/issues/1009 for more information"
        in caplog.messages
    )


def test_exception_with_only_pre_signed_file(upload_settings, stub_repository):
    """Raise an exception when only a signed file is uploaded."""
    # Upload only pre-signed file
    with pytest.raises(exceptions.InvalidDistribution) as err:
        upload.upload(upload_settings, [helpers.WHEEL_FIXTURE + ".asc"])

    assert (
        "Cannot upload signed files by themselves, must upload with a "
        "corresponding distribution file." in err.value.args[0]
    )


def test_success_when_gpg_is_run(upload_settings, stub_repository, monkeypatch):
    """Add GPG signature generated by gpg command to uploaded package."""
    # Indicate that upload() should run_gpg() to generate the signature, which
    # we'll stub out to use WHEEL_FIXTURE + ".asc"
    upload_settings.sign = True
    upload_settings.sign_with = "gpg"
    monkeypatch.setattr(
        package_file.PackageFile,
        "run_gpg",
        pretend.call_recorder(lambda cls, gpg_args: None),
    )

    # Upload an unsigned distribution
    result = upload.upload(upload_settings, [helpers.WHEEL_FIXTURE])
    assert result is None

    # The signature should be added via package.sign()
    package = stub_repository.upload.calls[0].args[0]
    assert len(package.run_gpg.calls) == 1
    assert helpers.WHEEL_FIXTURE in package.run_gpg.calls[0].args[1]
    assert package.gpg_signature == (
        "twine-4.0.2-py3-none-any.whl.asc",
        b"signature",
    )


@pytest.mark.parametrize("verbose", [False, True])
def test_exception_for_http_status(
    verbose, upload_settings, stub_response, capsys, caplog
):
    upload_settings.verbose = verbose

    stub_response.is_redirect = False
    stub_response.status_code = 403
    stub_response.reason = "Invalid or non-existent authentication information"
    stub_response.text = stub_response.reason
    stub_response.raise_for_status = pretend.raiser(requests.HTTPError)

    with pytest.raises(requests.HTTPError):
        upload.upload(upload_settings, [helpers.WHEEL_FIXTURE])

    captured = capsys.readouterr()
    assert RELEASE_URL not in captured.out

    if verbose:
        assert caplog.messages == [
            f"{helpers.WHEEL_FIXTURE} (35.5 KB)",
            f"Response from {stub_response.url}:\n403 {stub_response.reason}",
            stub_response.text,
        ]
    else:
        assert caplog.messages == [
            "Error during upload. Retry with the --verbose option for more details."
        ]


def test_get_config_old_format(make_settings, config_file):
    try:
        make_settings("""
            [server-login]
            username:foo
            password:bar
            """)
    except KeyError as err:
        assert all(
            text in err.args[0]
            for text in [
                "'pypi'",
                "--repository-url",
                config_file,
                "https://docs.python.org/",
            ]
        )


def test_deprecated_repo(make_settings):
    with pytest.raises(exceptions.UploadToDeprecatedPyPIDetected) as err:
        upload_settings = make_settings("""
            [pypi]
            repository: https://pypi.python.org/pypi/
            username:foo
            password:bar
            """)

        upload.upload(upload_settings, [helpers.WHEEL_FIXTURE])

    assert all(
        text in err.value.args[0]
        for text in [
            "https://pypi.python.org/pypi/",
            "https://upload.pypi.org/legacy/",
            "https://test.pypi.org/legacy/",
            "https://packaging.python.org/",
        ]
    )


@pytest.mark.parametrize(
    "repository_url, redirect_url, message_match",
    [
        (
            "https://test.pypi.org/legacy",
            "https://test.pypi.org/legacy/",
            (
                r"https://test.pypi.org/legacy.+https://test.pypi.org/legacy/"
                r".+\nYour repository URL is missing a trailing slash"
            ),
        ),
        (
            "https://test.pypi.org/legacy/",
            "https://malicious.website.org/danger/",
            (
                r"https://test.pypi.org/legacy/.+https://malicious.website.org/danger/"
                r".+\nIf you trust these URLs"
            ),
        ),
    ],
)
def test_exception_for_redirect(
    repository_url,
    redirect_url,
    message_match,
    make_settings,
):
    # Not using fixtures because this setup is significantly different

    upload_settings = make_settings(f"""
        [pypi]
        repository: {repository_url}
        username:foo
        password:bar
        """)

    stub_response = pretend.stub(
        is_redirect=True,
        url=redirect_url,
        status_code=301,
        headers={"location": redirect_url},
        reason="Redirect",
        text="",
    )

    stub_repository = pretend.stub(
        upload=lambda package: stub_response, close=lambda: None
    )

    upload_settings.create_repository = lambda: stub_repository

    with pytest.raises(exceptions.RedirectDetected, match=message_match):
        upload.upload(upload_settings, [helpers.WHEEL_FIXTURE])


def test_prints_skip_message_for_uploaded_package(
    upload_settings, stub_repository, capsys, caplog
):
    upload_settings.skip_existing = True

    # Short-circuit the upload
    stub_repository.package_is_uploaded = lambda package: True

    result = upload.upload(upload_settings, [helpers.WHEEL_FIXTURE])
    assert result is None

    captured = capsys.readouterr()
    assert RELEASE_URL not in captured.out

    assert caplog.messages == [
        "Skipping twine-4.0.2-py3-none-any.whl because it appears to already exist"
    ]


def test_prints_skip_message_for_response(
    upload_settings, stub_response, stub_repository, capsys, caplog
):
    upload_settings.skip_existing = True

    stub_response.status_code = 400
    stub_response.reason = "File already exists"
    stub_response.text = stub_response.reason

    # Do the upload, triggering the error response
    stub_repository.package_is_uploaded = lambda package: False

    result = upload.upload(upload_settings, [helpers.WHEEL_FIXTURE])
    assert result is None

    captured = capsys.readouterr()
    assert RELEASE_URL not in captured.out

    assert caplog.messages == [
        "Skipping twine-4.0.2-py3-none-any.whl because it appears to already exist"
    ]


@pytest.mark.parametrize(
    "response_kwargs",
    [
        pytest.param(
            dict(
                status_code=400,
                reason=(
                    'A file named "twine-4.0.2-py3-none-any.whl" already '
                    "exists for twine-4.0.2."
                ),
            ),
            id="pypi",
        ),
        pytest.param(
            dict(
                status_code=409,
                reason=(
                    'A file named "twine-4.0.2-py3-none-any.whl" already '
                    "exists for twine-4.0.2."
                ),
            ),
            id="pypiserver",
        ),
    ],
)
def test_skip_existing_skips_files_on_repository(response_kwargs):
    assert upload.skip_upload(
        response=pretend.stub(**response_kwargs),
        skip_existing=True,
        package=package_file.PackageFile.from_filename(helpers.WHEEL_FIXTURE, None),
    )


@pytest.mark.parametrize(
    "response_kwargs",
    [
        pytest.param(
            dict(status_code=400, reason="Invalid credentials"), id="wrong_reason"
        ),
        pytest.param(dict(status_code=404), id="wrong_code"),
    ],
)
def test_skip_upload_doesnt_match(response_kwargs):
    assert not upload.skip_upload(
        response=pretend.stub(**response_kwargs),
        skip_existing=True,
        package=package_file.PackageFile.from_filename(helpers.WHEEL_FIXTURE, None),
    )


def test_skip_upload_respects_skip_existing():
    assert not upload.skip_upload(
        response=pretend.stub(),
        skip_existing=False,
        package=package_file.PackageFile.from_filename(helpers.WHEEL_FIXTURE, None),
    )


@pytest.mark.parametrize("repo", ["pypi", "testpypi"])
def test_values_from_env_pypi(monkeypatch, repo):
    def none_upload(*args, **settings_kwargs):
        pass

    replaced_upload = pretend.call_recorder(none_upload)
    monkeypatch.setattr(upload, "upload", replaced_upload)
    testenv = {
        "TWINE_REPOSITORY": repo,
        "TWINE_USERNAME": "pypiuser",
        "TWINE_PASSWORD": "pypipassword",
        "TWINE_CERT": "/foo/bar.crt",
    }
    for key, value in testenv.items():
        monkeypatch.setenv(key, value)
    cli.dispatch(["upload", "path/to/file"])
    upload_settings = replaced_upload.calls[0].args[0]
    assert "pypipassword" == upload_settings.password
    assert "pypiuser" == upload_settings.username
    assert "/foo/bar.crt" == upload_settings.cacert


def test_values_from_env_non_pypi(monkeypatch, write_config_file):
    write_config_file("""
        [distutils]
        index-servers =
            notpypi

        [notpypi]
        repository: https://upload.example.org/legacy/
        username:someusername
        password:password
        """)

    def none_upload(*args, **settings_kwargs):
        pass

    replaced_upload = pretend.call_recorder(none_upload)
    monkeypatch.setattr(upload, "upload", replaced_upload)
    testenv = {
        "TWINE_REPOSITORY": "notpypi",
        "TWINE_USERNAME": "someusername",
        "TWINE_PASSWORD": "pypipassword",
        "TWINE_CERT": "/foo/bar.crt",
    }
    for key, value in testenv.items():
        monkeypatch.setenv(key, value)
    cli.dispatch(["upload", "path/to/file"])
    upload_settings = replaced_upload.calls[0].args[0]
    assert "pypipassword" == upload_settings.password
    assert "someusername" == upload_settings.username
    assert "/foo/bar.crt" == upload_settings.cacert


@pytest.mark.parametrize(
    "repo_url",
    ["https://upload.pypi.org/", "https://test.pypi.org/", "https://pypi.org/"],
)
def test_check_status_code_for_wrong_repo_url(repo_url, upload_settings, stub_response):
    upload_settings.repository_config["repository"] = repo_url

    stub_response.url = repo_url
    stub_response.status_code = 405

    with pytest.raises(exceptions.InvalidPyPIUploadURL):
        upload.upload(
            upload_settings,
            [
                helpers.WHEEL_FIXTURE,
                helpers.SDIST_FIXTURE,
                helpers.NEW_SDIST_FIXTURE,
                helpers.NEW_WHEEL_FIXTURE,
            ],
        )


def test_upload_warns_attestations_non_pypi(upload_settings, caplog, stub_response):
    upload_settings.repository_config["repository"] = "https://notpypi.example.com"
    upload_settings.attestations = True

    # This fails because the attestation isn't a real file, which is fine
    # since our functionality under test happens before the failure.
    with pytest.raises(exceptions.InvalidDistribution):
        upload.upload(
            upload_settings,
            [helpers.WHEEL_FIXTURE, helpers.WHEEL_FIXTURE + ".foo.attestation"],
        )

    assert (
        "Only PyPI and TestPyPI support attestations; if you experience "
        "failures, remove the --attestations flag and re-try this command"
        in caplog.messages
    )


@pytest.fixture
def recording_repository(stub_response):
    """Fake upload endpoint that records the bytes it receives."""
    received = {}

    def record_upload(package):
        received[package.basefilename] = pathlib.Path(package.filename).read_bytes()
        return stub_response

    return pretend.stub(
        upload=record_upload,
        close=lambda: None,
        release_urls=lambda packages: set(),
        received=received,
    )


def _copy_dists_to_tmp_path(tmp_path, fixtures):
    """Copy distribution fixtures into a temporary directory."""
    dists = []
    for fixture in fixtures:
        dest = tmp_path / os.path.basename(fixture)
        shutil.copy(fixture, dest)
        dists.append(dest)
    return dists


def _write_manifest(tmp_path, entries):
    """Write a sha256sum-style manifest of ``(filename, hexdigest)`` entries."""
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(
        "".join(f"{digest}  {filename}\n" for filename, digest in entries)
    )
    return str(manifest)


def _sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def test_upload_sha256_manifest_success(
    tmp_path, make_settings, recording_repository, caplog
):
    """Upload multiple files whose digests all match the manifest."""
    dists = _copy_dists_to_tmp_path(
        tmp_path, [helpers.WHEEL_FIXTURE, helpers.NEW_SDIST_FIXTURE]
    )
    manifest = _write_manifest(tmp_path, [(dist.name, _sha256(dist)) for dist in dists])

    upload_settings = make_settings(sha256_manifest=manifest)
    upload_settings.verbose = True
    upload_settings.create_repository = lambda: recording_repository

    upload.upload(upload_settings, [str(dist) for dist in dists])

    assert recording_repository.received == {
        dist.name: dist.read_bytes() for dist in dists
    }
    assert f"Verified SHA-256 digest of {dists[0].name}" in caplog.messages
    assert f"Verified SHA-256 digest of {dists[1].name}" in caplog.messages


def test_upload_sha256_manifest_mismatch(tmp_path, make_settings, recording_repository):
    """Abort without any upload when a digest does not match the manifest."""
    dists = _copy_dists_to_tmp_path(
        tmp_path, [helpers.WHEEL_FIXTURE, helpers.NEW_SDIST_FIXTURE]
    )
    manifest = _write_manifest(
        tmp_path,
        [
            (dists[0].name, _sha256(dists[0])),
            (dists[1].name, "0" * 64),
        ],
    )

    upload_settings = make_settings(sha256_manifest=manifest)
    upload_settings.create_repository = lambda: recording_repository

    with pytest.raises(
        exceptions.InvalidManifest, match="SHA-256 digest of .* does not match"
    ):
        upload.upload(upload_settings, [str(dist) for dist in dists])

    assert recording_repository.received == {}


def test_upload_sha256_manifest_missing_entry(
    tmp_path, make_settings, recording_repository
):
    """Abort without any upload when a file is missing from the manifest."""
    dists = _copy_dists_to_tmp_path(
        tmp_path, [helpers.WHEEL_FIXTURE, helpers.NEW_SDIST_FIXTURE]
    )
    manifest = _write_manifest(tmp_path, [(dists[0].name, _sha256(dists[0]))])

    upload_settings = make_settings(sha256_manifest=manifest)
    upload_settings.create_repository = lambda: recording_repository

    with pytest.raises(
        exceptions.InvalidManifest, match="missing from the SHA-256 manifest"
    ):
        upload.upload(upload_settings, [str(dist) for dist in dists])

    assert recording_repository.received == {}


def test_load_sha256_manifest_malformed_line(tmp_path):
    """Reject a manifest line that is not '<digest>  <filename>'."""
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text("not-a-digest\n")

    with pytest.raises(exceptions.InvalidManifest, match="Malformed line 1"):
        upload._load_sha256_manifest(str(manifest))


def test_load_sha256_manifest_parses_sha256sum_format(tmp_path):
    """Parse comments, binary-mode markers, and directory components."""
    digest = "a" * 64
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(
        f"# comment\n\n{digest} *dist/twine-4.0.2-py3-none-any.whl\n"
        f"{digest.upper()}  twine-1.5.0.tar.gz\n"
    )

    assert upload._load_sha256_manifest(str(manifest)) == {
        "twine-4.0.2-py3-none-any.whl": digest,
        "twine-1.5.0.tar.gz": digest,
    }
