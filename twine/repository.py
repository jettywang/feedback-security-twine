# Copyright 2015 Ian Cordasco
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
import logging
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

import requests
import requests_toolbelt
import rich.progress
from rich import print

from twine import exceptions
from twine import package as package_file
from twine.utils import make_requests_session

LEGACY_PYPI = "https://pypi.python.org/"
LEGACY_TEST_PYPI = "https://testpypi.python.org/"
WAREHOUSE = "https://upload.pypi.org/"
OLD_WAREHOUSE = "https://upload.pypi.io/"
TEST_WAREHOUSE = "https://test.pypi.org/"
WAREHOUSE_WEB = "https://pypi.org/"

# Endpoint, relative to the repository URL, advertising the features the
# repository supports. A successful read is shared by every file in an upload.
CAPABILITIES_ENDPOINT = "capabilities/"

logger = logging.getLogger(__name__)


class Repository:
    def __init__(
        self,
        repository_url: str,
        username: Optional[str],
        password: Optional[str],
        disable_progress_bar: bool = False,
    ) -> None:
        self.url = repository_url

        self.session = make_requests_session()
        # requests.Session.auth should be Union[None, Tuple[str, str], ...]
        # But username or password could be None
        # See TODO for utils.RepositoryConfig
        self.session.auth = (
            (username or "", password or "") if username or password else None
        )
        logger.info(f"username: {username if username else '<empty>'}")
        logger.info(f"password: <{'hidden' if password else 'empty'}>")

        # Working around https://github.com/python/typing/issues/182
        self._releases_json_data: Dict[str, Dict[str, Any]] = {}
        self.disable_progress_bar = disable_progress_bar

        # Capabilities read from the repository. Only a successful read is
        # cached; failures leave these empty so the next read is retried.
        self._capabilities: Optional[Set[str]] = None
        self._capabilities_url: Optional[str] = None

    @property
    def _capability_endpoint(self) -> str:
        return self.url.rstrip("/") + "/" + CAPABILITIES_ENDPOINT

    def read_capabilities(self) -> Set[str]:
        """Read the features supported by the repository.

        The result of a successful read is cached and reused for every file
        uploaded in the same command invocation. The cache is discarded when
        the target repository changes or when a previous read failed, so each
        of those situations triggers a fresh negotiation.

        :raises requests.RequestException:
            The repository could not be reached or returned an error response.
        """
        capabilities_url = self._capability_endpoint
        if (
            self._capabilities is not None
            and self._capabilities_url == capabilities_url
        ):
            return self._capabilities

        response = self.session.get(
            capabilities_url,
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()

        capabilities = set(response.json().get("capabilities", ()))
        self._capabilities = capabilities
        self._capabilities_url = capabilities_url
        return capabilities

    def verify_feature_capability(
        self, required_features: Mapping[str, str]
    ) -> None:
        """Verify the repository supports every requested feature.

        The capability read happens once and is shared by all files in the
        upload. Unsupported features raise before any file is transferred.

        :param required_features:
            Mapping of repository capability identifiers to the user-facing
            feature names reported when the capability is missing.
        :raises twine.exceptions.UnsupportedConfiguration:
            One or more required capabilities are not advertised by the
            repository.
        :raises requests.RequestException:
            The repository capabilities could not be read.
        """
        supported = self.read_capabilities()
        unsupported = [
            feature_name
            for capability, feature_name in required_features.items()
            if capability not in supported
        ]
        if unsupported:
            builder = exceptions.UnsupportedConfiguration.Builder()
            builder.with_repository_url(self.url)
            for feature_name in unsupported:
                builder.with_feature(feature_name)
            raise builder.finalize()

    def close(self) -> None:
        self.session.close()

    @staticmethod
    def _convert_metadata_to_list_of_tuples(
        data: package_file.PackageMetadata,
    ) -> List[Tuple[str, Any]]:
        # This does what ``warehouse.forklift.parse_form_metadata()`` does, in reverse.
        data_to_send: List[Tuple[str, Any]] = []
        for key, value in data.items():
            if key == "gpg_signature":
                assert isinstance(value, tuple)
                data_to_send.append((key, value))
            elif key == "project_urls":
                assert isinstance(value, dict)
                for name, url in value.items():
                    data_to_send.append((key, f"{name}, {url}"))
            elif key == "keywords":
                assert isinstance(value, list)
                data_to_send.append((key, ", ".join(value)))
            elif isinstance(value, (list, tuple)):
                data_to_send.extend((key, item) for item in value)
            else:
                assert isinstance(value, str)
                data_to_send.append((key, value))
        return data_to_send

    def set_certificate_authority(self, cacert: Optional[str]) -> None:
        if cacert:
            self.session.verify = cacert

    def set_client_certificate(self, clientcert: Optional[str]) -> None:
        if clientcert:
            self.session.cert = clientcert

    def _upload(self, package: package_file.PackageFile) -> requests.Response:
        print(f"Uploading {package.basefilename}")

        metadata = package.metadata_dictionary()
        data_to_send = self._convert_metadata_to_list_of_tuples(metadata)
        data_to_send.append((":action", "file_upload"))
        data_to_send.append(("protocol_version", "1"))
        with open(package.filename, "rb") as fp:
            data_to_send.append(
                (
                    "content",
                    (package.basefilename, fp, "application/octet-stream"),
                )
            )
            encoder = requests_toolbelt.MultipartEncoder(data_to_send)

            with rich.progress.Progress(
                "[progress.percentage]{task.percentage:>3.0f}%",
                rich.progress.BarColumn(),
                rich.progress.DownloadColumn(),
                "•",
                rich.progress.TimeRemainingColumn(
                    compact=True,
                    elapsed_when_finished=True,
                ),
                "•",
                rich.progress.TransferSpeedColumn(),
                disable=self.disable_progress_bar,
            ) as progress:
                task_id = progress.add_task("", total=encoder.len)

                monitor = requests_toolbelt.MultipartEncoderMonitor(
                    encoder,
                    lambda monitor: progress.update(
                        task_id,
                        completed=monitor.bytes_read,
                    ),
                )

                resp = self.session.post(
                    self.url,
                    data=monitor,
                    allow_redirects=False,
                    headers={"Content-Type": monitor.content_type},
                )

        return resp

    def upload(
        self, package: package_file.PackageFile, max_redirects: int = 5
    ) -> requests.Response:
        number_of_redirects = 0
        while number_of_redirects < max_redirects:
            resp = self._upload(package)

            if resp.status_code == requests.codes.OK:
                return resp
            if 500 <= resp.status_code < 600:
                number_of_redirects += 1
                logger.warning(
                    f'Received "{resp.status_code}: {resp.reason}"'
                    "\nPackage upload appears to have failed."
                    f" Retry {number_of_redirects} of {max_redirects}."
                )
            else:
                return resp

        return resp

    def package_is_uploaded(
        self, package: package_file.PackageFile, bypass_cache: bool = False
    ) -> bool:
        """Determine if a package has been uploaded to PyPI already.

        .. warning:: This does not support indexes other than PyPI or TestPyPI

        :param package:
            The package file that will otherwise be uploaded.
        :type package:
            :class:`~twine.package.PackageFile`
        :param bypass_cache:
            Force a request to PyPI.
        :type bypass_cache:
            bool
        :returns:
            True if package has already been uploaded, False otherwise
        :rtype:
            bool
        """
        # NOTE(sigmavirus24): Not all indices are PyPI and pypi.io doesn't
        # have a similar interface for finding the package versions.
        if not self.url.startswith((LEGACY_PYPI, WAREHOUSE, OLD_WAREHOUSE)):
            return False

        safe_name = package.safe_name
        releases = None

        if not bypass_cache:
            releases = self._releases_json_data.get(safe_name)

        if releases is None:
            url = f"{LEGACY_PYPI}pypi/{safe_name}/json"
            headers = {"Accept": "application/json"}
            response = self.session.get(url, headers=headers)
            if response.status_code == 200:
                releases = response.json()["releases"]
            else:
                releases = {}
            self._releases_json_data[safe_name] = releases

        packages = releases.get(package.version, [])

        for uploaded_package in packages:
            if uploaded_package["filename"] == package.basefilename:
                return True

        return False

    def release_urls(self, packages: List[package_file.PackageFile]) -> Set[str]:
        if self.url.startswith(WAREHOUSE):
            url = WAREHOUSE_WEB
        elif self.url.startswith(TEST_WAREHOUSE):
            url = TEST_WAREHOUSE
        else:
            return set()

        return {
            f"{url}project/{package.safe_name}/{package.version}/"
            for package in packages
        }

    def verify_package_integrity(self, package: package_file.PackageFile) -> None:
        # TODO(sigmavirus24): Add a way for users to download the package and
        # check its hash against what it has locally.
        pass
