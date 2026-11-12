"""Module containing the logic for the ``twine`` sub-commands.

The contents of this package are not a public API. For more details, see
https://github.com/pypa/twine/issues/194 and https://github.com/pypa/twine/issues/665.
"""

# Copyright 2013 Donald Stufft
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
import fnmatch
import glob
import os.path
from typing import Dict, List, NamedTuple

from twine import exceptions

__all__: List[str] = []

# Filename patterns used to classify the unstructured list of files passed on
# the command line. They are the single source of truth for what Twine treats
# as a signature or attestation, so other commands (e.g. the local attestation
# pre-check) can reuse them instead of re-deriving the matching rules.
SIGNATURE_GLOB = "*.asc"
ATTESTATION_GLOB = "*.*.attestation"


def _group_wheel_files_first(files: List[str]) -> List[str]:
    if not any(fname for fname in files if fname.endswith(".whl")):
        # Return early if there's no wheel files
        return files

    files.sort(key=lambda x: -1 if x.endswith(".whl") else 0)

    return files


def _find_dists(dists: List[str]) -> List[str]:
    uploads = []
    for filename in dists:
        if os.path.exists(filename):
            uploads.append(filename)
            continue
        # The filename didn't exist so it may be a glob
        files = glob.glob(filename)
        # If nothing matches, files is []
        if not files:
            raise exceptions.InvalidDistribution(
                "Cannot find file (or expand pattern): '%s'" % filename
            )
        # Otherwise, files will be filenames that exist
        uploads.extend(files)
    return _group_wheel_files_first(uploads)


class Inputs(NamedTuple):
    """Represents structured user inputs."""

    dists: List[str]
    signatures: Dict[str, str]
    attestations_by_dist: Dict[str, List[str]]


def _split_inputs(
    inputs: List[str],
) -> Inputs:
    """
    Split the unstructured list of input files provided by the user into groups.

    Three groups are returned: upload files (i.e. dists), signatures, and attestations.

    Upload files are returned as a linear list, signatures are returned as a
    dict of ``basename -> path``, and attestations are returned as a dict of
    ``dist-path -> [attestation-path]``.
    """
    signatures = {
        os.path.basename(i): i for i in fnmatch.filter(inputs, SIGNATURE_GLOB)
    }
    attestations = fnmatch.filter(inputs, ATTESTATION_GLOB)
    dists = [
        dist
        for dist in inputs
        if dist not in (set(signatures.values()) | set(attestations))
    ]

    attestations_by_dist = {
        dist: [
            a
            for a in attestations
            if attestation_matches_dist(os.path.basename(a), os.path.basename(dist))
        ]
        for dist in dists
    }

    return Inputs(dists, signatures, attestations_by_dist)


def attestation_matches_dist(attestation_basename: str, dist_basename: str) -> bool:
    """Return whether an attestation file is associated with a distribution.

    This is the exact association rule used while uploading: an attestation is
    attached to a distribution when its basename begins with the distribution's
    basename. Because the check is a plain prefix, a single attestation can be
    associated with more than one distribution when one distribution's
    basename is itself a prefix of another's.
    """
    return attestation_basename.startswith(dist_basename)
