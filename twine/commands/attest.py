"""Module containing the logic for ``twine attest``.

This is a local, offline pre-flight check. It never contacts a package index
and never requires credentials: it only inspects the files in a release
directory and reports how the ``*.*.attestation`` files would actually be
associated with distributions when ``twine upload --attestations`` runs.

The association rules are reused verbatim from the upload preparation flow in
:mod:`twine.commands`, so this reports exactly what an upload would do rather
than a re-implementation of the rules.
"""

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
import fnmatch
import logging
import os.path
from typing import Dict, List, NamedTuple

from rich import print

from twine import commands
from twine import exceptions

logger = logging.getLogger(__name__)


class AttestationMatch(NamedTuple):
    """The attestations associated with a single distribution."""

    dist: str
    attestations: List[str]


class AmbiguousAttestation(NamedTuple):
    """An attestation whose basename prefix-matches more than one distribution."""

    attestation: str
    dists: List[str]


class AttestationReport(NamedTuple):
    """The result of inspecting a release directory.

    All values store the paths exactly as Twine resolved them. Presentational
    code is responsible for shortening them to basenames.
    """

    dists: List[str]
    attestations: List[str]
    matches: List[AttestationMatch]
    orphan_dists: List[str]
    orphan_attestations: List[str]
    ambiguous: List[AmbiguousAttestation]

    @property
    def has_problems(self) -> bool:
        """Return whether the directory contains any orphan or ambiguous files."""
        return bool(self.orphan_dists or self.orphan_attestations or self.ambiguous)


def analyze(dists: List[str]) -> AttestationReport:
    """Inspect ``dists`` and classify every distribution and attestation.

    :param dists:
        Files or glob patterns, the same arguments accepted by
        ``twine upload`` (typically ``dist/*``).

    :return:
        An :class:`AttestationReport` describing the associations and any
        orphaned or ambiguously matched files.
    """
    resolved = commands._find_dists(dists)
    uploads, _, attestations_by_dist = commands._split_inputs(resolved)
    attestations = fnmatch.filter(resolved, commands.ATTESTATION_GLOB)

    matches = [
        AttestationMatch(dist=dist, attestations=list(attestations_by_dist[dist]))
        for dist in uploads
    ]

    matched_attestations = {
        attestation
        for match in matches
        for attestation in match.attestations
    }
    orphan_attestations = sorted(
        attestation
        for attestation in attestations
        if attestation not in matched_attestations
    )
    orphan_dists = sorted(
        dist for dist in uploads if not attestations_by_dist[dist]
    )

    ambiguous: List[AmbiguousAttestation] = []
    upload_basenames = {os.path.basename(dist): dist for dist in uploads}
    for attestation in attestations:
        attestation_basename = os.path.basename(attestation)
        matched_dists = [
            upload_basenames[dist_basename]
            for dist_basename in upload_basenames
            if commands.attestation_matches_dist(
                attestation_basename, dist_basename
            )
        ]
        if len(matched_dists) > 1:
            ambiguous.append(
                AmbiguousAttestation(
                    attestation=attestation, dists=sorted(matched_dists)
                )
            )

    return AttestationReport(
        dists=uploads,
        attestations=attestations,
        matches=matches,
        orphan_dists=orphan_dists,
        orphan_attestations=orphan_attestations,
        ambiguous=sorted(ambiguous, key=lambda item: item.attestation),
    )


def _print_report(report: AttestationReport) -> None:
    for match in report.matches:
        print(f"  {os.path.basename(match.dist)}")
        if match.attestations:
            for attestation in match.attestations:
                print(f"    <- {os.path.basename(attestation)}")
        else:
            print("    <- (no attestations)")

    for attestation in report.orphan_attestations:
        logger.warning(
            "Orphan attestation (no distribution basename matches it): %s",
            os.path.basename(attestation),
        )

    for dist in report.orphan_dists:
        logger.warning(
            "Distribution without any attestation: %s", os.path.basename(dist)
        )

    for item in report.ambiguous:
        logger.warning(
            "Attestation %s matches more than one distribution: %s",
            os.path.basename(item.attestation),
            ", ".join(os.path.basename(dist) for dist in item.dists),
        )


def attest(dists: List[str]) -> bool:
    """Check attestation-to-distribution associations and print the results.

    This performs no network access and does not read any repository
    credentials, so it is safe to run before every upload.

    :param dists:
        Files or glob patterns, the same arguments accepted by
        ``twine upload`` (typically ``dist/*``).

    :return:
        ``True`` if problems were found (orphaned files or ambiguous
        associations), otherwise ``False``.
    """
    try:
        report = analyze(dists)
    except exceptions.InvalidDistribution:
        logger.error("No files to check.")
        return True

    if not report.dists and not report.attestations:
        logger.error("No files to check.")
        return True

    print("Attestation associations:")
    _print_report(report)
    if report.has_problems:
        print(
            "[red]FAILED[/red]: attestation layout has problems; resolve the "
            "warnings above before uploading."
        )
        return True

    print(
        "[green]PASSED[/green]: every distribution has attestations and every "
        "attestation is associated with exactly one distribution."
    )
    return False


def main(args: List[str]) -> bool:
    """Execute the ``twine attest`` command.

    :param args:
        The command-line arguments.

    :return:
        The exit status of the ``attest`` command (non-zero when problems are
        found).
    """
    parser = argparse.ArgumentParser(prog="twine attest")
    parser.add_argument(
        "dists",
        nargs="+",
        metavar="dist",
        help="The distribution files to inspect, usually dist/* . This is a "
        "local, offline check: nothing is uploaded and no credentials are used.",
    )

    parsed_args = parser.parse_args(args)

    return attest(parsed_args.dists)
