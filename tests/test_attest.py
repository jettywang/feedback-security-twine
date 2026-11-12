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

import pretend
import pytest

from twine.commands import attest


def _touch(tmp_path, name):
    path = tmp_path / name
    path.write_text("")
    return str(path)


def test_analyze_fully_aligned(tmp_path):
    sdist = _touch(tmp_path, "demo-1.0.0.tar.gz")
    wheel = _touch(tmp_path, "demo-1.0.0-py3-none-any.whl")
    sdist_att = _touch(tmp_path, "demo-1.0.0.tar.gz.publish.attestation")
    wheel_att = _touch(
        tmp_path, "demo-1.0.0-py3-none-any.whl.publish.attestation"
    )

    report = attest.analyze([str(tmp_path) + "/*"])

    assert report.dists == [wheel, sdist]
    assert report.attestations == sorted([sdist_att, wheel_att])
    assert {match.dist: match.attestations for match in report.matches} == {
        wheel: [wheel_att],
        sdist: [sdist_att],
    }
    assert report.orphan_dists == []
    assert report.orphan_attestations == []
    assert report.ambiguous == []
    assert report.has_problems is False


def test_analyze_multiple_attestations_per_dist(tmp_path):
    wheel = _touch(tmp_path, "demo-1.0.0-py3-none-any.whl")
    build_att = _touch(
        tmp_path, "demo-1.0.0-py3-none-any.whl.build.attestation"
    )
    publish_att = _touch(
        tmp_path, "demo-1.0.0-py3-none-any.whl.publish.attestation"
    )

    report = attest.analyze([str(tmp_path) + "/*"])

    assert report.matches[0].attestations == [build_att, publish_att]
    assert report.has_problems is False


def test_analyze_orphan_attestation(tmp_path):
    _touch(tmp_path, "demo-1.0.0.tar.gz")
    _touch(tmp_path, "demo-1.0.0.tar.gz.publish.attestation")
    orphan = _touch(tmp_path, "other-2.0.0.tar.gz.publish.attestation")

    report = attest.analyze([str(tmp_path) + "/*"])

    assert report.orphan_attestations == [orphan]
    assert report.has_problems is True


def test_analyze_distribution_without_attestation(tmp_path):
    _touch(tmp_path, "demo-1.0.0.tar.gz")
    wheel = _touch(tmp_path, "demo-1.0.0-py3-none-any.whl")
    _touch(tmp_path, "demo-1.0.0-py3-none-any.whl.publish.attestation")

    report = attest.analyze([str(tmp_path) + "/*"])

    assert report.orphan_dists == [str(tmp_path / "demo-1.0.0.tar.gz")]
    # The wheel is still correctly associated and not reported as an orphan.
    assert wheel not in report.orphan_dists
    assert report.has_problems is True


def test_analyze_ambiguous_prefix_match(tmp_path):
    short_wheel = _touch(tmp_path, "demo-1.0.0-py3-none-any.whl")
    long_wheel = _touch(
        tmp_path, "demo-1.0.0-py3-none-any.whl.bak"
    )
    shared_att = _touch(
        tmp_path, "demo-1.0.0-py3-none-any.whl.bak.publish.attestation"
    )

    report = attest.analyze([str(tmp_path) + "/*"])

    assert len(report.ambiguous) == 1
    ambiguous = report.ambiguous[0]
    assert ambiguous.attestation == shared_att
    assert ambiguous.dists == sorted([short_wheel, long_wheel])
    # The shared attestation is associated with both distributions, mirroring
    # exactly what ``twine upload`` would do.
    associations = {
        match.dist: match.attestations for match in report.matches
    }
    assert associations[short_wheel] == [shared_att]
    assert associations[long_wheel] == [shared_att]
    assert report.has_problems is True


def test_analyze_uses_real_matching_rule(tmp_path, monkeypatch):
    """The pre-check must classify files with the same rule as the upload."""
    real_split_inputs = attest.commands._split_inputs
    split_stub = pretend.call_recorder(real_split_inputs)
    monkeypatch.setattr(attest.commands, "_split_inputs", split_stub)

    _touch(tmp_path, "demo-1.0.0.tar.gz")
    _touch(tmp_path, "demo-1.0.0.tar.gz.publish.attestation")

    attest.analyze([str(tmp_path) + "/*"])

    assert len(split_stub.calls) == 1


def test_attest_passes(tmp_path, capsys, caplog):
    _touch(tmp_path, "demo-1.0.0.tar.gz")
    _touch(tmp_path, "demo-1.0.0.tar.gz.publish.attestation")

    assert attest.attest([str(tmp_path) + "/*"]) is False

    out = capsys.readouterr().out
    assert "PASSED" in out
    assert "demo-1.0.0.tar.gz" in out
    assert not caplog.records


def test_attest_fails_on_problems(tmp_path, capsys, caplog):
    orphan = _touch(tmp_path, "other-2.0.0.tar.gz.publish.attestation")

    assert attest.attest([str(tmp_path) + "/*"]) is True

    out = capsys.readouterr().out
    assert "FAILED" in out
    assert any(
        "Orphan attestation" in record.message and orphan.endswith(
            record.args[0]
        )
        for record in caplog.records
        if record.levelno == logging.WARNING
    )


def test_attest_no_files(tmp_path, caplog):
    assert attest.attest([str(tmp_path) + "/*"]) is True
    assert caplog.record_tuples == [
        ("twine.commands.attest", logging.ERROR, "No files to check.")
    ]


def test_main(monkeypatch):
    attest_result = pretend.stub()
    attest_stub = pretend.call_recorder(lambda dists: attest_result)
    monkeypatch.setattr(attest, "attest", attest_stub)

    assert attest.main(["dist/*"]) == attest_result
    assert attest_stub.calls == [pretend.call(["dist/*"])]


def test_main_rejects_missing_arguments():
    with pytest.raises(SystemExit):
        attest.main([])
