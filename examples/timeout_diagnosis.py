"""Diagnose ``twine upload`` timeout outcomes without a real package index.

A scripted ``requests`` transport adapter stands in for the index, so each
failure stage can be reproduced deterministically and classified:

1. request never sent (connect timeout)
2. connection dropped while waiting for the response
3. explicit rejection (an HTTP error response came back)

The script drives the real code paths in ``twine.repository.Repository``,
``twine.commands.upload.skip_upload`` and ``twine.utils.check_status_code``
so the observable behavior matches production.

Run from the repository root:

    python examples/timeout_diagnosis.py

No network access is performed.
"""

import pathlib
import sys
from dataclasses import dataclass, field

import requests
from requests.adapters import BaseAdapter

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from twine import package as package_file
from twine import repository, utils
from twine.commands.upload import skip_upload

FIXTURE = (
    pathlib.Path(__file__).resolve().parent.parent
    / "tests"
    / "fixtures"
    / "twine-4.0.2-py3-none-any.whl"
)
FAKE_URL = "https://index.example.invalid/legacy/"


class FakeIndexAdapter(BaseAdapter):
    """Scripted stand-in for a package index.

    One behavior is consumed per POST:

    ``connect_timeout``
        Raise before the request body is read: nothing left the client.
    ``drop_after_commit``
        Read the whole body, record the upload server-side, then drop the
        connection without a response.
    ``flaky_503_then_ok``
        Return 503 until ``self.ok_after`` requests have been seen.
    ``reject_403``
        Return an explicit authentication refusal.
    ``ok_or_400_if_exists``
        Return 400 "already exists" if the file was committed before,
        otherwise commit it and return 200.
    """

    def __init__(self, script, ok_after=0):
        super().__init__()
        self.script = list(script)
        self.ok_after = ok_after
        self.requests_seen = 0
        self.bytes_received = 0
        self.committed = False

    def send(self, request, **kwargs):
        self.requests_seen += 1
        if len(self.script) > 1:
            behavior = self.script.pop(0)
        elif self.script:
            behavior = self.script[0]
        else:
            behavior = "ok_or_400_if_exists"

        if behavior == "connect_timeout":
            raise requests.exceptions.ConnectTimeout(
                f"HTTPSConnectionPool: connect timed out for {request.url}"
            )

        self._drain(request)

        if behavior == "drop_after_commit":
            self.committed = True
            raise requests.exceptions.ConnectionError(
                "('Connection aborted.', "
                "RemoteDisconnected('Remote end closed connection without "
                "response'))"
            )
        if behavior == "flaky_503_then_ok":
            if self.requests_seen <= self.ok_after:
                return self._respond(request, 503, "Service Unavailable")
            self.committed = True
            return self._respond(request, 200, "OK")
        if behavior == "reject_403":
            return self._respond(
                request, 403, "Invalid or non-existent authentication"
            )
        # ok_or_400_if_exists
        if self.committed:
            return self._respond(
                request,
                400,
                "File already exists",
                text="File already exists. See "
                "https://pypi.org/help/#file-name-reuse for more information.",
            )
        self.committed = True
        return self._respond(request, 200, "OK")

    def _drain(self, request):
        body = request.body
        if hasattr(body, "read"):
            while body.read(65536):
                pass
            self.bytes_received += getattr(body, "bytes_read", 0)

    @staticmethod
    def _respond(request, status, reason, text=""):
        resp = requests.Response()
        resp.status_code = status
        resp.reason = reason
        resp.url = request.url
        resp.request = request
        resp._content = text.encode()
        return resp

    def close(self):
        pass


@dataclass
class Outcome:
    stage: str
    verdict: str
    detail: str
    evidence: dict = field(default_factory=dict)


def attempt_upload(repo, package, skip_existing):
    """Mirror the decision logic in ``twine.commands.upload.upload()``."""
    try:
        resp = repo.upload(package)
    except requests.exceptions.ConnectTimeout as exc:
        return Outcome(
            stage="connect",
            verdict="SAFE_TO_RETRY_AS_IS",
            detail=f"ConnectTimeout: {exc}",
        )
    except (
        requests.exceptions.ReadTimeout,
        requests.exceptions.ConnectionError,
    ) as exc:
        return Outcome(
            stage="awaiting_response",
            verdict="UNKNOWN_MUST_VERIFY",
            detail=f"{type(exc).__name__}: {exc}",
        )

    if skip_upload(resp, skip_existing, package):
        return Outcome(
            stage="response_received",
            verdict="ALREADY_ON_INDEX",
            detail=f"{resp.status_code} {resp.reason}",
        )
    try:
        utils.check_status_code(resp, verbose=False)
    except requests.HTTPError:
        return Outcome(
            stage="response_received",
            verdict="DO_NOT_RETRY_AS_IS",
            detail=f"{resp.status_code} {resp.reason}",
        )
    return Outcome(
        stage="response_received",
        verdict="SUCCESS",
        detail=f"{resp.status_code} {resp.reason}",
    )


def make_repo(adapter):
    repo = repository.Repository(
        FAKE_URL, username="oncall", password="token", disable_progress_bar=True
    )
    repo.session.mount("https://", adapter)
    return repo


def report(title, outcome, adapter):
    print(f"=== {title} ===")
    print(f"  阶段: {outcome.stage}")
    print(f"  判定: {outcome.verdict}")
    print(f"  细节: {outcome.detail}")
    print(
        "  证据: "
        f"请求次数={adapter.requests_seen} "
        f"服务端收到字节={adapter.bytes_received} "
        f"服务端已提交={adapter.committed}"
    )
    print()


def main():
    package = package_file.PackageFile.from_filename(str(FIXTURE), comment=None)

    # 1. Connect timeout: nothing was sent, retrying as-is is safe.
    adapter = FakeIndexAdapter(["connect_timeout"])
    outcome = attempt_upload(make_repo(adapter), package, skip_existing=False)
    report("场景 1: 连接阶段超时（请求未发出）", outcome, adapter)

    # 2. Connection dropped while awaiting the response. The fake index
    #    *did* commit the upload, but the client cannot tell.
    adapter = FakeIndexAdapter(["drop_after_commit", "ok_or_400_if_exists"])
    outcome = attempt_upload(make_repo(adapter), package, skip_existing=False)
    report("场景 2: 等待响应时连接断开（结果未知）", outcome, adapter)

    # 2b. Probe: retrying with --skip-existing turns the index's
    #     "already exists" refusal into proof the first attempt landed.
    outcome = attempt_upload(make_repo(adapter), package, skip_existing=True)
    report("场景 2b: 用 --skip-existing 重试作为探针", outcome, adapter)

    # 3. Explicit refusal: a response came back, the outcome is known.
    adapter = FakeIndexAdapter(["reject_403"])
    outcome = attempt_upload(make_repo(adapter), package, skip_existing=False)
    report("场景 3: 服务端明确拒绝（403 凭证无效）", outcome, adapter)

    # 4. 5xx: Repository.upload retries internally (up to 5 times),
    #    re-sending the whole body each time.
    adapter = FakeIndexAdapter(["flaky_503_then_ok"], ok_after=2)
    outcome = attempt_upload(make_repo(adapter), package, skip_existing=False)
    report("场景 4: 5xx 触发 Twine 应用层重试后成功", outcome, adapter)


if __name__ == "__main__":
    main()
