# Twine 上传超时后的重试诊断（值班维护说明）

发布客户端超时后，能不能**原样重试**取决于请求死在哪一个阶段。本文配合
`examples/timeout_diagnosis.py`（用假的请求端运行，不访问真实包仓库）给出每个
阶段可观测的证据、仍然不确定的事项和建议动作。

## 相关机制速览

- `twine/utils.py` 的 `make_requests_session()`：urllib3 层重试
  `allowed_methods=["GET"]`，**POST 上传不会被底层自动重试**（包括连接错误）。
- `twine/repository.py` 的 `Repository.upload()`：应用层只对 **5xx 响应**重试，
  最多 5 次，每次重发整个包体；对异常（超时、断连）不重试。
- `twine/commands/upload.py` 的 `skip_upload()`：仅在 `--skip-existing` 下，
  把 409 或「400 + already exist」视为"已存在"而跳过。
- `twine/utils.py` 的 `check_status_code()`：其余非 2xx 一律抛 `HTTPError`。
- `Repository.package_is_uploaded()` 只对 PyPI/TestPyPI 生效，其他 index 的
  `--skip-existing` 完全依赖上传响应里的 400/409 判定。

## 分阶段诊断表

### 阶段 1：连接建立前（请求未发出）

- 典型异常：`requests.exceptions.ConnectTimeout`（诊断示例场景 1）。
- 可观测证据：进度条未出现或 0%；异常类型为 `ConnectTimeout`；示例中
  服务端收到字节 = 0。
- 仍不确定：极少数情况下 TCP 已建连、TLS 已握手，但请求行尚未发完——
  服务端访问日志里可能有一条不完整的连接记录，但不可能已处理上传。
- 建议动作：**可原样重试**。

### 阶段 2：请求体传输中断开

- 典型异常：`ConnectionError`（进度条卡在 0%–100% 之间）。
- 可观测证据：进度条最后百分比 < 100%；示例场景 2 中服务端已收到全部字节
  这一事实**客户端看不到**，只能看到异常。
- 仍不确定：服务端是否收齐了 body、是否已落库。客户端侧无任何证据。
- 建议动作：按阶段 3 处理。

### 阶段 3：等待响应时断开（结果未知）

- 典型异常：`ReadTimeout`，或 `ConnectionError`（`RemoteDisconnected`，
  进度条已到 100% 之后）。
- 可观测证据：进度条 100%；异常发生在等待响应期间；**没有任何响应对象**，
  因此 `skip_upload` / `check_status_code` 都无从介入。
- 仍不确定：上传可能已成功提交（示例场景 2 中 `服务端已提交=True`，但
  客户端无法得知），也可能被丢弃。**不要直接原样重试**：若第一次已成功，
  裸重试会得到 400，部分 index 还会把文件名永久占用。
- 建议动作（任选其一查证后再决定）：
  1. 用 `twine upload --skip-existing` 重试同一个文件作为**探针**
     （示例场景 2b）：若返回「already exists」被跳过，说明第一次已成功，
     无需再发；若返回 200，说明第一次未生效，此次即补发成功。
  2. 对 PyPI/TestPyPI，先查 `https://pypi.org/pypi/<项目>/json` 或项目页面
     确认版本是否已出现。
  3. 有服务端访问权限时，查 index 的上传日志/存储。

### 阶段 4：收到了明确响应（结果已知）

- 可观测证据：HTTP 状态码和 reason，日志中有
  `Response from <url>: <status> <reason>`。
- 判定与动作：
  - **400 + "already exist" / 409**：文件已在 index 上（说明此前某次"失败"
    其实成功了）。带 `--skip-existing` 时自动跳过；否则报错但无需重发。
  - **401/403**：凭证或权限问题。**不要原样重试**，先修凭证。
  - **其他 4xx**（如 413、元数据错误）：请求本身有问题，原样重试无意义。
  - **5xx**：Twine 已自动重试 5 次（示例场景 4，每次重发整个包体）仍失败
    才抛错，属于服务端故障，可稍后原样重试。

## 运行诊断示例

```bash
python examples/timeout_diagnosis.py
```

输出对每个场景给出：阶段、判定（`SAFE_TO_RETRY_AS_IS` /
`UNKNOWN_MUST_VERIFY` / `DO_NOT_RETRY_AS_IS` / `ALREADY_ON_INDEX` /
`SUCCESS`）、以及假 index 侧的证据（请求次数、收到字节数、是否已提交）。
判定逻辑复用了 `twine.commands.upload.upload()` 的真实分支顺序。

## 局限

- 假适配器在 `requests` 层注入行为，无法模拟 TLS 握手失败、代理截断、
  半开连接等更底层的形态；这些形态在客户端仍归类到上表某个阶段。
- 「服务端已提交」是示例为了演示不确定性而记录的状态，真实排障时客户端
  拿不到这个信息，必须靠阶段 3 的查证手段。
