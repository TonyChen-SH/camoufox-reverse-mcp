# Camoufox Reverse MCP

本地采集 Camoufox 原生 API 日志，按脚本位置查看调用和返回值摘要，并通过只读 MCP 工具分析。配套浏览器源码：[camoufox-reverse](https://github.com/TonyChen-SH/camoufox-reverse)。Python 模块名为 `camoufox_trace_mcp`，避免与其他同名 Camoufox 工具混淆。

**已通过 Linux x86_64 真实监控浏览器与 MCP SDK stdio 联调。** [下载监控浏览器并校验安装包](https://github.com/TonyChen-SH/camoufox-reverse#下载与使用)，再按下面的步骤采集。普通 Camoufox 安装包不输出这些原生事件。离线 `fixtures/` 是合成测试记录。

## 快速运行

Python 3.11+。从本仓库根目录运行以下命令；离线分析只用标准库，无须安装 MCP SDK：

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m camoufox_trace_mcp summarize fixtures/pilot.jsonl
python -m camoufox_trace_mcp events fixtures/pilot.jsonl --api WebGLRenderingContext.getParameter --limit 20
python -m camoufox_trace_mcp compare fixtures/pilot.jsonl fixtures/pilot.jsonl
```

摘要包括 API 次数、脚本 URL/行列、调用位置聚合、返回值摘要变体、异常与截断情况。`compare` 输出调用计数及调用位置结果摘要的差异；它不匹配同一个逻辑调用，也不把差异认定为风控原因。对象只含类名、字符串可能截断，相同摘要不能证明原值相同。

数值负零会保留符号；返回摘要按计数与规范 JSON 键稳定排序，相同结果集合不会因线程完成顺序或进程编号改变而产生差异。

## 采集

POSIX 系统可显式启动一个本地命令，收集 stderr 中带 `CAMOUFOX_TRACE ` 标记的事件，写入新 JSONL 文件。拒绝覆盖已有文件，不使用 shell。这个功能仅在 CLI 提供，MCP 不执行进程。

```bash
mkdir -p traces
python -m camoufox_trace_mcp collect --output traces/demo.jsonl --timeout 10 -- python fixtures/replay.py
python -m camoufox_trace_mcp summarize traces/demo.jsonl
```

`fixtures/replay.py` 回放合成事件并夹入普通日志，用于验证采集链路。真实采集时把 `--` 后的命令换成使用已编译监控浏览器的启动程序。采集器自动传入 `CAMOUFOX_TRACE=1`；需要栈时在外层设置 `CAMOUFOX_TRACE_STACK=1`。普通 stdout 丢弃，普通 stderr 不写入 trace，结果 JSON 单独输出到 CLI stdout。

接入现有 Camoufox 脚本时，先把脚本中的 `executable_path` 指向监控版的 `bin/camoufox-bin`。Playwright 驱动会接管浏览器 stderr，所以采集 Python 脚本还需打开驱动的浏览器日志，并关闭日志颜色以保留 JSON 行：

```bash
DEBUG=pw:browser DEBUG_COLORS=0 CAMOUFOX_TRACE_STACK=1 \
python -m camoufox_trace_mcp collect --output traces/session.jsonl --timeout 180 -- python your_script.py
```

这条命令从当前目录运行你的 `your_script.py`。如果脚本向 Camoufox 显式传入 `env`，应把继承的环境合并进去，让 `CAMOUFOX_TRACE` 等设置进入实际浏览器进程。脚本正常关闭浏览器后，使用 `summarize traces/session.jsonl` 找到脚本位置，再用 `events` 查询该 API 的原始参数、返回摘要和栈。

浏览器对应的 Python 启动器验证版本为 Camoufox `b6205b0` 与 Playwright `1.62.0`。在当前虚拟环境中安装同一版本：

```bash
git clone https://github.com/daijro/camoufox.git ../camoufox-launcher
git -C ../camoufox-launcher checkout b6205b0ee1e4c2e8e4bb9eb0e084472028a9c6a3
python -m pip install 'playwright==1.62.0' -e ../camoufox-launcher/python
python ../camoufox-launcher/python/scripts/pin-fpgen-model.py
```

不使用自动化脚本时，也可直接采集浏览器；在窗口内复现问题并正常关闭浏览器后分析：

```bash
CAMOUFOX_TRACE_STACK=1 python -m camoufox_trace_mcp collect \
  --output traces/manual.jsonl --timeout 300 -- /absolute/path/bin/camoufox-bin https://example.com
python -m camoufox_trace_mcp summarize traces/manual.jsonl
python -m camoufox_trace_mcp events traces/manual.jsonl --api HTMLCanvasElement.toDataURL --limit 20
```

超时、中断、非零/信号退出、无法启动、输出上限和 stderr 未排空都会保存在 `collection` 记录。POSIX 进程组负责回收仍在同组内的子进程；自行脱离进程组的程序不在这个保证内。关闭浏览器后采集才正常结束；到达 `--timeout` 会终止进程并返回 124。

CLI 退出码：0 为已观察到事件且没有已知采集丢失，3 为无事件，65 为已知不完整/格式损坏，2 为参数或文件错误；子进程失败保留其非零状态（超时 124、中断 130、启动失败 127）。0 不代表网站无检测。

## MCP 接入

MCP 使用固定版本 SDK；锁文件固定开发验证所用的依赖版本。Python 3.12 / Linux 为 CI 环境。文件访问与 stdio 管道实现需要 POSIX。

```bash
python -m pip install -r requirements-mcp.lock
python -m pip install --no-deps -e .
mkdir -p traces
cp fixtures/pilot.jsonl traces/pilot.jsonl
python -m camoufox_trace_mcp serve --trace-root "$PWD/traces"
```

最后一条命令等待 MCP 客户端输入。支持 stdio 的客户端配置示例（替换绝对路径）：

```json
{
  "mcpServers": {
    "camoufox-trace": {
      "command": "/absolute/path/camoufox-reverse-mcp/.venv/bin/python",
      "args": ["-m", "camoufox_trace_mcp", "serve", "--trace-root", "/absolute/path/camoufox-reverse-mcp/traces"]
    }
  }
}
```

四个只读工具：

| 工具 | 用途 |
|---|---|
| `list_traces` | 分页列出根目录下 JSONL 文件 |
| `summarize_trace` | 聚合 API、脚本位置、结果摘要和采集状态 |
| `get_trace_events` | 按 API、URL、PID、异常筛选并分页 |
| `compare_traces` | 比较两份日志的观察差异并保留双方限制 |

传入相对 `.jsonl` 路径，例如 `pilot.jsonl`。拒绝绝对路径、`..`、符号链接与特殊文件；逐层使用目录文件描述符和 `O_NOFOLLOW` 打开文件。MCP 不访问任意文件、不打开浏览器、不执行网页脚本。stdio 使用事件循环管道并复用 SDK 的协议处理，避免阻塞文件读取依赖工作线程唤醒。

## 协议与解释边界

支持原生 `schema: 1` 的 `meta`、`api`、`limit`，既可读原始 stderr 标记，也可读裸 JSONL。序号在原生调用入口分配，退出时写出，允许乱序；重复或缺号标为不完整。直接调用列号由生产者 metadata 声明，当前 pilot 为 `one-origin`，读取器不自行偏移。

最多读取 64 MiB，单行 1 MiB、保留 100000 个事件和处理 200000 个记录；达到上限会报告状态。每个调用位置最多展示 10 种返回摘要和 3 个事件位置示例，超出时标记。`no_known_loss` 仅说明没有发现这些检查能识别的丢失；传输尾部丢失仍可能无法识别。

- `no_events`、`no_producer_metadata`、格式错误、未知 schema、上限、截断和子进程退出均会显示；空日志不证明页面没有检测。
- URL/行列可为空；没有 frame、Worker、request ID，不能从 PID 或 realm 类名补造。栈与值只保留日志实际提供的内容。
- 旧 PropertyTracer 数据须加 `--legacy`；其 `s` 为原生源码位置，不能作为 JS 位置，`v` 也不视为调用时返回值。
- API 调用不等于风控命中。IP、账号、TLS、HTTP、行为和服务端判定无法从这份日志直接还原。

## 测试

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m unittest discover -s tests_mcp -v
```

第二组需要锁文件中的 SDK，使用真实 stdio 客户端检查初始化、四个工具、结构化结果和路径拒绝。第一组覆盖独立 CLI、格式与序号、返回摘要差异、采集退出/超时及文件根目录约束；不需要浏览器。CI 缺少依赖会失败，不静默跳过。

当前为 40 个核心测试和 1 个真实 SDK stdio 集成测试。另有 [真实浏览器联调工作流](https://github.com/TonyChen-SH/camoufox-reverse/actions/runs/40895409218)：覆盖全部 16 个原生入口、22 条页面测试调用，并用四个 MCP 工具读取实际 JSONL，验证 Worker、负零与事件重排比较。[原始证据与报告](https://github.com/TonyChen-SH/camoufox-reverse/actions/runs/40895409218/artifacts/12906343755) 可下载核对；上游相关守卫 8/8、build-tester 1048/1048 通过。这些测试不等于目标网站风控原因已确定。

MIT License，见 [LICENSE](LICENSE)。
