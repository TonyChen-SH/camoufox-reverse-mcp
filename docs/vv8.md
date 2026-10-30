# VisibleV8 引擎日志

本包可读取标准 VisibleV8 `.log`，也可接收 Camoufox 原生引擎通过 stderr 发送的分段记录。参考格式依据 VisibleV8 固定版本 `068c617f28686f5c43d27c891803cd21510aa141`；`fixtures/engine.jsonl` 与 `fixtures/engine.log` 是同一组合成记录的两种表达。

## 运行

从安装后的仓库根目录运行：

```bash
mkdir -p traces
python -m camoufox_trace_mcp collect --engine --no-bindings --output traces/engine.jsonl --timeout 10 -- python fixtures/replay_engine.py
python -m camoufox_trace_mcp summarize traces/engine.jsonl --channel engine
python -m camoufox_trace_mcp events traces/engine.jsonl --channel engine --op get --property-name userAgent
python -m camoufox_trace_mcp scripts traces/engine.jsonl
python -m camoufox_trace_mcp script-source traces/engine.jsonl --index 0 --offset 0 --limit 4096
python -m camoufox_trace_mcp export-vv8 traces/engine.jsonl --output traces/vv8-export
python -m camoufox_trace_mcp summarize fixtures/engine.log
python -m camoufox_trace_mcp import-vv8 fixtures/engine.log --output traces/imported.jsonl --pid 41 --tid 51
```

采集文件与导出目录均必须不存在；重新运行前选择新路径。导出的 `.log` 按真实 `(pid,tid)` 分开，内容是完整原始记录并补上末尾换行，可交给匹配版本的官方 Go 后处理器。`manifest.json` 说明文件、ID 与状态；文件名中的时间是导出时间，不是事件时间。

读取原始文件时，若文件名符合 `vv8-TIMESTAMP-PID-TID-NAME.SEGMENT.log`，可保留其中的 PID/TID，否则保持未知。包装为传输 JSONL 时需要文件名中的 ID，或显式 `--pid/--tid`；后者标为 `identity_source:"import_options"`，不会伪称原生观测。

`import-vv8` 可接收多个显式文件名：

```bash
python -m camoufox_trace_mcp import-vv8 traces/vv8-export/*.log --output traces/segments.jsonl
python -m camoufox_trace_mcp import-vv8 traces/vv8-export/*.log --manifest traces/vv8-export/manifest.json --output traces/with-source-metadata.jsonl
```

Shell 在 CLI 侧展开输入；MCP 工具不提供路径 glob。导入按文件名 stem 分组，并按数字段号排序（2 在 10 前），拒绝缺失零段、缺段、重复段及不完整的非末段记录。每个线程的 isolate/源码注册表跨段连续，不补发 `$`。不同 stem 若复用了相同 PID/TID，必须分别导入，不能暗中合并成同一个原生线程。多线程导入保留文件名中的 ID；`--pid/--tid` 覆盖只允许用于单线程 cluster。

`--manifest` 显式恢复导出时附带的 `source_unavailable` 控制元数据；原始标准 VV8 文件本身不承载这些原因。manifest 的段文件清单必须与显式输入相同，且不能声明已知丢失。携带来源元数据时不能覆盖 PID/TID，避免把原生来源重新归属给其他线程。MCP 不读取任意 manifest 路径。

导出默认在累计字节超过 1,000,000,000 后，为下一条完整记录开启新段。记录不在中间拆开，单条长记录可能使一段超过阈值。可用 `export-vv8 ... --segment-bytes 4096` 设置小阈值；manifest 为各段保留段号、字节数、记录数、首末逻辑记录号、PID/TID 与 ID 来源。

`collect --engine` 向子进程传入 `CAMOUFOX_ENGINE_TRACE=1`。`--no-bindings` 将旧的 `CAMOUFOX_TRACE` 设置为 `0`；省略时两路可同时启用。采集器继续只保存带 `CAMOUFOX_TRACE ` 标记的 stderr 行，子进程 stdout 丢弃。实际浏览器启动脚本须继承这些环境变量并把浏览器 stderr 转发给采集器；Playwright 场景可沿用 README 的 `DEBUG=pw:browser DEBUG_COLORS=0`。

## 传输和状态

```json
{"schema":1,"event":"vv8","pid":123,"tid":456,"record":1,"part":0,"final":true,"data":"~0x1234"}
```

同样使用 `CAMOUFOX_TRACE ` 前缀。`pid/tid/record` 是正整数，`record` 是每线程逻辑记录计数，`part` 从零连续递增，`final` 为布尔值。`data` 是原始 VV8 记录的 ASCII 片段，完整记录不含最终换行。每个 JSON envelope 至多 4096 字节。按 `(pid,tid,record)` 严格重组，允许不同线程交错。

重复、逆序、缺段、缺记录、非法类型、非法转义、跨 isolate 的未知脚本引用和不完整结束都有明确状态。已知损坏或采集丢失时拒绝完整导出。完整尾部记录若在传输前整体消失，且没有后续计数或结束清单，仍可能无法识别；`no_known_loss` 不等于绝对无丢失。

引擎 `limit` 记录的原因会保留在摘要 `limits` 中。`channel:"engine",reason:"engine_record_cap"` 标为 `producer_event_cap`；其他引擎停止原因（例如 `engine_source_or_context`、`engine_value`、`engine_transport`），以及未知或缺失原因，标为 `producer_stopped`。两种状态都表示已知丢失，`integrity` 为 `incomplete`，分析退出码为 65，并拒绝完整导出。旧 binding `limit` 及其无效上限报告仍沿用 `producer_event_cap`。显式未知调用者的 `provenance_unknown` 自身不属于丢失。

`event:"source_unavailable"` 是来源可用性的控制记录，包含 `schema:1,channel:"engine",pid,tid,source_id,reason,filename,introduction_type,retrievable`。`source_id` 保留原生 `ScriptSource::id()` 的 uint32 值；filename/introduction_type 可为 null。可选 `scope:"source"|"introduction"`、`introduction_source_id` 及截断布尔值也原样保存。常见原因是 `source_missing`、`source_not_loaded` 和 `introduction_cycle`，后续原因不按固定枚举丢弃。

来源不可得不等于传输损坏：当前脚本可以保持 `!?`，完整 child 脚本可用 `$child:#?` 表示未知祖先；读取器不编造空源码。摘要的 `engine` 区、事件/脚本/源码/原始记录分页返回 `source_unavailable` 和捕获级 `source_provenance_complete`。`source_provenance_scope:"observed_engine_sources"` 明确其范围仅为已观察引擎记录的来源；binding-only 或没有任何真实 `$` 源码注册的 capture 为 false，true 也不表示所有脚本或浏览器 API 均被覆盖。该标志在存在不可用记录、未知调用者或未知祖先时为 false；即使后续成功取回源码，也保留历史不可用记录。有效控制记录自身不属于已知丢失，完整 raw 导出可保留 `!?/#?`，并在 manifest 附上控制元数据。控制记录或 manifest 不会替代 `$` 注册：真正未知的 `!ID`、缺失当前脚本或未知数字父 ID 仍是已知丢失并拒绝导入/完整导出。真正的 source load/OOM 等失败仍使用 `limit` 并按 `producer_stopped` 拒绝完整导出。

摘要、事件、raw 和源码页最多预览 100 条 `source_unavailable`，同时返回总数 `source_unavailable_count`；`source_unavailable_limited` 表示本响应没有包含全部控制记录。`get_trace_scripts` 使用同一请求的 offset/limit 分页不可用来源，并单独返回 `source_unavailable_matched`、`source_unavailable_offset`、`source_unavailable_limit` 和 `source_unavailable_next_offset`；依次使用该游标直至 null 可读全，原 scripts/matched/next_offset 仍只代表实际注册脚本。导出 manifest 使用全量模式保留全部控制记录，count 为总数、limited 为 false。

默认读入上限仍为 64 MiB、单行 1 MiB、事件 100000、传输记录 200000；一个重组的逻辑记录最多 64 MiB。`--max-input-bytes`、`--max-line-bytes`、`--max-events` 可显式调整读取限制。原生分段可承载超过单行限制的完整源码；直接导入极大的旧 VV8 源码行可能需要提高单行上限。达到上限会报告不完整，不静默截成完整日志。

## 记录解释

支持 `~` isolate、`@` 文档 href/安全令牌、`$` 完整源码与 URL/eval 父来源、`!` 活跃脚本，以及 `g/s/c/n` 操作。`@?`、`!?` 和未知 eval 父来源保持未知。Java `j` 扩展保留原始记录并明确标记，桌面 API 统计不将它伪装为标准调用。

显式 `!?` 后的调用是合法的未知调用者：记录 `provenance_unknown`，保留 `script_id/source:null`，不视为传输损坏，也不阻止导出。缺少 isolate/脚本切换或引用未注册的 `!ID` 仍是完整性错误；未知调用者不会沿用前一个脚本的来源。

`g/s/c/n` 转为 `channel:"engine"` API 事件，分别使用 `op:get/set/call/construct`。脚本来源保留 `pid/tid/isolate/script_id`、`source_offset` 与完整注册源码。原始 `vv8_raw` 保持原样，`vv8_fields` 及参数摘要中的 `raw` 是解码转义后的字段 token；对象、函数、symbol 等有损表达不能恢复成完整 JS 值。API 名由接收者类名和成员/函数文本构成；原始字段始终可查。

桌面 VV8 的 `g/c/n` 没有返回值；本包使用 `result:{"type":"unavailable","reason":"not_observed"}`、`threw:null`。`s` 保留赋入值，仍不宣称赋值成功。负零保留符号。普通 WebIDL 记录继续保留实际 result/threw/duration/scope，未标 channel 的记录按 `binding` 处理。摘要和比较以通道区分 API 与调用位置，避免将两路重复计数为同一类观测。

事件 offset 使用 UTF-16 码元；行、列由对应注册源码计算，为一基 UTF-16 位置。支持 CRLF、CR、LF、U+2028、U+2029 和非 BMP 字符。未知或越界 offset 不生成猜测位置。`get_trace_script_source` 的分页 offset 则使用 Unicode 码点，并在结果中声明单位。

合法 JS 字符串与源码可包含孤立的 UTF-16 代理码元。本包在内存中完整保留，不替换为 U+FFFD，也不标成丢失。脚本元数据的 `source_sha256_encoding:"utf-8-surrogatepass"` 说明既有 `source_sha256` 的字节编码：正常 Unicode 使用标准 UTF-8，孤立代理码元保留其三字节 surrogatepass 表达。该 hash 不冒充官方 Go 的 hash。固定版本 Go [`splitFields`](https://github.com/wspr-ncsu/visiblev8/blob/068c617f28686f5c43d27c891803cd21510aa141/post-processor/core/core.go#L20) 会丢弃单个孤立代理码元，还可能跨字段组合；不是规范的 UTF-16 替换解码。例如源码 `A\ud800B` 在官方 `-annotate` 中按 `AB` 哈希。需要官方聚合语义时，应导出未改变的 ASCII 原始记录并由该版本后处理器执行。

## MCP

原四个工具均可分析包含引擎记录的 capture。`get_trace_events` 支持 channel、op、API、URL、PID/TID、isolate、script_id、property_name、source_offset 和分页。engine 没有异常结果，因此 `threw:false` 不会把未知结果当成成功。

新增只读工具：`get_trace_scripts` 返回脚本注册与可用于查询的零基 `index`；`get_trace_script_source` 按 index 分页取源码；`get_trace_raw_records` 返回按线程分组的已重组原始记录。源码全文保存在 capture 中，元数据列表不重复内嵌全文。导出、包装只在显式 CLI 命令提供，MCP 工具不启动进程或写入任意路径。

七个 MCP 工具的返回值统一处理不可直接编码为 UTF-8 的字符串。只有包含孤立代理码元的字符串改为 `{"encoding":"utf16le_base64","data":"ANg=","escaped":"\"\\ud800\""}`；`data` 是无 BOM 的完整 UTF-16LE 字节，`escaped` 是可用 JSON 解码恢复的 ASCII 字符串字面量。正常 Unicode 字符串保持原接口。此规则也适用于 URL、属性名、参数和解码后的 symbol token，不仅是源码。若对象键含孤立代理码元，该对象使用 `{"encoding":"utf16_keyed_entries","entries":[{"key":...,"value":...}]}`，键和值递归应用同一规则，不丢弃或覆盖键。源分页 offset/limit、UTF-16 事件 offset 与完整源码 hash 均按原始文本计算；原始 ASCII VV8 记录不变。

原始 VV8 格式兼容不等于原生浏览器的所有监控路径均已验证。浏览器测试还应检查热循环、Worker、eval、构造器及语义不变；官方 Go 后处理器的各模式另有 IDL、数据库、规则或实体数据要求。
