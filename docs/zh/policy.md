# 策略即代码（Policy as Code）

pipguard 支持加载可选策略文件，用于在团队或组织范围内统一安全默认值。

默认路径：

```text
./pipguard.toml
```

也可以显式指定：

```bash
pipguard install --policy ./security/pipguard.toml -r requirements.txt
```

## 示例

```toml title="pipguard.toml"
[install]
require_hashes = true
allow_vcs_pinned = true
allow_direct_url_pinned = true
binary_only = "block"  # prompt | block | allow

[allowlist]
seed = ["my-internal-auth-lib", "corp-keyring"]

[intel]
feed = "https://example.org/pipguard-feed.json"
enforce = true

[osv]
enabled = true        # 查询 OSV.dev 已知 CVE（等价于 --check-vulns）
fail_on_vuln = false  # 为 true 时，命中已知 CVE 即阻断安装（等价于 --fail-on-vuln）
```

## 配置项

`[install]` 段：

- `require_hashes`（bool）：强制所有依赖都带 hash（hash-locked）。
- `allow_vcs_pinned`（bool）：仅当 VCS 依赖 pin 到 commit hash 时才允许。
- `allow_direct_url_pinned`（bool）：仅当直接 URL 依赖带 hash 片段时才允许。
- `binary_only`（string）：检测到纯二进制 wheel 时的行为：
  - `prompt`（默认）：保持 MEDIUM 行为（提示确认）。
  - `block`：阻断安装（exit 1）。
  - `allow`：不额外施加纯二进制阻断策略。

`[allowlist]` 段：

- `seed`（list[string]）：项目级种子允许列表，会与内置种子允许列表及 `--allow` 命令行参数合并。

`[intel]` 段：

- `feed`（string）：本地文件路径或 HTTPS URL，指向 JSON 格式的拦截名单。
- `enforce`（bool）：为 `true` 时，在扫描/安装前直接阻断名单中的包。

`[osv]` 段：

- `enabled`（bool）：查询 [OSV.dev](https://osv.dev) 已知 CVE（等价于 `--check-vulns`）。默认关闭——这是扫描期间 pipguard 唯一的外部网络请求。
- `fail_on_vuln`（bool）：为 `true` 时，命中已知 CVE 的包会导致安装失败（等价于 `--fail-on-vuln`），并隐含开启 `enabled`；否则仅作提示。

优先级：命令行参数 > 策略文件 > 内置默认值。

## 建议

- 在 CI 中强制使用同一份策略文件。
- 仅将确有业务必要的包加入 allowlist。
- 对策略改动走代码评审流程。
