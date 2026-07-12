# 使用说明

![pipguard 演示](assets/demo.gif)

## 基本用法

### 安装单个包

```bash
pipguard install requests
```

pipguard 会先下载并扫描，再从已扫描的本地缓存安装。默认输出采用摘要优先：
展开 `CRITICAL` / `HIGH` / `MEDIUM` 详情，`LOW` 仅显示包级计数，`CLEAN`
只计入汇总。

### 从 requirements.txt 安装

```bash
pipguard install -r requirements.txt
```

## 支持的依赖来源

pipguard 只能对它下载并检查过的制品保证扫描承诺，因此只接受能解析为
**固定、可校验制品** 的依赖项，其余的会被拒绝（退出码 2）：

| 依赖写法 | 是否接受 |
|----------|----------|
| PyPI 版本约束（`requests==2.31.0`、`numpy>=1.24`） | ✅ |
| hash 锁定（`pkg==1.0 --hash=sha256:…`） | ✅ |
| pin 到 commit 的 VCS（`git+https://…@<commit-sha>`） | ✅（必须 pin commit SHA） |
| 带 hash 的直接 URL（`pkg @ https://…/pkg-1.0.whl#sha256=…`） | ✅（必须带 hash） |
| 可编辑安装（`-e .`） | ⏭️ 跳过并告警 |
| 未 pin 的 VCS（`git+https://…`，无 commit） | ❌ 退出码 2 |
| 不带 hash 的直接 URL | ❌ 退出码 2 |
| 本地路径（`./pkg`、`/abs/pkg`） | ❌ 退出码 2 |

加 `--require-hashes`（或策略文件 `[install] require_hashes = true`）可要求
**每一项** 都带 hash，等同于 `pip install --require-hashes` 的完整性保证。
可通过策略键 `allow_vcs_pinned` / `allow_direct_url_pinned` 完全禁用 VCS / 直接 URL 依赖。

### 非交互模式（CI 推荐）

```bash
pipguard install --yes -r requirements.txt
```

## 已知 CVE 查询（osv.dev）

pipguard 的 AST 扫描检测的是 *可疑行为*；`--check-vulns` 会额外查询
[osv.dev](https://osv.dev)，补上 *已公开漏洞* 这一互补信号：

```bash
pipguard install --check-vulns requests
```

已知 CVE 会显示在独立的 **Known CVEs (osv.dev)** 区块——即使包在行为上被判为
CLEAN 也会显示。默认仅提示、不阻断；加 `--fail-on-vuln`（隐含 `--check-vulns`）
可将其变为硬性门禁（退出码 1）。

!!! note "opt-in 网络请求"
    OSV 查询是扫描期间 pipguard 唯一的外部请求，因此是 opt-in 的。不加
    `--check-vulns`（或策略文件 `[osv] enabled = true`）时 pipguard 保持离线。
    查询是尽力而为的——osv.dev 不可达时会静默降级，行为扫描照常进行。

## 常用参数

- `--yes` / `-y`：自动确认 MEDIUM/LOW 风险（适合 CI）
- `--allow pkg`：将指定包 HIGH 降级为 MEDIUM（可重复）
- `--force`：对指定包绕过所有检查（谨慎使用）
- `--allow-sdist`：允许 sdist（默认不允许；会执行任意代码）
- `--require-hashes`：要求所有 requirements 条目都带 hash
- `--check-vulns`：查询 osv.dev 已知漏洞（opt-in 网络请求；仅提示）
- `--fail-on-vuln`：命中已知 CVE 时退出码 1（隐含 `--check-vulns`）
- `--intel-feed FILE_OR_URL` / `--enforce-intel`：威胁情报名单及其强制阻断
- `--verbose`：显示完整扫描明细，包括 LOW 文件详情与 CLEAN 包列表
- `--show-pip-output`：显示原始 pip 安装输出
- `--policy path/to/pipguard.toml`：使用策略文件

## 输出与行为

- 检测到 **CRITICAL/HIGH**：阻断安装，退出码 `1`
- 检测到 **MEDIUM/LOW**：提示确认（或 `--yes` 自动继续）
- 全部 **CLEAN**：在摘要中显示计数，退出码 `0`
- 扫描失败：退出码 `2`

默认会静默成功安装时的原始 `pip install` 日志；如需查看完整安装输出，
可加 `--show-pip-output`。

更多细节请参考：[风险等级](risk-levels.md) 与 [退出码](exit-codes.md)。
