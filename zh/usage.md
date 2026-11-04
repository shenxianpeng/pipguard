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

## 扫描 PyPI feed（reporter 工作流）

`pipguard scan-feed` 会监控 PyPI 最近发布的 RSS feed，对每一项**只扫描、不安装**，
并把高风险的挑出来作为人工核查候选。这把"reporter"工作流落地了——绝大多数新发布
都平平无奇，扫描让一个人能把注意力集中在少数可疑的上面，人工确认后再提交 advisory。

```bash
# 扫描最近 20 个发布，列出 HIGH 或 CRITICAL
pipguard scan-feed

# 新包（而非已有包的新版本），仅 CRITICAL
pipguard scan-feed --feed packages --min-level critical

# 扫描本地保存的 feed 文件，放宽到 MEDIUM，并查 CVE
pipguard scan-feed --feed ./updates.xml --min-level medium --check-vulns
```

参数：`--feed`（`updates`（默认）| `packages` | URL 或本地文件）、`--limit N`
（默认 20；`0` 表示不限）、`--min-level`（`critical`|`high`|`medium`|`low`，默认
`high`），以及 `--allow`、`--check-vulns`、`--verbose`、`--policy`。

退出码：任何包达到或超过 `--min-level` 时为 **1**（便于定时任务告警），没有则 **0**，
feed/下载错误为 **2**。纯 sdist 的发布会被跳过（不执行构建代码就无法扫描）。

!!! note "这是初筛，不是定论"
    被标记的包只是*核查候选*，不代表确认的攻击。请先人工检查（例如用 PyPI Inspector）
    再行动。

### 作为定时哨兵运行

"有候选就退出 1"的行为让 `scan-feed` 很容易定时化。仓库提供了一个可直接复制的
GitHub Actions 工作流 [`examples/scan-feed-cron.yml`](https://github.com/shenxianpeng/pipguard/blob/main/examples/scan-feed-cron.yml)，
它按 cron 运行，发现被标记的发布时自动开一个 GitHub issue：

```bash
cp examples/scan-feed-cron.yml .github/workflows/pipguard-sentinel.yml
```

## 输出与行为

- 检测到 **CRITICAL/HIGH**：阻断安装，退出码 `1`
- 检测到 **MEDIUM/LOW**：提示确认（或 `--yes` 自动继续）
- 全部 **CLEAN**：在摘要中显示计数，退出码 `0`
- 扫描失败：退出码 `2`

默认会静默成功安装时的原始 `pip install` 日志；如需查看完整安装输出，
可加 `--show-pip-output`。

更多细节请参考：[风险等级](risk-levels.md) 与 [退出码](exit-codes.md)。
