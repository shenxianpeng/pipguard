# 工具链信任

pipguard 通过 `python -m pip download` 下载包。如果这个 pip 信任一个私钥已泄露的
证书颁发机构（CA），网络路径上的攻击者就能冒充 pypi.org，在 pipguard 扫描**之前**
把包换掉——扫描结果反而会为攻击者的代码背书。

## eMudhra / emSign 事件（2026 年 10 月）

eMudhra 旗下 emSign 中间证书的私钥极弱，任何人都能为任意域名（包括 `pypi.org`）
签发受信任的证书。它们所链接的根证书 **emSign ECC Root CA - G3**
（SHA-256 `86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b`）
已在 certifi 2026.10.18/19、pip 26.2.2、uv 0.13.4 中移除。

**pip 26.2.2 之前的所有版本都会始终信任自带的 certifi**（与系统证书库叠加），
所以只更新操作系统并不能解决问题。详见
[Python Discourse 公告](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)。

## pipguard 的处理

`pipguard install` 在下载之前，会检查即将运行的 pip 实际信任哪些证书：

| 发现 | 结果 |
|---|---|
| pip 的 CA 证书包含被攻破的根证书 | **阻断**，退出码 `2`，并给出修复命令 |
| 系统 OpenSSL 证书库包含它（**Linux** 上 pip 通过 truststore 读取） | pipguard 生成一份**去掉**该根证书的证书库副本，让本次运行的 pip 使用它（`SSL_CERT_FILE`），再次检查确认 pip 不再信任该根证书后继续 |
| macOS / Windows 上 pip 还会询问系统钥匙串/证书库，pipguard 无法过滤 | 同样过滤 OpenSSL 部分，并提示安装系统更新 |
| 没有问题 | 静默继续 |

撰写本文时，GitHub 的 `ubuntu-latest` runner 系统证书库里仍然有这张根证书，正是这个过滤让 pip 26.2.2 能在上面安全运行。

检查的是证书本身而不是 pip 版本号，所以打过补丁、改用系统证书库的发行版 pip（如 Debian）不会误报。

- `--require-hashes`：pip 会用锁文件里的哈希校验每个下载，被替换的包会被拒绝，因此阻断降级为警告。
- `--skip-toolchain-check`：完全跳过检查（不推荐）。
- `pipguard scan-feed` 从不安装，只给出警告。

## `pipguard doctor`

不安装任何东西，检查一个或多个解释器：

```bash
pipguard doctor
pipguard doctor --python /usr/bin/python3 --python ~/project/.venv/bin/python
```

| 退出码 | 含义 |
|---|---|
| `0` | 没有会阻断安装的问题（可能有警告） |
| `1` | 至少一个解释器的 pip 可被利用被攻破的 CA 中间人攻击（指不经 pipguard 过滤、直接 `pip install` 的情况） |
| `2` | 有解释器无法检查 |

## 修复

用**锁定哈希**的 wheel 升级 pip。有 sha256 校验，即使通过旧的有漏洞的 pip 执行也是安全的：

```bash
python -m pip install "pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
```

pip 26.2.2 需要 Python 3.10+。然后更新系统证书库（`sudo apt-get install --only-upgrade ca-certificates`、
`brew upgrade ca-certificates` 或系统更新），并重新构建容器镜像：Docker 官方的
`python:3.11` / `python:3.12` 镜像会继续带着旧 pip。

[GitHub Action](usage.md) 会在安装 pipguard 之前自动完成 pip 升级。
