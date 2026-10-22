# 工具链信任

pipguard 通过 `python -m pip download` 下载包。如果这个 pip 信任一个私钥已泄露的
证书颁发机构（CA），网络路径上的攻击者就能冒充 pypi.org，在 pipguard 扫描**之前**
把包换掉——扫描结果反而会为攻击者的代码背书。

## eMudhra / emSign 事件（2026 年 10 月）

[eMudhra 的 8 个中间 CA](https://emudhra.we-have-a-problem.com/) 私钥极弱，任何人都能为任意域名
（包括 `pypi.org`）签发受信任的证书。这些中间证书链接到三个根证书：

| 根证书 | 谁信任它 |
|---|---|
| emSign ECC Root CA - G3 | certifi / Mozilla、Apple、Microsoft，已在 certifi 2026.10.18/19 与 **pip 26.2.2** 中移除 |
| emSign Root TLS CA - G3 | Microsoft |
| AAA Certificate Services（Sectigo） | Apple、Microsoft（Mozilla 与 Chrome 已移除） |

只要 pip 用到的**任何一个**证书库里有这些根证书，pip 就会信任被攻破的中间证书：

1. **pip 自带的证书包**：pip 26.2.2 之前的版本总会加载自带的 certifi，只更新操作系统没用。
2. **OpenSSL 系统证书库**：pip 24.2+ 通过 truststore 询问系统证书库，在 Linux 上就是这个文件。
3. **操作系统验证器**：macOS / Windows 上 truststore 询问系统（钥匙串 / Windows 证书库）。
   2026-10-22 在一台 Mac 上实测，pip 26.2.2 仍会通过这条路径接受被攻破 CA 签发的证书。

详见 [Python Discourse 公告](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)。

## `pipguard install` 的处理

下载之前，检查即将运行的 pip 实际信任哪些证书，能修的**在本次运行中**修掉，然后再检查一遍：

| 发现 | pipguard 的处理 |
|---|---|
| pip 自带证书包有坏根证书（pip < 26.2.2） | **阻断**，退出码 `2`，给出锁定哈希的修复命令（外部无法修复） |
| OpenSSL 证书库有坏根证书 | 生成一份**去掉**坏根证书的副本，本次运行使用它（`SSL_CERT_FILE`）；其他 CA（如公司代理 CA）照常可用 |
| macOS 钥匙串 / Windows 证书库有坏根证书 | 让 pip 以 `PIP_USE_DEPRECATED=legacy-certs` 运行，只用自带的（已干净的）证书包 |
| 没有问题 | 静默继续 |

撰写本文时，GitHub `ubuntu-latest` runner 的系统证书库里仍然有 emSign ECC Root CA - G3，
正是这个过滤让 pip 26.2.2 在上面变得安全。

检查的是证书本身而不是 pip 版本号，所以打过补丁、改用系统证书库的发行版 pip（如 Debian）不会误报。

- `--require-hashes`：pip 会用锁文件里的哈希校验每个下载，被替换的包会被拒绝，因此阻断降级为警告。
- `--skip-toolchain-check`：完全跳过（不推荐）。
- `pipguard scan-feed` 从不安装，只给出警告。
- 使用 `legacy-certs` 时，pip 不会使用只存在于系统证书库里的 CA（例如公司 TLS 代理）。
  可以用 `--cert` / `PIP_CERT` 提供该 CA，或更新系统去掉坏根证书。

## `pipguard doctor`

显示**直接**运行 `pip install` 时信任什么，不安装任何东西：

```bash
pipguard doctor
pipguard doctor --python /usr/bin/python3 --python ~/project/.venv/bin/python

# 实测：让 pip 直接连接事件方提供的测试主机，分别以普通 pip 和 pipguard 运行的方式
pipguard doctor --online
```

`--online` 会连接 `*.we-have-a-problem.com`，它们使用被攻破 CA 签发的证书。结果为 `rejected` 才安全。

| 退出码 | 含义 |
|---|---|
| `0` | 普通 pip 不信任被攻破的 CA |
| `1` | 普通 pip 信任它们（pipguard install 可能仍受保护，见输出） |
| `2` | 有解释器无法检查 |

## 彻底修复

用**锁定哈希**的 wheel 升级 pip。有 sha256 校验，即使通过旧的有漏洞的 pip 执行也是安全的：

```bash
python -m pip install "pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
```

pip 26.2.2 需要 Python 3.10+。然后更新系统证书库（`sudo apt-get install --only-upgrade ca-certificates`、
`brew upgrade ca-certificates`、系统更新），并重新构建容器镜像：Docker 官方的
`python:3.11` / `python:3.12` 镜像会继续带着旧 pip。

GitHub Action 会在安装 pipguard 之前自动完成 pip 升级。
