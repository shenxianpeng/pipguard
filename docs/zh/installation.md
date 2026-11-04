# 安装指南

## 环境要求

- Python 3.10+
- pip（任意较新版本）
- 零外部依赖：pipguard 仅使用 Python 标准库

## 从 PyPI 安装

```bash
pip install pipguard
```

验证安装：

```bash
pipguard --version
```

## 从源码安装

```bash
git clone https://github.com/shenxianpeng/pipguard.git
cd pipguard
pip install -e .
```

## CI / Docker

可将 pipguard 加入 `requirements-dev.txt`，或在 CI 中直接安装：

```yaml title=".github/workflows/ci.yml"
- name: 安装 pipguard
  run: pip install pipguard

- name: 安全安装依赖
  run: pipguard install --yes -r requirements.txt
```

## 升级

```bash
pip install --upgrade pipguard
```

## 卸载

```bash
pip uninstall pipguard
```

pipguard 不会生成配置文件，也不会写入持久状态，卸载后环境保持干净。
