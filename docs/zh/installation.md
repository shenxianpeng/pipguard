# 安装

## 环境要求

- Python 3.10+
- 可用的 pip
- 无额外运行时依赖（pipguard 基于 Python 标准库实现）

## 从 PyPI 安装

```bash
pip install pipguard
```

## 验证安装

```bash
pipguard --version
```

## 升级

```bash
pip install -U pipguard
```

## 在 CI 中使用

建议将 `pipguard install ...` 放在依赖安装之前执行，
并根据退出码决定是否中断流水线。
