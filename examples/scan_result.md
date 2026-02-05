# CodeSentry 扫描结果示例

## TheAlgorithms/Python 项目扫描

```bash
python3 codesentry.py /path/to/TheAlgorithms-Python
```

### 扫描统计
- **扫描时间**: 1.10秒
- **扫描文件数**: 1,381
- **代码行数**: 117,767

### 漏洞统计
- 🔴 Critical: 7
- 🟠 High: 58  
- 🟡 Medium: 1,172
- 🟢 Low: 0

## 发现的漏洞类型

### A05 - Verbose Error Messages (大量)
在Python doctest注释中发现很多`Traceback`示例，这些被误报为Verbose Error Messages。

**实际风险**: 低 (测试代码注释)

### 主要发现
1. **测试代码中的错误示例** - 算法库通常包含doctest，展示错误情况
2. **示例代码** - 很多是教学性质的代码示例

## 使用建议

```bash
# 扫描整个项目
python3 codesentry.py /path/to/project

# 生成JSON报告
python3 codesentry.py /path/to/project --format json --output report.json
```
