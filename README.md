# CodeSentry - AI驱动的代码安全审计工具

## 核心功能
- C/C++ 代码静态分析
- AI 驱动的漏洞检测与验证
- 低误报率的智能审计

## 技术栈
- Python 3.10+
- LibClang（Python binding）
- 大模型 API（OpenAI/Claude/本地模型）

## 项目结构

```
CodeSentry/
├── core/                    # 核心分析引擎
│   ├── parser.py           # 代码解析器
│   ├── scanner.py          # 漏洞扫描器
│   └── analyzer.py         # 静态分析器
├── ai/                      # AI 相关
│   ├── engine.py           # 大模型集成
│   └── validator.py        # 漏洞验证器
├── rules/                   # 漏洞规则库
│   ├── cwe_top10.py        # CWE Top 10 规则
│   └── custom.py           # 自定义规则
├── output/                  # 输出模块
│   ├── reporter.py         # 报告生成
│   └── formats/            # 格式支持（JSON/SARIF/HTML）
├── tests/                   # 测试用例
│   ├── samples/            # 测试样本代码
│   └── test_*.py           # 单元测试
├── config/                  # 配置
│   └── settings.py         # 配置文件
├── cli/                     # 命令行工具
│   └── main.py             # CLI 入口
├── utils/                   # 工具函数
│   └── logger.py           # 日志
├── requirements.txt         # 依赖
├── README.md               # 说明文档
└── .env.example            # 环境变量模板
```

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 配置 API Key
cp .env.example .env
# 编辑 .env 填入你的 API Key

# 运行扫描
python -m cli.main scan <目标代码路径>
```

## 支持的语言
- [x] C/C++ (第一阶段)
- [ ] Python (第二阶段)
- [ ] Java (第三阶段)
- [ ] Go (待定)

## 许可证
MIT
