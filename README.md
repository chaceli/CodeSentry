# CodeSentry - AI-driven Code Security Audit Tool

## Core Features
- **Multi-language Static Analysis** - Supports C/C++, Python, Java, JavaScript, Go, PHP, Ruby, and more
- **OWASP Top 10 Coverage** - Comprehensive coverage of Web application security risks
- **Memory Safety Detection** - Buffer overflow, format string, integer overflow detection
- **CI/CD Integration** - Easy to integrate into your development workflow

## Supported Vulnerability Types

### Code Injection
- SQL Injection
- Command Injection  
- Code Injection
- LDAP/XPath Injection
- XSS (Cross-Site Scripting)
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity)

### Memory Safety
- Buffer Overflow
- Stack Overflow
- Format String
- Integer Overflow/Underflow
- Memory Leak

### Cryptographic
- Weak Encryption Algorithms
- Hard-coded Credentials
- Insecure SSL/TLS Configuration

### Web Security
- Path Traversal
- Insecure Deserialization
- Missing Authorization
- Verbose Error Messages

## 支持的漏洞类型

### 代码注入漏洞
- SQL注入 (SQL Injection)
- 命令注入 (Command Injection)
- 代码注入 (Code Injection)
- LDAP注入 (LDAP Injection)
- XPath注入 (XPath Injection)

### 内存破坏漏洞
- 缓冲区溢出 (Buffer Overflow)
- 栈溢出 (Stack Overflow)
- 堆溢出 (Heap Overflow)
- Off-by-One
- 格式化字符串 (Format String)
- 整数溢出/下溢 (Integer Overflow/Underflow)

### 路径与文件安全
- 路径遍历 (Path Traversal)
- 敏感文件泄露
- 任意文件读取/写入
- 符号链接攻击

### Web安全
- 跨站脚本 (XSS)
- 跨站请求伪造 (CSRF)
- 不安全的直接对象引用 (IDOR)
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE)

### 认证与会话
- 弱密码算法
- 不安全的会话管理
- 敏感信息泄露
- 硬编码凭据

### 加密与密钥
- 弱加密算法
- 不安全的随机数
- 密钥硬编码
- SSL/TLS配置问题

### 逻辑漏洞
- 业务逻辑缺陷
- 访问控制绕过
- 条件竞争 (Race Condition)
- TOCTOU竞争条件

## 技术栈
- Python 3.10+
- 正则表达式引擎 + 数据流分析
- AI大模型集成 (OpenAI, Claude, Gemini等)
- 污点分析 (Taint Analysis)

## 项目结构

```
CodeSentry/
├── core/                    # 核心分析引擎
│   ├── analyzer.py         # 主分析器（含数据流分析）
│   ├── models.py           # 数据结构定义
│   └── taint_tracker.py    # 污点分析引擎
├── rules/                   # 漏洞规则库
│   ├── owasp_rules.py      # OWASP Top 10规则集
│   ├── injection_rules.py   # 注入类规则
│   └── memory_rules.py     # 内存安全规则
├── ai/                      # AI相关
│   ├── engine.py           # 大模型集成
│   └── validator.py        # AI漏洞验证器
├── output/                  # 输出模块
│   └── reporter.py         # 报告生成
├── cli/                     # 命令行工具
│   └── main.py             # CLI入口
├── config/                  # 配置
│   └── settings.py         # 配置文件
├── utils/                   # 工具函数
└── README.md               # 说明文档
```

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 代码漏洞扫描
python -m codesentry scan <目标目录或文件>

# AI辅助验证
python -m codesentry verify <漏洞ID>

# 生成HTML报告
python -m codesentry scan <目标> --format html --output report.html
```

## AI验证模式

CodeSentry集成AI大模型，可对扫描结果进行二次验证：

```bash
# 启用AI验证
python -m codesentry scan <目标> --ai-verify

# 只使用AI验证（高精度模式）
python -m codesentry scan <目标> --ai-only
```

## 支持的语言
- C / C++
- Python
- Java
- JavaScript / TypeScript
- Go
- PHP
- Ruby
- And more...

## 配置

通过 `config/settings.py` 或环境变量配置：

```python
# AI模型配置
AI_MODEL = "gpt-4"  # 或 "claude-3-opus", "gemini-pro"
AI_API_KEY = os.getenv("AI_API_KEY")

# 分析配置
ANALYSIS_DEPTH = "deep"  # "shallow" | "medium" | "deep"
TAINT_TRACKING = True    # 启用污点分析
```

## 输出示例

```
🔒 CodeSentry 安全扫描报告
==================================================
📂 目标: /path/to/project
📊 文件数: 150
📝 代码行数: 45,230
⏱️  扫描耗时: 12.34秒

📈 漏洞统计:
  🔴 Critical: 2
  🟠 High: 5
  🟡 Medium: 12
  🟢 Low: 8

🔍 AI验证结果: 误报率降低 85%
```

## 与CI/CD集成

```yaml
# GitHub Actions示例
- name: CodeSentry Scan
  run: |
    pip install codesentry
    codesentry scan . --ai-verify --format json > results.json
```

## 许可证
MIT License

## 贡献
欢迎提交Issue和Pull Request！
