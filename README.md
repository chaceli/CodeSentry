# CodeSentry - AI驱动的代码安全审计 & Pwn 分析工具

## 核心功能
- **C/C++ 代码静态分析** - 漏洞检测与验证
- **CTF Pwn 分析** - 二进制漏洞利用模式识别
- **ELF 二进制分析** - 安全保护机制检测 & ROP Gadget 发现
- **AI 驱动的漏洞验证** - 低误报率的智能审计

## 支持的漏洞类型

### 内存破坏漏洞
- 栈溢出 (Stack Overflow)
- 堆溢出 (Heap Overflow)
- Off-by-One
- Use After Free
- Double Free
- 格式化字符串

### 二进制安全
- ROP/JOP/COP 利用模式
- GOT 表劫持
- ret2libc / ret2dlresolve
- SROP (Sigreturn ROP)

### 条件竞争
- TOCTOU 竞争
- 条件竞争

## 技术栈
- Python 3.10+
- 正则表达式引擎
- ROPgadget / ropper (二进制分析)
- checksec (保护机制检测)

## 项目结构

```
CodeSentry/
├── core/                    # 核心分析引擎
│   ├── analyzer.py         # 漏洞检测分析器
│   ├── elf_analyzer.py      # ELF 二进制分析
│   ├── pwn_analyzer.py     # CTF Pwn 模式分析
│   └── models.py           # 数据结构定义
├── rules/                   # 漏洞知识库
│   └── pwn_knowledge.py    # CTF Pwn 技术百科
├── ai/                      # AI 相关
│   ├── engine.py           # 大模型集成
│   └── validator.py        # 漏洞验证器
├── output/                  # 输出模块
│   └── reporter.py         # 报告生成
├── tests/                   # 测试用例
├── cli/                     # 命令行工具
│   └── main.py             # CLI 入口
├── config/                  # 配置
│   └── settings.py         # 配置文件
├── utils/                   # 工具函数
└── README.md               # 说明文档
```

## 快速开始

```bash
# 代码漏洞扫描
python -m codesentry scan <目标目录>

# 二进制安全分析
python -m codesentry analyze-elf <二进制文件>

# Pwn 模式检测
python -m codesentry pwn-scan <C代码文件>
```

## CTF Pwn 技术支持

### 利用技术百科
- Basic Stack Overflow → ROP
- House of Spirit / Force / Einherjar / Lore
- Use After Free / Double Free
- Unsorted Bin Attack
- Tcache Attack
- Format String (Leak / Write)
- SROP / ret2dlresolve

### 保护机制检测
- NX/DEP, Stack Canary, PIE, RELRO, FORTIFY_SOURCE, ASLR

## 许可证
MIT
