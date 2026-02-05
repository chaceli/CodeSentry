"""
CodeSentry 核心分析引擎 - 简化版
支持多语言和OWASP Top 10
"""
import re
import time
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(Enum):
    SQL_INJECTION = "CWE-89"
    COMMAND_INJECTION = "CWE-78"
    CODE_INJECTION = "CWE-94"
    BUFFER_OVERFLOW = "CWE-120"
    STACK_OVERFLOW = "CWE-121"
    FORMAT_STRING = "CWE-134"
    INTEGER_OVERFLOW = "CWE-190"
    PATH_TRAVERSAL = "CWE-22"
    XSS = "CWE-79"
    SSRF = "CWE-918"
    XXE = "CWE-611"
    AUTH_BYPASS = "CWE-287"
    SENSITIVE_DATA = "CWE-200"
    WEAK_CRYPTO = "CWE-328"
    HARDCODED_SECRET = "CWE-798"
    MEMORY_LEAK = "CWE-401"
    RACE_CONDITION = "CWE-362"
    UNKNOWN = "CWE-0"


@dataclass
class Location:
    file: str
    line: int

    def __str__(self):
        return f"{self.file}:{self.line}"


@dataclass
class Vulnerability:
    id: str
    type: VulnerabilityType
    severity: Severity
    title: str
    description: str
    location: Location
    code_snippet: str
    cwe_id: str
    confidence: float = 0.6
    fix_suggestion: Optional[str] = None
    owasp_category: Optional[str] = None


@dataclass
class ScanResult:
    target: str
    total_files: int = 0
    total_lines: int = 0
    vulnerabilities: List[Vulnerability] = None
    scan_time_seconds: float = 0.0
    errors: List[str] = None

    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.errors is None:
            self.errors = []

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)


# OWASP Top 10 2025 规则
OWASP_RULES = [
    # A03: Injection
    {
        "id": "A03-001",
        "type": VulnerabilityType.SQL_INJECTION,
        "severity": Severity.CRITICAL,
        "title": "SQL Injection - String Concatenation",
        "pattern": r"(?:execute|query|raw_sql)\s*\([^)]*[\"\'](?:SELECT|INSERT|UPDATE|DELETE|DROP)[^\"\']*[\"\']",
        "description": "SQL查询使用字符串拼接，可能导致SQL注入",
        "fix": "使用参数化查询或ORM",
        "cwe": "CWE-89",
        "owasp": "A03",
    },
    {
        "id": "A03-002",
        "type": VulnerabilityType.COMMAND_INJECTION,
        "severity": Severity.CRITICAL,
        "title": "Command Injection via Shell",
        "pattern": r"(?:os\.system|subprocess\.(?:call|run|Popen|check_call)|shell=True)",
        "description": "用户输入直接用于命令执行",
        "fix": "避免使用shell命令，使用参数化API",
        "cwe": "CWE-78",
        "owasp": "A03",
    },
    {
        "id": "A03-003",
        "type": VulnerabilityType.CODE_INJECTION,
        "severity": Severity.CRITICAL,
        "title": "Code Injection via eval/exec",
        "pattern": r"(?:eval|exec)\s*\([^)]*(?:request|user|input|param)",
        "description": "动态代码执行存在注入风险",
        "fix": "禁止在代码中执行用户输入",
        "cwe": "CWE-94",
        "owasp": "A03",
    },
    {
        "id": "A03-004",
        "type": VulnerabilityType.XSS,
        "severity": Severity.HIGH,
        "title": "Cross-Site Scripting (XSS)",
        "pattern": r"(?:innerHTML|outerHTML|dangerouslySetInnerHTML)",
        "description": "未经过滤的用户输入被渲染为HTML",
        "fix": "对所有用户输入进行HTML转义",
        "cwe": "CWE-79",
        "owasp": "A03",
    },
    {
        "id": "A03-005",
        "type": VulnerabilityType.SSRF,
        "severity": Severity.HIGH,
        "title": "Server-Side Request Forgery",
        "pattern": r"(?:requests\.(?:get|post|put|delete)|urllib\.request|urlopen|axios\.get)",
        "description": "服务器发起请求到用户可控的URL",
        "fix": "验证目标URL是否在允许列表中",
        "cwe": "CWE-918",
        "owasp": "A03",
    },
    {
        "id": "A03-006",
        "type": VulnerabilityType.XXE,
        "severity": Severity.CRITICAL,
        "title": "XML External Entity (XXE)",
        "pattern": r"(?:ElementTree\.parse|XMLParser|SAXParser|parseString|fromstring)",
        "description": "XML解析器未禁用外部实体",
        "fix": "禁用XML外部实体解析",
        "cwe": "CWE-611",
        "owasp": "A03",
    },
    
    # A02: Cryptographic Failures
    {
        "id": "A02-001",
        "type": VulnerabilityType.WEAK_CRYPTO,
        "severity": Severity.CRITICAL,
        "title": "Use of Weak Cryptographic Algorithm",
        "pattern": r"(?:md5|sha1)\s*\(",
        "description": "使用已知不安全的加密算法",
        "fix": "使用AES-256或ChaCha20替代",
        "cwe": "CWE-328",
        "owasp": "A02",
    },
    {
        "id": "A02-002",
        "type": VulnerabilityType.HARDCODED_SECRET,
        "severity": Severity.CRITICAL,
        "title": "Hard-coded Secret Key",
        "pattern": r"(?:api[_-]?key|secret|password|token)\s*=\s*[\"\'][a-zA-Z0-9_\-]{16,}[\"\']",
        "description": "代码中硬编码密钥或凭据",
        "fix": "使用环境变量或密钥管理服务",
        "cwe": "CWE-798",
        "owasp": "A02",
    },
    {
        "id": "A02-003",
        "type": VulnerabilityType.WEAK_CRYPTO,
        "severity": Severity.HIGH,
        "title": "Insecure SSL/TLS Verification",
        "pattern": r"(?:verify_mode\s*=\s*ssl\.CERT_NONE|check_hostname\s*=\s*False)",
        "description": "SSL/TLS证书验证被禁用",
        "fix": "启用完整的证书验证",
        "cwe": "CWE-295",
        "owasp": "A02",
    },
    
    # A01: Broken Access Control
    {
        "id": "A01-001",
        "type": VulnerabilityType.AUTH_BYPASS,
        "severity": Severity.HIGH,
        "title": "Missing Authorization Check",
        "pattern": r"(?:@app\.route|@router|@api\.route)\s*\([^)]*\)\s*\n\s*def\s+\w+\s*\([^)]*\):",
        "description": "关键API缺少认证检查",
        "fix": "为所有敏感端点实施认证",
        "cwe": "CWE-284",
        "owasp": "A01",
    },
    
    # A05: Security Misconfiguration
    {
        "id": "A05-001",
        "type": VulnerabilityType.SENSITIVE_DATA,
        "severity": Severity.HIGH,
        "title": "Debug Mode Enabled in Production",
        "pattern": r"(?:DEBUG|debug)\s*=\s*(?:True|true|1)",
        "description": "生产环境启用了调试模式",
        "fix": "生产环境禁用调试模式",
        "cwe": "CWE-489",
        "owasp": "A05",
    },
    {
        "id": "A05-002",
        "type": VulnerabilityType.SENSITIVE_DATA,
        "severity": Severity.MEDIUM,
        "title": "Verbose Error Messages",
        "pattern": r"(?:traceback|format_exc|print\s*\([^)]*exception)",
        "description": "生产环境暴露详细的错误信息",
        "fix": "在生产环境使用通用错误页面",
        "cwe": "CWE-200",
        "owasp": "A05",
    },
    
    # A07: Authentication Failures
    {
        "id": "A07-001",
        "type": VulnerabilityType.WEAK_CRYPTO,
        "severity": Severity.HIGH,
        "title": "Weak Password Hashing",
        "pattern": r"(?:md5|sha1|crypt)\s*\(\s*(?:password|pass|pwd)",
        "description": "使用弱算法哈希密码",
        "fix": "使用bcrypt、argon2或scrypt",
        "cwe": "CWE-328",
        "owasp": "A07",
    },
    
    # A08: Data Integrity Failures
    {
        "id": "A08-001",
        "type": VulnerabilityType.SENSITIVE_DATA,
        "severity": Severity.CRITICAL,
        "title": "Insecure Deserialization",
        "pattern": r"(?:pickle\.loads|marshal\.loads|yaml\.load|eval\s*\()",
        "description": "不安全的反序列化可能导致代码执行",
        "fix": "避免反序列化不可信数据",
        "cwe": "CWE-502",
        "owasp": "A08",
    },
    {
        "id": "A08-002",
        "type": VulnerabilityType.PATH_TRAVERSAL,
        "severity": Severity.HIGH,
        "title": "Path Traversal",
        "pattern": r"(?:open|read|write)\s*\([^)]*(?:\.\.|\%2e\%2e)",
        "description": "路径遍历漏洞，可能读取或写入任意文件",
        "fix": "对路径进行规范化并验证在允许范围内",
        "cwe": "CWE-22",
        "owasp": "A08",
    },
    
    # A10: SSRF
    {
        "id": "A10-001",
        "type": VulnerabilityType.SSRF,
        "severity": Severity.HIGH,
        "title": "Server-Side Request Forgery",
        "pattern": r"(?:requests\.get|requests\.post|urllib\.request\.urlopen|fetch|axios)",
        "description": "服务器发起请求到用户可控的URL",
        "fix": "验证所有URL是否在允许列表中",
        "cwe": "CWE-918",
        "owasp": "A10",
    },
]

# C/C++ 内存安全规则
MEMORY_SAFETY_RULES = [
    {
        "id": "CWE-120",
        "type": VulnerabilityType.BUFFER_OVERFLOW,
        "severity": Severity.CRITICAL,
        "title": "Unsafe strcpy",
        "pattern": r"strcpy\s*\(",
        "description": "strcpy() does not check buffer boundaries",
        "fix": "Use strncpy() or snprintf() instead",
        "cwe": "CWE-120",
    },
    {
        "id": "CWE-121",
        "type": VulnerabilityType.STACK_OVERFLOW,
        "severity": Severity.CRITICAL,
        "title": "Dangerous gets()",
        "pattern": r"gets\s*\(",
        "description": "gets() is removed in C11. It cannot specify buffer size.",
        "fix": "Use fgets() instead.",
        "cwe": "CWE-121",
    },
    {
        "id": "CWE-121",
        "type": VulnerabilityType.STACK_OVERFLOW,
        "severity": Severity.CRITICAL,
        "title": "Unbounded strcat",
        "pattern": r"strcat\s*\(",
        "description": "strcat may cause buffer overflow if length not checked.",
        "fix": "Use strncat with explicit size.",
        "cwe": "CWE-121",
    },
    {
        "id": "CWE-134",
        "type": VulnerabilityType.FORMAT_STRING,
        "severity": Severity.HIGH,
        "title": "Format String Vulnerability",
        "pattern": r"printf\s*\([^,)]+\)",
        "description": "Format string should be a constant literal, not a variable.",
        "fix": "Use printf(\"%s\", var) instead of printf(var).",
        "cwe": "CWE-134",
    },
    {
        "id": "CWE-190",
        "type": VulnerabilityType.INTEGER_OVERFLOW,
        "severity": Severity.MEDIUM,
        "title": "Potential Integer Overflow",
        "pattern": r"malloc\s*\([^)]*(?:\w+\s*\*\s*\w+|\w+\s*\+\s*\w+)",
        "description": "Multiplication/addition may cause integer overflow in allocation size.",
        "fix": "Check for overflow before malloc calculation.",
        "cwe": "CWE-190",
    },
    {
        "id": "CWE-401",
        "type": VulnerabilityType.MEMORY_LEAK,
        "severity": Severity.MEDIUM,
        "title": "Potential Memory Leak",
        "pattern": r"malloc|calloc|realloc\s*\([^)]+\)[^;]*\n(?:[^}]|})*(?!\bfree\b)",
        "description": "Allocated memory may not be freed on all paths.",
        "fix": "Ensure every allocation has a corresponding free.",
        "cwe": "CWE-401",
    },
]


def get_code_snippet(content: str, line: int, context: int = 3) -> str:
    """获取代码片段"""
    lines = content.split("\n")
    start = max(0, line - context - 1)
    end = min(len(lines), line + context)

    snippet = []
    for i in range(start, end):
        prefix = ">>> " if i == line - 1 else "    "
        snippet.append(f"{prefix}{i+1:4d} | {lines[i]}")
    return "\n".join(snippet)


def get_supported_extensions() -> List[str]:
    """获取支持的文件扩展名"""
    return [
        ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx",  # C/C++
        ".py", ".pyw",  # Python
        ".java", ".jsp",  # Java
        ".js", ".jsx", ".ts", ".tsx", ".mjs",  # JavaScript/TypeScript
        ".go",  # Go
        ".php", ".phtml",  # PHP
        ".rb", ".erb",  # Ruby
        ".sh", ".bash", ".zsh",  # Shell
        ".swift", ".kt", ".scala", ".rs", ".lua",  # Other
    ]


def analyze_file(file_path: str, content: str) -> List[Vulnerability]:
    """分析单个文件"""
    vulnerabilities = []
    
    # 合并所有规则
    all_rules = OWASP_RULES + MEMORY_SAFETY_RULES
    
    for rule in all_rules:
        pattern = rule["pattern"]
        try:
            for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                line_no = content[:match.start()].count("\n") + 1
                snippet = get_code_snippet(content, line_no)

                vuln = Vulnerability(
                    id=f"{rule['id']}-{line_no}",
                    type=rule["type"],
                    severity=rule["severity"],
                    title=rule["title"],
                    description=rule["description"],
                    location=Location(file=file_path, line=line_no),
                    code_snippet=snippet,
                    cwe_id=rule["id"],
                    confidence=0.6,
                    fix_suggestion=rule.get("fix"),
                    owasp_category=rule.get("owasp"),
                )
                vulnerabilities.append(vuln)
        except Exception as e:
            print(f"[WARNING] 规则 {rule['id']} 匹配失败: {e}")

    return vulnerabilities


def analyze_directory(dir_path: str) -> ScanResult:
    """分析整个目录"""
    result = ScanResult(target=dir_path)
    path = Path(dir_path)
    extensions = get_supported_extensions()

    if path.is_file():
        if path.suffix in extensions:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                result.total_files = 1
                result.total_lines = content.count("\n")
                result.vulnerabilities = analyze_file(str(path), content)
            except Exception as e:
                result.errors.append(str(e))
        return result

    # 递归扫描支持的文件类型
    code_files = []
    for ext in extensions:
        code_files.extend(list(path.rglob(f"*{ext}")))

    code_files = list(set(code_files))
    result.total_files = len(code_files)

    for file_path in code_files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            result.total_lines += content.count("\n")
            result.vulnerabilities.extend(analyze_file(str(file_path), content))
        except Exception as e:
            result.errors.append(f"{file_path}: {e}")

    return result


def print_result(result: ScanResult):
    """打印扫描结果"""
    print("\n" + "=" * 60)
    print("🔒 CodeSentry 安全扫描报告")
    print("=" * 60)
    print(f"📂 目标: {result.target}")
    print(f"📊 文件数: {result.total_files}")
    print(f"📝 代码行数: {result.total_lines}")
    print(f"⏱️  扫描耗时: {result.scan_time_seconds:.2f}秒")
    print("")
    print("📈 漏洞统计:")
    print(f"  🔴 Critical: {result.critical_count}")
    print(f"  🟠 High: {result.high_count}")
    print(f"  🟡 Medium: {result.medium_count}")
    print(f"  🟢 Low: {result.low_count}")
    print("")

    if result.vulnerabilities:
        for i, vuln in enumerate(result.vulnerabilities, 1):
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[vuln.severity.value]
            owasp_tag = f"[{vuln.owasp_category}] " if vuln.owasp_category else ""
            print(f"{icon} {owasp_tag}[{vuln.cwe_id}] {vuln.title}")
            print(f"   📍 {vuln.location}")
            print(f"   💡 {vuln.description}")
            if vuln.fix_suggestion:
                print(f"   🔧 修复: {vuln.fix_suggestion}")
            print("```")
            print(vuln.code_snippet)
            print("```\n")
    else:
        print("✅ 未发现漏洞！")

    if result.errors:
        print(f"\n⚠️  错误: {len(result.errors)} 个")
