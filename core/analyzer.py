"""
纯正则版代码分析器 - 无需外部依赖
"""
import re
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional
import time


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(Enum):
    BUFFER_OVERFLOW = "CWE-120"
    FORMAT_STRING = "CWE-134"
    INTEGER_OVERFLOW = "CWE-190"
    NULL_POINTER = "CWE-476"
    USE_AFTER_FREE = "CWE-416"
    COMMAND_INJECTION = "CWE-78"
    SQL_INJECTION = "CWE-89"


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
    confidence: float = 0.0
    ai_verified: bool = False
    fix_suggestion: Optional[str] = None
    ai_analysis: Optional[str] = None
    ai_verification_result: Optional[str] = None


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


# 漏洞检测规则
RULES = [
    {
        "id": "CWE-120",
        "type": VulnerabilityType.BUFFER_OVERFLOW,
        "severity": Severity.CRITICAL,
        "title": "Unsafe strcpy - Potential Buffer Overflow",
        "pattern": r"strcpy\s*\(",
        "message": "strcpy() does not check buffer boundaries.",
        "fix": "Use strncpy() or snprintf() instead.",
    },
    {
        "id": "CWE-134",
        "type": VulnerabilityType.FORMAT_STRING,
        "severity": Severity.HIGH,
        "title": "Unsafe sprintf - Format String",
        "pattern": r"sprintf\s*\(",
        "message": "sprintf() does not limit buffer size.",
        "fix": "Use snprintf() instead.",
    },
    {
        "id": "CWE-120",
        "type": VulnerabilityType.BUFFER_OVERFLOW,
        "severity": Severity.CRITICAL,
        "title": "Dangerous gets() - Removed in C11",
        "pattern": r"gets\s*\(",
        "message": "gets() is removed in C11.",
        "fix": "Use fgets() instead.",
    },
    {
        "id": "CWE-134",
        "type": VulnerabilityType.FORMAT_STRING,
        "severity": Severity.HIGH,
        "title": "Format String Vulnerability",
        "pattern": r"printf\s*\(\s*\w+",
        "message": "Variable format string detected.",
        "fix": "Use printf(\"%s\", var); instead of printf(var);",
    },
    {
        "id": "CWE-78",
        "type": VulnerabilityType.COMMAND_INJECTION,
        "severity": Severity.CRITICAL,
        "title": "Command Injection via system()",
        "pattern": r"system\s*\([^)]*(?:getenv|argv|user|input|param)",
        "message": "User input in system() may cause command injection.",
        "fix": "Avoid system() with user input.",
    },
    {
        "id": "CWE-190",
        "type": VulnerabilityType.INTEGER_OVERFLOW,
        "severity": Severity.MEDIUM,
        "title": "Potential Integer Overflow",
        "pattern": r"malloc\s*\([^)]*\*[^)]*\)",
        "message": "Multiplication may cause integer overflow.",
        "fix": "Check for overflow before malloc.",
    },
    {
        "id": "CWE-416",
        "type": VulnerabilityType.USE_AFTER_FREE,
        "severity": Severity.CRITICAL,
        "title": "Use After Free",
        "pattern": r"free\s*\([^)]+\);\s*\n\s*\w+[^;]*;",
        "message": "Potential use-after-free pattern.",
        "fix": "Set pointer to NULL after free.",
    },
    {
        "id": "CWE-259",
        "type": VulnerabilityType.SQL_INJECTION,
        "severity": Severity.CRITICAL,
        "title": "SQL Injection",
        "pattern": r"(?:sprintf|strcpy)\s*\([^)]*(?:SELECT|FROM|WHERE|query)",
        "message": "Potential SQL injection.",
        "fix": "Use parameterized queries.",
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


def analyze_file(file_path: str, content: str) -> List[Vulnerability]:
    """分析单个文件"""
    vulnerabilities = []

    for rule in RULES:
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
                    description=rule["message"],
                    location=Location(file=file_path, line=line_no),
                    code_snippet=snippet,
                    cwe_id=rule["id"],
                    confidence=0.6,
                    fix_suggestion=rule.get("fix"),
                )
                vulnerabilities.append(vuln)
        except Exception as e:
            print(f"[WARNING] 规则 {rule['id']} 匹配失败: {e}")

    return vulnerabilities


def analyze_directory(dir_path: str) -> ScanResult:
    """分析整个目录"""
    result = ScanResult(target=dir_path)
    path = Path(dir_path)

    if path.is_file():
        if path.suffix in [".c", ".cpp", ".h", ".hpp"]:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                result.total_files = 1
                result.total_lines = content.count("\n")
                result.vulnerabilities = analyze_file(str(path), content)
            except Exception as e:
                result.errors.append(str(e))
        return result

    # 递归扫描
    code_files = list(path.rglob("*.c")) + list(path.rglob("*.cpp"))
    code_files += list(path.rglob("*.h")) + list(path.rglob("*.hpp"))
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
            print(f"{icon} [{vuln.cwe_id}] {vuln.title}")
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
