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
    # 内存破坏漏洞
    BUFFER_OVERFLOW = "CWE-120"  # 缓冲区溢出
    STACK_OVERFLOW = "CWE-121"  # 栈溢出
    HEAP_OVERFLOW = "CWE-122"  # 堆溢出
    OFF_BY_ONE = "CWE-193"  #  Off-by-One
    FORMAT_STRING = "CWE-134"  # 格式化字符串
    INTEGER_OVERFLOW = "CWE-190"  # 整数溢出
    INTEGER_UNDERFLOW = "CWE-191"  # 整数下溢
    NULL_POINTER = "CWE-476"  # 空指针解引用
    USE_AFTER_FREE = "CWE-416"  # 释放后使用
    DOUBLE_FREE = "CWE-415"  # 双重释放

    # 控制流相关
    ROP_GADGET = "CWE-94"  # 代码注入/ROP
    RET2LIBC = "CWE-94"  # ret2libc 攻击
    JOP_GADGET = "CWE-94"  # Jump-Oriented Programming
    COP_GADGET = "CWE-94"  # Call-Oriented Programming

    # 权限/认证
    COMMAND_INJECTION = "CWE-78"  # 命令注入
    SQL_INJECTION = "CWE-89"  # SQL 注入
    PATH_TRAVERSAL = "CWE-22"  # 路径遍历

    # 二进制安全
    GOT_HIJACK = "CWE-829"  # GOT 表劫持
    DTORS_HIJACK = "CWE-829"  # dtors 表劫持
    FINI_ARRAY_HIJACK = "CWE-829"  # fini_array 劫持
    VTABLE_HIJACK = "CWE-829"  # C++ vtable 劫持
    FUNCTION_POINTER = "CWE-754"  # 危险函数指针

    # 条件竞争
    RACE_CONDITION = "CWE-362"  # 条件竞争
    TOCTOU = "CWE-367"  # TOCTOU 竞争条件

    # 内存管理
    UNINITIALIZED_POINTER = "CWE-457"  # 未初始化指针
    DANGLING_POINTER = "CWE-822"  # 悬空指针
    MEMORY_LEAK = "CWE-401"  # 内存泄漏


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
    # ========== 栈溢出相关 ==========
    {
        "id": "CWE-120",
        "type": VulnerabilityType.BUFFER_OVERFLOW,
        "severity": Severity.CRITICAL,
        "title": "Unsafe strcpy - Potential Buffer Overflow",
        "pattern": r"strcpy\s*\(",
        "message": "strcpy() does not check buffer boundaries.",
        "fix": "Use strncpy() or snprintf() instead.",
        "category": "stack_overflow",
    },
    {
        "id": "CWE-120",
        "type": VulnerabilityType.STACK_OVERFLOW,
        "severity": Severity.CRITICAL,
        "title": "Unsafe strncpy - Potential Truncation",
        "pattern": r"strncpy\s*\([^,]+,\s*[^,]+,\s*(?:sizeof|strlen)",
        "message": "strncpy may not null-terminate if source is longer than size.",
        "fix": "Ensure null-termination after strncpy.",
        "category": "stack_overflow",
    },
    {
        "id": "CWE-121",
        "type": VulnerabilityType.STACK_OVERFLOW,
        "severity": Severity.CRITICAL,
        "title": "Dangerous gets() - Removed in C11",
        "pattern": r"gets\s*\(",
        "message": "gets() is removed in C11. It cannot specify buffer size.",
        "fix": "Use fgets() instead.",
        "category": "stack_overflow",
    },
    {
        "id": "CWE-121",
        "type": VulnerabilityType.STACK_OVERFLOW,
        "severity": Severity.CRITICAL,
        "title": "Unsafe scanf without width specifier",
        "pattern": r"scanf\s*\(\s*\"%[sldif]\"",
        "message": "scanf without width limit may cause buffer overflow.",
        "fix": "Use scanf(\"%100s\", buf) instead of scanf(\"%s\", buf).",
        "category": "stack_overflow",
    },
    {
        "id": "CWE-121",
        "type": VulnerabilityType.STACK_OVERFLOW,
        "severity": Severity.CRITICAL,
        "title": "Unbounded strcat",
        "pattern": r"strcat\s*\(",
        "message": "strcat may cause buffer overflow if length not checked.",
        "fix": "Use strncat with explicit size.",
        "category": "stack_overflow",
    },
    {
        "id": "CWE-121",
        "type": VulnerabilityType.STACK_OVERFLOW,
        "severity": Severity.CRITICAL,
        "title": "Unbounded strncat",
        "pattern": r"strncat\s*\([^,]+,\s*[^,]+,\s*(?:sizeof|strlen)",
        "message": "strncat may still overflow if size calculation is wrong.",
        "fix": "Verify size calculation: n = sizeof(dest) - strlen(dest) - 1.",
        "category": "stack_overflow",
    },

    # ========== 格式化字符串 ==========
    {
        "id": "CWE-134",
        "type": VulnerabilityType.FORMAT_STRING,
        "severity": Severity.HIGH,
        "title": "Unsafe sprintf - Format String",
        "pattern": r"sprintf\s*\(",
        "message": "sprintf() does not limit buffer size.",
        "fix": "Use snprintf() instead.",
        "category": "format_string",
    },
    {
        "id": "CWE-134",
        "type": VulnerabilityType.FORMAT_STRING,
        "severity": Severity.HIGH,
        "title": "Format String Vulnerability - User Controlled",
        "pattern": r"(?:printf| fprintf| sprintf| snprintf|vprintf|vfprintf|vsprintf|vsnprintf)\s*\(\s*(?:\w+|\([^)]*\))[^,)]*\s*\)",
        "message": "Format string should be a constant literal, not a variable.",
        "fix": "Use printf(\"%s\", var) instead of printf(var).",
        "category": "format_string",
    },
    {
        "id": "CWE-134",
        "type": VulnerabilityType.FORMAT_STRING,
        "severity": Severity.HIGH,
        "title": "syslog with user-controlled format",
        "pattern": r"syslog\s*\([^,)]*\s*,\s*(?:\w+)",
        "message": "User input in syslog format string is dangerous.",
        "fix": "Use syslog(LOG_INFO, \"%s\", user_input).",
        "category": "format_string",
    },

    # ========== 堆漏洞 ==========
    {
        "id": "CWE-415",
        "type": VulnerabilityType.DOUBLE_FREE,
        "severity": Severity.CRITICAL,
        "title": "Potential Double Free",
        "pattern": r"free\s*\([^)]+\);\s*\n\s*free\s*\([^)]+\)",
        "message": "Same pointer freed twice leads to heap corruption.",
        "fix": "Set pointer to NULL after free, use free guard.",
        "category": "heap_exploitation",
    },
    {
        "id": "CWE-416",
        "type": VulnerabilityType.USE_AFTER_FREE,
        "severity": Severity.CRITICAL,
        "title": "Use After Free",
        "pattern": r"free\s*\([^)]+\);\s*\n\s*[^}]*(?:\w+\s*(?:\(|\[))",
        "message": "Use of memory after free - critical heap vulnerability.",
        "fix": "Set pointer to NULL after free and check before use.",
        "category": "heap_exploitation",
    },
    {
        "id": "CWE-122",
        "type": VulnerabilityType.HEAP_OVERFLOW,
        "severity": Severity.CRITICAL,
        "title": "Unbounded memcpy",
        "pattern": r"memcpy\s*\([^,]+,\s*[^,]+,\s*(?:sizeof|strlen)",
        "message": "memcpy without explicit size may overflow.",
        "fix": "Use explicit size: memcpy(dest, src, min(src_size, dest_size)).",
        "category": "heap_exploitation",
    },
    {
        "id": "CWE-122",
        "type": VulnerabilityType.HEAP_OVERFLOW,
        "severity": Severity.CRITICAL,
        "title": "Unbounded memmove",
        "pattern": r"memmove\s*\([^,]+,\s*[^,]+,\s*(?:sizeof|strlen)",
        "message": "memmove without explicit size may overflow.",
        "fix": "Use explicit size to prevent overflow.",
        "category": "heap_exploitation",
    },
    {
        "id": "CWE-190",
        "type": VulnerabilityType.INTEGER_OVERFLOW,
        "severity": Severity.MEDIUM,
        "title": "Potential Integer Overflow in malloc size",
        "pattern": r"malloc\s*\([^)]*(?:\w+\s*\*\s*\w+|\w+\s*\+\s*\w+)",
        "message": "Multiplication/addition may cause integer overflow in allocation size.",
        "fix": "Check for overflow before malloc calculation.",
        "category": "heap_exploitation",
    },
    {
        "id": "CWE-190",
        "type": VulnerabilityType.INTEGER_UNDERFLOW,
        "severity": Severity.MEDIUM,
        "title": "Potential Integer Underflow",
        "pattern": r"(?:\w+)\s*-\s*(?:\w+)\s*(?:size_t|uint|\d+)",
        "message": "Subtraction may cause underflow with unsigned types.",
        "fix": "Add bounds check before subtraction.",
        "category": "heap_exploitation",
    },

    # ========== Off-by-One ==========
    {
        "id": "CWE-193",
        "type": VulnerabilityType.OFF_BY_ONE,
        "severity": Severity.HIGH,
        "title": "Potential Off-by-One in loop",
        "pattern": r"for\s*\(\s*(?:\w+)\s*=\s*0\s*;\s*\1\s*<=\s*(?:\w+)\s*;\s*\1\+\+\s*\)",
        "message": "Loop condition uses <= which may cause off-by-one.",
        "fix": "Check if buffer size matches loop bound.",
        "category": "stack_overflow",
    },
    {
        "id": "CWE-193",
        "type": VulnerabilityType.OFF_BY_ONE,
        "severity": Severity.HIGH,
        "title": "Potential Off-by-One in array access",
        "pattern": r"(?:\w+)\s*\[\s*(?:\w+)\s*\+\s*1\s*\]",
        "message": "Array access at index+1 may overflow.",
        "fix": "Verify index bounds.",
        "category": "stack_overflow",
    },

    # ========== 命令注入 ==========
    {
        "id": "CWE-78",
        "type": VulnerabilityType.COMMAND_INJECTION,
        "severity": Severity.CRITICAL,
        "title": "Command Injection via system()",
        "pattern": r"system\s*\([^)]*(?:getenv|argv|user|input|param|request)",
        "message": "User input in system() may cause command injection.",
        "fix": "Avoid system() with user input. Use execve() with proper sanitization.",
        "category": "command_injection",
    },
    {
        "id": "CWE-78",
        "type": VulnerabilityType.COMMAND_INJECTION,
        "severity": Severity.CRITICAL,
        "title": "Command Injection via popen()",
        "pattern": r"popen\s*\([^)]*(?:getenv|argv|user|input|param|request)",
        "message": "User input in popen() may cause command injection.",
        "fix": "Sanitize input or avoid popen().",
        "category": "command_injection",
    },
    {
        "id": "CWE-78",
        "type": VulnerabilityType.COMMAND_INJECTION,
        "severity": Severity.CRITICAL,
        "title": "Command Injection via execl/execlp/execv",
        "pattern": r"(?:execl|execlp|execv|execve|execvp|execvpe)\s*\([^)]*(?:getenv|argv|user|input)",
        "message": "User input as command argument is dangerous.",
        "fix": "Validate and sanitize command arguments.",
        "category": "command_injection",
    },

    # ========== 二进制安全 - GOT/PLT 操纵 ==========
    {
        "id": "CWE-829",
        "type": VulnerabilityType.GOT_HIJACK,
        "severity": Severity.CRITICAL,
        "title": "Global Offset Table (GOT) Access",
        "pattern": r"(?:&|\*)\s*(?:free|printf|scanf|system|strcmp|memcpy|strcpy|strlen|malloc)\s*@@?GLIBC",
        "message": "Direct GOT access detected - potential GOT hijack target.",
        "fix": "Use GOT with caution. Consider RELRO protection.",
        "category": "binary_exploitation",
    },
    {
        "id": "CWE-829",
        "type": VulnerabilityType.FUNCTION_POINTER,
        "severity": Severity.CRITICAL,
        "title": "Dangerous Function Pointer",
        "pattern": r"(?:void\s*\*\s*\*|\(\s*\*\s*\w+\s*\))\s*\([^)]*\)\s*(?:;|=)",
        "message": "Function pointer manipulation detected.",
        "fix": "Validate function pointer targets.",
        "category": "binary_exploitation",
    },
    {
        "id": "CWE-829",
        "type": VulnerabilityType.VTABLE_HIJACK,
        "severity": Severity.CRITICAL,
        "title": "C++ Virtual Table (vtable) Access",
        "pattern": r"(?:->|\.)\s*vtable\s*(?:;|=)",
        "message": "Direct vtable access detected - potential vtable hijack.",
        "fix": "Ensure object integrity and validate vtable pointers.",
        "category": "binary_exploitation",
    },
    {
        "id": "CWE-754",
        "type": VulnerabilityType.FUNCTION_POINTER,
        "severity": Severity.HIGH,
        "title": "Callback Function Pointer",
        "pattern": r"(?:signal|atexit|atexit|setjmp|longjmp)\s*\(",
        "message": "Signal handler or callback registration detected.",
        "fix": "Ensure handler functions are secure and non-executable stacks.",
        "category": "binary_exploitation",
    },

    # ========== 条件竞争 ==========
    {
        "id": "CWE-362",
        "type": VulnerabilityType.RACE_CONDITION,
        "severity": Severity.HIGH,
        "title": "Concurrent Access without Lock",
        "pattern": r"(?:\bfree\b|\bfwrite\b|\fprintf\b)\s*\([^)]+\)[^;]*\n[^}]*(?:\bfree\b|\bfwrite\b|\bfprintf\b)",
        "message": "Potential race condition in concurrent code.",
        "fix": "Use mutex/lock to protect shared resources.",
        "category": "race_condition",
    },
    {
        "id": "CWE-367",
        "type": VulnerabilityType.TOCTOU,
        "severity": Severity.MEDIUM,
        "title": "Time-of-Check Time-of-Use (TOCTOU)",
        "pattern": r"(?:access|fopen|stat|rename)\s*\([^)]+\);\s*(?:if|while)",
        "message": "File checked then used - potential TOCTOU race.",
        "fix": "Perform operations atomically or use file descriptors.",
        "category": "race_condition",
    },

    # ========== 路径遍历 ==========
    {
        "id": "CWE-22",
        "type": VulnerabilityType.PATH_TRAVERSAL,
        "severity": Severity.HIGH,
        "title": "Potential Path Traversal",
        "pattern": r"(?:fopen|freopen|open|rename)\s*\([^)]*(?:\.\.|\%2e\%2e|/etc|/proc|/sys)",
        "message": "Path with ../ or sensitive paths detected.",
        "fix": "Sanitize and validate file paths.",
        "category": "path_traversal",
    },
    {
        "id": "CWE-22",
        "type": VulnerabilityType.PATH_TRAVERSAL,
        "severity": Severity.HIGH,
        "title": "User-Controlled Path",
        "pattern": r"(?:fopen|freopen|open|rename)\s*\([^)]*(?:getenv|argv|user|input|param|request)",
        "message": "User input used in file path - potential path traversal.",
        "fix": "Validate and sanitize user-controlled paths.",
        "category": "path_traversal",
    },

    # ========== 内存管理 ==========
    {
        "id": "CWE-457",
        "type": VulnerabilityType.UNINITIALIZED_POINTER,
        "severity": Severity.HIGH,
        "title": "Use of Uninitialized Pointer",
        "pattern": r"(?:struct\s+\w+\s*\*|void\s*\*\s*\w+)\s*(?:=|;)\s*(?:malloc|calloc)\s*\([^)]*\)",
        "message": "Pointer may be used before proper initialization.",
        "fix": "Initialize pointers before use.",
        "category": "memory_management",
    },
    {
        "id": "CWE-401",
        "type": VulnerabilityType.MEMORY_LEAK,
        "severity": Severity.MEDIUM,
        "title": "Potential Memory Leak",
        "pattern": r"(?:malloc|calloc|realloc)\s*\([^)]+\)[^;]*\n(?:[^}]|})*(?!\bfree\b)",
        "message": "Allocated memory may not be freed on all paths.",
        "fix": "Ensure every allocation has a corresponding free.",
        "category": "memory_management",
    },
    {
        "id": "CWE-822",
        "type": VulnerabilityType.DANGLING_POINTER,
        "severity": Severity.HIGH,
        "title": "Dangling Pointer",
        "pattern": r"(?:char|void|int|float|double|size_t)\s*\*\s*\w+\s*=\s*(?:realloc|free)\s*\([^)]+\)",
        "message": "Pointer may become dangling after realloc/free.",
        "fix": "Set pointer to NULL after realloc/free.",
        "category": "memory_management",
    },

    # ========== ROP 相关检测 ==========
    {
        "id": "CWE-94",
        "type": VulnerabilityType.RET2LIBC,
        "severity": Severity.CRITICAL,
        "title": "Return-to-libc / ROP Chain Pattern",
        "pattern": r"(?:pop|ret|jmp|call)\s*%?\s*(?:eax|ebx|ecx|edx|esi|edi|eip|rip|esp|rsp|rbp)",
        "message": "Potential ROP gadget pattern detected.",
        "fix": "Enable Stack Canary, PIE, and NX/DEP protections.",
        "category": "rop_exploitation",
    },
    {
        "id": "CWE-94",
        "type": VulnerabilityType.ROP_GADGET,
        "severity": Severity.CRITICAL,
        "title": "Stack Pivot Pattern",
        "pattern": r"(?:xchg|mov|lea)\s*%?\s*(?:rsp|esp)[^,]*(?:rbp|rbx|rdi|rsi)",
        "message": "Potential stack pivot gadget - allows stack moving.",
        "fix": "Enable stack canary and control-flow integrity.",
        "category": "rop_exploitation",
    },

    # ========== SROP ==========
    {
        "id": "CWE-94",
        "type": VulnerabilityType.ROP_GADGET,
        "severity": Severity.CRITICAL,
        "title": "Sigreturn Oriented Programming (SROP) Pattern",
        "pattern": r"(?:sigreturn|sigaction|signal)\s*\(",
        "message": "Signal handling detected - potential SROP target.",
        "fix": "Enable ASLR and limit sigaction usage.",
        "category": "srop",
    },

    # ========== SQL 注入 ==========
    {
        "id": "CWE-89",
        "type": VulnerabilityType.SQL_INJECTION,
        "severity": Severity.CRITICAL,
        "title": "SQL Injection - String Concatenation",
        "pattern": r"(?:sprintf|strcpy|strcat|strdup)\s*\([^)]*(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|query)",
        "message": "SQL query built via string manipulation is vulnerable.",
        "fix": "Use parameterized queries or prepared statements.",
        "category": "sql_injection",
    },
    {
        "id": "CWE-89",
        "type": VulnerabilityType.SQL_INJECTION,
        "severity": Severity.CRITICAL,
        "title": "SQL Injection - Direct Query Execution",
        "pattern": r"(?:mysql_query|sqlite3_exec|pg_query|exec_sql)\s*\([^)]*(?:\+|concat\()",
        "message": "Query built with concatenation may be injectable.",
        "fix": "Use parameterized queries.",
        "category": "sql_injection",
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
