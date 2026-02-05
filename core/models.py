"""
核心数据结构定义
"""
from dataclasses import dataclass, field
from typing import Optional, Literal
from enum import Enum


class Severity(Enum):
    """漏洞严重等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(Enum):
    """漏洞类型（CWE 对应）"""
    # CWE Top 10 2021
    INJECTION = "CWE-79"  # Cross-site Scripting
    BROKEN_AUTH = "CWE-307"  # Broken Authentication
    SENSITIVE_DATA = "CWE-259"  # Hard-coded Credentials
    XXE = "CWE-611"  # XML External Entities
    BROKEN_ACCESS = "CWE-862"  # Missing Authorization
    SECURITY_MISCONFIG = "CWE-916"  # Use of Insufficiently Random Values
    XSS = "CWE-79"  # Cross-Site Scripting
    INSECURE_DESERIALIZATION = "CWE-502"  # Deserialization of Untrusted Data
    VULNERABLE_COMPONENTS = "CWE-1104"  # Use of Unmaintained Third Party Components
    INSUFFICIENT_LOGGING = "CWE-778"  # Insufficient Logging

    # C/C++ 特有
    BUFFER_OVERFLOW = "CWE-120"  # Buffer Overflow
    FORMAT_STRING = "CWE-134"  # Use of Externally-Controlled Format String
    INTEGER_OVERFLOW = "CWE-190"  # Integer Overflow or Wraparound
    NULL_POINTER = "CWE-476"  # NULL Pointer Dereference
    USE_AFTER_FREE = "CWE-416"  # Use After Free
    UNINITIALIZED_MEMORY = "CWE-908"  # Use of Uninitialized Resource
    RACE_CONDITION = "CWE-362"  # Concurrent Execution Using Shared Resource with Improper Synchronization

    # OWASP Top 10 2025 扩展
    SQL_INJECTION = "CWE-89"  # SQL注入
    COMMAND_INJECTION = "CWE-78"  # 命令注入
    CODE_INJECTION = "CWE-94"  # 代码注入
    LDAP_INJECTION = "CWE-90"  # LDAP注入
    XPATH_INJECTION = "CWE-643"  # XPath注入
    SSRF = "CWE-918"  # 服务端请求伪造
    STACK_OVERFLOW = "CWE-121"  # 栈溢出
    HEAP_OVERFLOW = "CWE-122"  # 堆溢出
    OFF_BY_ONE = "CWE-193"  # Off-by-One
    INTEGER_UNDERFLOW = "CWE-191"  # 整数下溢
    DOUBLE_FREE = "CWE-415"  # 双重释放
    UNAUTHORIZED_ACCESS = "CWE-284"  # 未授权访问
    WEAK_PASSWORD = "CWE-328"  # 弱密码
    SESSION_MANAGEMENT = "CWE-384"  # 会话管理问题
    PRIVILEGE_ESCALATION = "CWE-269"  # 权限提升
    SENSITIVE_DATA_EXPOSURE = "CWE-200"  # 敏感信息泄露
    CRYPTO_FAILURES = "CWE-310"  # 加密失败
    WEAK_ENCRYPTION = "CWE-328"  # 弱加密
    HARD_CODED_CREDENTIAL = "CWE-798"  # 硬编码凭据
    INSECURE_RANDOM = "CWE-338"  # 弱随机数
    PATH_TRAVERSAL = "CWE-22"  # 路径遍历
    ARBITRARY_FILE_READ = "CWE-22"  # 任意文件读取
    ARBITRARY_FILE_WRITE = "CWE-22"  # 任意文件写入
    CSRF = "CWE-352"  # 跨站请求伪造
    IDOR = "CWE-639"  # 不安全直接对象引用
    VULNERABLE_DEPENDENCY = "CWE-1104"  # 漏洞依赖
    TOCTOU = "CWE-367"  # TOCTOU竞争条件
    INSECURE_DESIGN = "CWE-693"  # 不安全设计
    INSECURE_SSL = "CWE-295"  # SSL配置问题
    MISSING_RATE_LIMIT = "CWE-307"  # 缺少速率限制
    MEMORY_LEAK = "CWE-401"  # 内存泄漏
    LOGGING_ISSUES = "CWE-778"  # 日志问题
    BRUTE_FORCE = "CWE-307"  # 暴力破解
    SENSITIVE_DATA_LOGGING = "CWE-532"  # 敏感数据日志
    WEAK_AUTHENTICATION = "CWE-287"  # 弱认证
    
    # 二进制安全相关
    GOT_HIJACK = "CWE-829"  # GOT表劫持
    VTABLE_HIJACK = "CWE-829"  # VTable劫持
    FUNCTION_POINTER = "CWE-754"  # 函数指针危险使用
    ROP_GADGET = "CWE-94"  # ROP Gadget
    RET2LIBC = "CWE-94"  # Ret2libc
    UNINITIALIZED_POINTER = "CWE-457"  # 未初始化指针
    DANGLING_POINTER = "CWE-822"  # 悬空指针
    
    UNKNOWN = "CWE-0"  # 未知


@dataclass
class Location:
    """漏洞位置"""
    file: str
    line: int
    column: int = 0
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    def __str__(self):
        return f"{self.file}:{self.line}"


@dataclass
class Vulnerability:
    """漏洞信息"""
    id: str  # 唯一标识
    type: VulnerabilityType  # 漏洞类型
    severity: Severity  # 严重等级
    title: str  # 漏洞标题
    description: str  # 详细描述
    location: Location  # 位置
    code_snippet: str  # 相关代码片段
    cwe_id: str  # CWE 编号
    confidence: float = 0.0  # AI 判断的可信度 (0-1)
    ai_verified: bool = False  # 是否经过 AI 验证
    fix_suggestion: Optional[str] = None  # 修复建议

    # AI 验证相关
    ai_analysis: Optional[str] = None
    ai_verification_result: Optional[Literal["confirmed", "false_positive", "uncertain"]] = None


@dataclass
class ScanResult:
    """扫描结果"""
    target: str
    total_files: int = 0
    total_lines: int = 0
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    scan_time_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

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

    def summary(self) -> str:
        return (
            f"扫描结果:\n"
            f"  文件数: {self.total_files}\n"
            f"  代码行数: {self.total_lines}\n"
            f"  漏洞统计:\n"
            f"    🔴 Critical: {self.critical_count}\n"
            f"    🟠 High: {self.high_count}\n"
            f"    🟡 Medium: {self.medium_count}\n"
            f"    🟢 Low: {self.low_count}\n"
            f"  耗时: {self.scan_time_seconds:.2f}秒"
        )
