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
