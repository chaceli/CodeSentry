"""
CodeSentry Core - 漏洞分析核心模块
"""
from .models import (
    Severity,
    VulnerabilityType,
    Location,
    Vulnerability,
    ScanResult,
)

from .analyzer import (
    analyze_file,
    analyze_directory,
    print_result,
    RULES,
)

from .elf_analyzer import (
    BinaryProtection,
    Gadget,
    FunctionInfo,
    BinaryAnalysisResult,
    analyze_elf,
    check_protections,
    find_rop_gadgets,
    print_binary_analysis,
)

from .pwn_analyzer import (
    ExploitationTechnique,
    ExploitPattern,
    PwnAnalysisResult,
    analyze_pwn_patterns,
    print_pwn_analysis,
    PWN_PATTERNS,
)

__all__ = [
    # Models
    "Severity",
    "VulnerabilityType",
    "Location",
    "Vulnerability",
    "ScanResult",
    # Analyzer
    "analyze_file",
    "analyze_directory",
    "print_result",
    "RULES",
    # ELF Analyzer
    "BinaryProtection",
    "Gadget",
    "FunctionInfo",
    "BinaryAnalysisResult",
    "analyze_elf",
    "check_protections",
    "find_rop_gadgets",
    "print_binary_analysis",
    # Pwn Analyzer
    "ExploitationTechnique",
    "ExploitPattern",
    "PwnAnalysisResult",
    "analyze_pwn_patterns",
    "print_pwn_analysis",
    "PWN_PATTERNS",
]
