"""
CTF Pwn 分析模块 - 针对 CTF 竞赛和 Pwn 题目的专门分析
"""
import re
from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum


class ExploitationTechnique(Enum):
    """利用技术分类"""
    STACK_OVERFLOW = "stack_overflow"
    HEAP_EXPLOITATION = "heap_exploitation"
    FORMAT_STRING = "format_string"
    ROP_CHAIN = "rop_chain"
    JOP = "jump_oriented_programming"
    COP = "call_oriented_programming"
    SROP = "sigreturn_rop"
    RET2DL = "ret2dlresolve"
    RET2VDSO = "ret2vdso"
    INTEGER_EXPLOITATION = "integer_exploitation"
    RACE_CONDITION = "race_condition"


@dataclass
class ExploitPattern:
    """利用模式信息"""
    name: str
    technique: ExploitationTechnique
    description: str
    detection_patterns: List[str]
    severity: str  # "easy", "medium", "hard"
    exploit_difficulty: int  # 1-10, 10 越难利用
    mitigations: List[str]


@dataclass
class PwnAnalysisResult:
    """Pwn 分析结果"""
    file_path: str
    patterns_found: List[ExploitPattern]
    vulnerability_hints: List[str]
    exploitation_difficulty: int  # 1-10
    suggested_exploits: List[str]
    warnings: List[str]


# CTF Pwn 常见利用模式
PWN_PATTERNS = [
    # ========== 栈溢出模式 ==========
    {
        "name": "Basic Stack Overflow",
        "technique": ExploitationTechnique.STACK_OVERFLOW,
        "description": "最基础的栈溢出，可通过溢出覆盖返回地址",
        "patterns": [
            r"char\s+\w+\s*\[\s*(?:64|128|256|512|1024)\s*\]",  # 大型栈缓冲区
            r"gets\s*\(",  # gets 不检查长度
            r"strcpy\s*\(",  # strcpy 不检查长度
            r"memcpy\s*\([^,]+,\s*[^,]+,\s*strlen\s*\(",  # 基于 strlen 的 memcpy
            r"scanf\s*\(\s*\"%[^\"]*\"\s*,\s*(?:\w+|&\w+)\s*\)(?!\s*,\s*\d+)",  # 无长度限制的 scanf
        ],
        "severity": "easy",
        "exploit_difficulty": 3,
        "mitigations": ["NX", "Canary", "PIE"],
    },
    {
        "name": "Off-by-One Stack Overflow",
        "technique": ExploitationTechnique.STACK_OVERFLOW,
        "description": "单字节溢出，通常用于覆盖 Canary 或栈指针",
        "patterns": [
            r"for\s*\([^)]*<=\s*\w+\s*\)",  # 错误的循环边界
            r"strlen\s*\([^)]*\)\s*[><=]",  # 基于 strlen 的比较
            r"strncpy\s*\([^,]+,\s*[^,]+,\s*sizeof\s*\(",  # sizeof 用错
        ],
        "severity": "medium",
        "exploit_difficulty": 5,
        "mitigations": ["Canary", "PIE"],
    },
    {
        "name": "Stack Buffer Overflow with Function Pointer",
        "technique": ExploitationTechnique.STACK_OVERFLOW,
        "description": "栈溢出覆盖函数指针进行劫持",
        "patterns": [
            r"void\s*\(?\*\s*\w+\s*\)\s*\([^)]*\)",  # 函数指针声明
            r"\(\s*\*\s*\w+\s*\)\s*=",  # 函数指针赋值
            r"memcpy\s*\([^,]+,\s*[^,]+,\s*(?:0x)?[1-9][0-9]*\s*\)",  # 复制到函数指针附近
        ],
        "severity": "easy",
        "exploit_difficulty": 2,
        "mitigations": ["NX", "CFI"],
    },

    # ========== 堆利用模式 ==========
    {
        "name": "Use After Free (UAF)",
        "technique": ExploitationTechnique.HEAP_EXPLOITATION,
        "description": "释放后使用，可用于任意地址读写",
        "patterns": [
            r"free\s*\([^)]+\)\s*;\s*\n\s*\w+\s*\(",  # free 后直接使用
            r"delete\s+\w+",  # C++ delete
            r"free\s*\([^)]+\)[^;]*\n\s*(?:\w+\[|\*\w+)",  # free 后数组访问
            r"use[_-]?after[_-]?free",  # 注释中的 UAF
        ],
        "severity": "easy",
        "exploit_difficulty": 4,
        "mitigations": ["Heap Canary", "Safe Unlinking"],
    },
    {
        "name": "Double Free",
        "technique": ExploitationTechnique.HEAP_EXPLOITATION,
        "description": "双重释放，可用于堆风水和任意地址分配",
        "patterns": [
            r"free\s*\([^)]+\)\s*;\s*\n\s*free\s*\([^)]+\)",  # 连续 free
            r"delete\s+\w+\s*;\s*\n\s*delete\s+\w+",  # C++ 连续 delete
            r"if\s*\([^)]+\)\s*free\s*\([^)]+\)\s*;\s*\n\s*free\s*\([^)]+\)",  # 条件双 free "severity":
        ],
        "easy",
        "exploit_difficulty": 4,
        "mitigations": ["Safe Unlinking", "Tcache Sanity"],
    },
    {
        "name": "Heap Overflow",
        "technique": ExploitationTechnique.HEAP_EXPLOITATION,
        "description": "堆缓冲区溢出，可用于覆盖下一个 chunk 的元数据",
        "patterns": [
            r"memcpy\s*\([^,]+,\s*[^,]+,\s*(?:sizeof\s*\w+|(?:\w+))\)",  # 基于源大小的 memcpy
            r"strcpy\s*\([^,]+,\s*[^,]+\)",  # 无长度限制的 strcpy
            r"sprintf\s*\([^,]+,\s*\"%[^\"]*\"\s*,\s*\w+\s*\)",  # sprintf 溢出
        ],
        "severity": "medium",
        "exploit_difficulty": 5,
        "mitigations": ["Heap Canary", "Safe Unlinking"],
    },
    {
        "name": "House of Spirit",
        "technique": ExploitationTechnique.HEAP_EXPLOITATION,
        "description": "在栈上构造伪 chunk 欺骗分配器",
        "patterns": [
            r"memcpy\s*\([^,]+,\s*\"\\x00\\x00\\x00\\x00",  # 构造 fake chunk
            r"malloc\s*\(\s*(?:\w+|sizeof)",  # 分配大小可控
            r"memcpy\s*\([^,]+,\s*&?\w+,\s*(?:0x)?[78][0-9a-fA-F]\s*\)",  # 构造 chunk
        ],
        "severity": "hard",
        "exploit_difficulty": 7,
        "mitigations": ["Safe Unlinking", "Double Free Checks"],
    },
    {
        "name": "House of Force",
        "technique": ExploitationTechnique.HEAP_EXPLOITATION,
        "description": "利用 top chunk 溢出分配任意地址",
        "patterns": [
            r"malloc\s*\(\s*-(?:\d+|0x[0-9a-fA-F]+)\s*\)",  # 负大小 malloc
            r"malloc\s*\(\s*(?:\w+|sizeof)[^)]*\)",  # malloc 大小可控
            r"memcpy\s*\([^,]+,\s*[^,]+,\s*(?:\w+)\s*\)[^;]*malloc",  # memcpy 后 malloc
        ],
        "severity": "hard",
        "exploit_difficulty": 8,
        "mitigations": ["Top Chunk Guard"],
    },
    {
        "name": "House of Lore",
        "technique": ExploitationTechnique.HEAP_EXPLOITATION,
        "description": "伪造 small bin 进行地址泄露",
        "patterns": [
            r"malloc\s*\([^)]+\);\s*\n\s*free\s*\([^)]+\)",  # malloc then free
            r"memcpy\s*\([^,]+,\s*[^,]+,\s*(?:0x)?20\s*\)",  # 伪造 bin 元数据
        ],
        "severity": "hard",
        "exploit_difficulty": 8,
        "mitigations": ["Safe Unlinking"],
    },
    {
        "name": "Unsorted Bin Attack",
        "technique": ExploitationTechnique.HEAP_EXPLOITATION,
        "description": "利用 unsorted bin 写入任意地址",
        "patterns": [
            r"free\s*\([^)]+\);\s*\n\s*\w+\s*=\s*malloc",  # free 后 malloc
            r"malloc\s*\([^)]+\);\s*\n\s*free\s*\([^)]+\)",  # malloc 后 free
            r"unsorted.*bin",  # 注释提及 unsorted bin
        ],
        "severity": "medium",
        "exploit_difficulty": 6,
        "mitigations": ["Unsorted Bin Checks"],
    },
    {
        "name": "Tcache Attack",
        "technique": ExploitationTechnique.HEAP_EXPLOITATION,
        "description": "利用 tcache 的弱检查进行利用",
        "patterns": [
            r"tcache",  # tcache 相关代码
            r"malloc\s*\(\s*(?:\d+|0x[0-9a-fA-F]+)\s*\)",  # tcache 分配
            r"free\s*\([^)]+\)\s*;\s*\n\s*\w+\s*=\s*malloc",  # 简单的 tcache 利用模式
        ],
        "severity": "easy",
        "exploit_difficulty": 3,
        "mitigations": ["Tcache Sanity Checks"],
    },

    # ========== 格式化字符串 ==========
    {
        "name": "Format String Leak",
        "technique": ExploitationTechnique.FORMAT_STRING,
        "description": "格式化字符串漏洞，可泄露内存",
        "patterns": [
            r"printf\s*\(\s*(?:\w+)\s*\)",  # 可变的 printf
            r"fprintf\s*\(\s*\w+\s*,\s*(?:\w+)\s*\)",  # 可变的 fprintf
            r"syslog\s*\([^,)]*\s*,\s*(?:\w+)\s*\)",  # 可变的 syslog
        ],
        "severity": "medium",
        "exploit_difficulty": 3,
        "mitigations": ["FORTIFY_SOURCE"],
    },
    {
        "name": "Format String Write",
        "technique": ExploitationTechnique.FORMAT_STRING,
        "description": "格式化字符串写入任意地址",
        "patterns": [
            r"printf\s*\(\s*(?:\w+)\s*\)",  # 可变的 printf
            r"%[0-9]*[nxdfs]",  # 格式化字符串
            r"\*0x[0-9a-fA-F]+",  # 可能的地址写入
        ],
        "severity": "easy",
        "exploit_difficulty": 3,
        "mitigations": ["FORTIFY_SOURCE", "PIE"],
    },

    # ========== ROP 相关 ==========
    {
        "name": "ROP with plt functions",
        "technique": ExploitationTechnique.ROP_CHAIN,
        "description": "调用 PLT 函数构造 ROP 链",
        "patterns": [
            r"puts@plt|printf@plt|read@plt|write@plt|system@plt",  # PLT 函数调用
            r"mov.*edi.*ret",  # 调用约定 gadget
            r"pop.*ret",  # pop ret gadget
        ],
        "severity": "medium",
        "exploit_difficulty": 5,
        "mitigations": ["NX", "Canary", "PIE"],
    },
    {
        "name": "ret2libc",
        "technique": ExploitationTechnique.ROP_CHAIN,
        "description": "返回到 libc 获取 shell",
        "patterns": [
            r"system\s*\(@?GLIBC",  # system 函数
            r"/bin/sh|/sh",  # /bin/sh 字符串
            r"printf@GLIBC|gets@GLIBC",  # libc 函数
        ],
        "severity": "medium",
        "exploit_difficulty": 4,
        "mitigations": ["NX", "ASLR"],
    },
    {
        "name": "ret2syscall",
        "technique": ExploitationTechnique.ROP_CHAIN,
        "description": "构造系统调用获取 shell",
        "patterns": [
            r"syscall",  # syscall 指令
            r"int\s+0x80",  # int 0x80 系统调用
            r"execve",  # execve 系统调用
        ],
        "severity": "medium",
        "exploit_difficulty": 5,
        "mitigations": ["NX", "seccomp"],
    },
    {
        "name": "SROP (Sigreturn ROP)",
        "technique": ExploitationTechnique.SROP,
        "description": "利用 sigreturn 进行控制流劫持",
        "patterns": [
            r"sigreturn",  # sigreturn
            r"sigaction",  # sigaction
            r"signal\s*\([^,]+,\s*(?:SIG|SIG_\w+)\s*\)",  # signal 设置
            r"ucontext",  # ucontext 结构体
        ],
        "severity": "hard",
        "exploit_difficulty": 8,
        "mitigations": ["Signal Guard", "NX"],
    },
    {
        "name": "ret2dlresolve",
        "technique": ExploitationTechnique.RET2DL,
        "description": "动态链接器解析漏洞，绕过 ASLR",
        "patterns": [
            r"dl_resolve|dl_runtime",  # 动态链接相关
            r"Link_map",  # Link_map 结构
            r"_dl_fixup",  # 解析函数
        ],
        "severity": "hard",
        "exploit_difficulty": 9,
        "mitigations": ["Full RELRO", "DFL"],
    },
    {
        "name": "ret2vdso/vsyscall",
        "technique": ExploitationTechnique.RET2VDSO,
        "description": "利用 VDSO 绕过某些保护",
        "patterns": [
            r"vdso",  # vdso 相关
            r"vsyscall",  # vsyscall
            r"gettimeofday.*@.*vdso",  # vdso 函数
        ],
        "severity": "hard",
        "exploit_difficulty": 8,
        "mitigations": ["vdso randomization"],
    },

    # ========== 整数溢出 ==========
    {
        "name": "Integer Overflow to Heap Overflow",
        "technique": ExploitationTechnique.INTEGER_EXPLOITATION,
        "description": "整数溢出导致分配过小缓冲区",
        "patterns": [
            r"(?:\w+)\s*\+\s*(?:\w+)\s*(?:\|\||&&)",  # 整数加法条件
            r"(?:\w+)\s*\*\s*(?:\w+)",  # 整数乘法
            r"malloc\s*\((?:\w+)\s*\+\s*(?:\w+)\)",  # malloc 大小计算
        ],
        "severity": "medium",
        "exploit_difficulty": 5,
        "mitigations": ["Integer Overflow Checks"],
    },
    {
        "name": "Signed to Unsigned Conversion",
        "technique": ExploitationTechnique.INTEGER_EXPLOITATION,
        "description": "有符号转无符号导致负数变成大正数",
        "patterns": [
            r"size_t\s+\w+\s*=\s*(?:\w+)",  # size_t 赋值
            r"unsigned\s+(?:int|short|long)\s+\w+\s*=\s*(?:-\w+)",  # 负数转无符号
            r"if\s*\(\s*(?:\w+)\s*(?:>=|<=)\s*0\s*\)",  # 符号检查后转无符号
        ],
        "severity": "medium",
        "exploit_difficulty": 5,
        "mitigations": ["Signed/Unsigned Checks"],
    },

    # ========== 条件竞争 ==========
    {
        "name": "TOCTOU Race Condition",
        "technique": ExploitationTechnique.RACE_CONDITION,
        "description": "检查-使用时间竞争",
        "patterns": [
            r"access\s*\([^)]+\)\s*;\s*\n\s*(?:if|)\s*\([^)]+\)\s*(?:fopen|open)",  # 检查后打开
            r"stat\s*\([^)]+\)\s*;\s*\n\s*(?:if|)\s*\([^)]+\)\s*(?:fopen|open|unlink)",  # stat 后操作
            r"lstat\s*\([^)]+\)\s*;\s*\n",  # lstat 检查
        ],
        "severity": "medium",
        "exploit_difficulty": 6,
        "mitigations": ["Atomic Operations"],
    },
    {
        "name": "Use After Free (Race)",
        "technique": ExploitationTechnique.RACE_CONDITION,
        "description": "多线程 use-after-free",
        "patterns": [
            r"pthread|pthread_create",  # 多线程代码
            r"free\s*\([^)]+\)\s*;",  # free
            r"(?:\w+)\s*\(\s*\)",  # 函数调用
        ],
        "severity": "medium",
        "exploit_difficulty": 7,
        "mitigations": ["Thread Sanitizer", "Mutex"],
    },
]


def analyze_pwn_patterns(file_path: str, content: str) -> PwnAnalysisResult:
    """分析 CTF Pwn 漏洞模式"""
    patterns_found = []
    vulnerability_hints = []
    warnings = []
    all_difficulties = []

    # 检查每种模式
    for pattern_info in PWN_PATTERNS:
        for pattern in pattern_info["patterns"]:
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                patterns_found.append(ExploitPattern(
                    name=pattern_info["name"],
                    technique=pattern_info["technique"],
                    description=pattern_info["description"],
                    detection_patterns=pattern_info["patterns"],
                    severity=pattern_info["severity"],
                    exploit_difficulty=pattern_info["exploit_difficulty"],
                    mitigations=pattern_info["mitigations"],
                ))
                all_difficulties.append(pattern_info["exploit_difficulty"])
                break

    # 计算总体利用难度
    if all_difficulties:
        exploitation_difficulty = int(sum(all_difficulties) / len(all_difficulties))
    else:
        exploitation_difficulty = 1

    # 生成漏洞提示
    for pattern in patterns_found:
        hint = f"[{pattern.technique.value.upper()}] {pattern.name}"
        vulnerability_hints.append(hint)

    # 生成警告
    for pattern in patterns_found:
        if pattern.severity == "easy":
            warnings.append(
                f"⚠️  {pattern.name}: 容易利用，建议立即修复"
            )
        elif pattern.severity == "medium":
            warnings.append(
                f"🟡 {pattern.name}: 中等难度利用，建议修复"
            )

    # 建议的利用方法
    suggested_exploits = []
    for pattern in patterns_found:
        if pattern.technique == ExploitationTechnique.STACK_OVERFLOW:
            suggested_exploits.append(f"栈溢出利用: 覆盖返回地址 → ROP 链")
        elif pattern.technique == ExploitationTechnique.HEAP_EXPLOITATION:
            suggested_exploits.append(f"堆利用: UAF → 任意地址读写 → shell")
        elif pattern.technique == ExploitationTechnique.FORMAT_STRING:
            suggested_exploits.append(f"格式化字符串: 泄露 → 写入 → 控制流")
        elif pattern.technique == ExploitationTechnique.ROP_CHAIN:
            suggested_exploits.append(f"ROP: 构造 gadgets → 调用 system('/bin/sh')")
        elif pattern.technique == ExploitationTechnique.SROP:
            suggested_exploits.append(f"SROP: 伪造 sigreturn frame → syscall")

    suggested_exploits = list(set(suggested_exploits))  # 去重

    return PwnAnalysisResult(
        file_path=file_path,
        patterns_found=patterns_found,
        vulnerability_hints=vulnerability_hints,
        exploitation_difficulty=exploitation_difficulty,
        suggested_exploits=suggested_exploits,
        warnings=warnings,
    )


def print_pwn_analysis(result: PwnAnalysisResult):
    """打印 Pwn 分析结果"""
    print("\n" + "=" * 60)
    print("🎯 CTF Pwn 分析报告")
    print("=" * 60)
    print(f"📄 文件: {result.file_path}")
    print(f"⚔️  利用难度: {result.exploitation_difficulty}/10")
    print(f"🔍 发现模式: {len(result.patterns_found)} 个")
    print("")

    if result.patterns_found:
        print("📋 发现的可利用模式:")
        for pattern in result.patterns_found:
            print(f"  [{pattern.technique.value}] {pattern.name}")
            print(f"    难度: {pattern.exploit_difficulty}/10")
            print(f"    描述: {pattern.description}")
            print(f"    缓解: {' '.join(pattern.mitigations)}")

    if result.warnings:
        print("\n⚠️  警告:")
        for warning in result.warnings:
            print(f"  {warning}")

    if result.suggested_exploits:
        print("\n💡 可能的利用思路:")
        for exploit in result.suggested_exploits:
            print(f"  → {exploit}")
