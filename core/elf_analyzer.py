"""
ELF 二进制分析器 - 支持 Pwn 相关漏洞检测
"""
import subprocess
import re
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Dict
from enum import Enum


class BinaryProtection(Enum):
    """二进制安全保护机制"""
    NX = "NX (Non-Executable Stack)"  # 栈不可执行
    CANARY = "Stack Canary"  # 栈保护
    PIE = "PIE (Position Independent Executable)"  # 位置无关可执行
    RELRO = "RELRO (RELocation Read-Only)"  # 重定位只读
    FORTIFY = "FORTIFY_SOURCE"  # 强化检查
    ASLR = "ASLR (Address Space Layout Randomization)"  # 地址空间布局随机化


@dataclass
class Gadget:
    """ROP/JOP/COP Gadget"""
    address: str
    instruction: str
    category: str  # "pop", "mov", "xor", "syscall", etc.
    danger_level: int  # 0-10, 越高越危险


@dataclass
class FunctionInfo:
    """函数信息"""
    name: str
    address: str
    size: int
    has_arguments: bool
    uses_pointers: bool


@dataclass
class BinaryAnalysisResult:
    """二进制分析结果"""
    file_path: str
    architecture: str  # "x86_64", "x86", "arm", "mips"
    protections: Dict[BinaryProtection, bool]
    gadgets: List[Gadget]
    functions: List[FunctionInfo]
    vulnerabilities: List[str]
    is_stripped: bool
    is_static: bool

    @property
    def has_nx(self) -> bool:
        return self.protections.get(BinaryProtection.NX, False)

    @property
    def has_canary(self) -> bool:
        return self.protections.get(BinaryProtection.CANARY, False)

    @property
    def has_pie(self) -> bool:
        return self.protections.get(BinaryProtection.PIE, False)

    @property
    def has_relro(self) -> bool:
        return self.protections.get(BinaryProtection.RELRO, False)

    @property
    def danger_level(self) -> int:
        """综合危险等级"""
        score = 0
        if not self.has_nx:
            score += 3  # 可执行栈
        if not self.has_canary:
            score += 2  # 无栈保护
        if not self.has_pie:
            score += 2  # 无 PIE
        if not self.has_relro:
            score += 2  # GOT 可写
        return min(score, 10)


def check_protections(file_path: str) -> Dict[BinaryProtection, bool]:
    """检查二进制保护机制"""
    protections = {
        BinaryProtection.NX: False,
        BinaryProtection.CANARY: False,
        BinaryProtection.PIE: False,
        BinaryProtection.RELRO: False,
        BinaryProtection.FORTIFY: False,
        BinaryProtection.ASLR: False,
    }

    try:
        result = subprocess.run(
            ["checksec", "--file", file_path],
            capture_output=True,
            text=True,
            timeout=10
        )

        output = result.stdout + result.stderr

        if "NX: disabled" in output or "NX: 0" in output:
            protections[BinaryProtection.NX] = False
        elif "NX: enabled" in output or "NX: 1" in output:
            protections[BinaryProtection.NX] = True

        if "Canary: found" in output or "Canary: 1" in output:
            protections[BinaryProtection.CANARY] = True

        if "PIE: enabled" in output or "PIE: 1" in output:
            protections[BinaryProtection.PIE] = True

        if "Full RELRO" in output:
            protections[BinaryProtection.RELRO] = True
        elif "Partial RELRO" in output:
            protections[BinaryProtection.RELRO] = True  # 部分也算有

        if "FORTIFY" in output or "Fortified" in output:
            protections[BinaryProtection.FORTIFY] = True

    except Exception as e:
        print(f"[WARNING] checksec failed: {e}")

    # ASLR 在运行时检查
    try:
        result = subprocess.run(
            ["cat", "/proc/sys/kernel/randomize_va_space"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.stdout.strip() != "0":
            protections[BinaryProtection.ASLR] = True
    except:
        pass

    return protections


def find_rop_gadgets(file_path: str) -> List[Gadget]:
    """使用 ROPgadget 或 ropper 查找 ROP gadgets"""
    gadgets = []

    # 危险 gadgets 类别
    dangerous_patterns = [
        ("syscall", 10),
        ("int 0x80", 10),
        ("execve", 9),
        ("pop rdi", 8),
        ("pop rsi", 7),
        ("pop rdx", 7),
        ("pop rax", 7),
        ("mov rax", 6),
        ("xchg", 5),
        ("jmp rax", 8),
        ("jmp rdi", 8),
        ("call rax", 8),
        ("ret", 1),
    ]

    try:
        # 使用 ROPgadget
        result = subprocess.run(
            ["ROPgadget", "--binary", file_path, "--nosys"],
            capture_output=True,
            text=True,
            timeout=30
        )

        for line in result.stdout.split("\n"):
            if "0x" in line and ("ret" in line.lower() or "pop" in line.lower()):
                # 解析 gadget
                try:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        addr = parts[0].strip()
                        instr = parts[1].strip()

                        # 分类 gadget
                        category = "other"
                        danger = 1

                        for pattern, level in dangerous_patterns:
                            if pattern.lower() in instr.lower():
                                category = pattern.split()[0].lower()
                                danger = level
                                break

                        gadgets.append(Gadget(
                            address=addr,
                            instruction=instr,
                            category=category,
                            danger_level=danger
                        ))
                except:
                    pass
    except FileNotFoundError:
        # 尝试使用 ropper
        try:
            result = subprocess.run(
                ["ropper", "--file", file_path, "--nocolor"],
                capture_output=True,
                text=True,
                timeout=30
            )

            for line in result.stdout.split("\n"):
                if "0x" in line and "ret" in line.lower():
                    try:
                        parts = line.split()
                        if len(parts) >= 2:
                            addr = parts[0]
                            instr = " ".join(parts[1:])

                            gadgets.append(Gadget(
                                address=addr,
                                instruction=instr,
                                category="ret",
                                danger_level=1
                            ))
                    except:
                        pass
        except FileNotFoundError:
            print("[INFO] ROPgadget/ropper not installed. Skipping gadget search.")

    return gadgets


def analyze_elf(file_path: str) -> BinaryAnalysisResult:
    """完整的 ELF 二进制分析"""
    result = BinaryAnalysisResult(
        file_path=file_path,
        architecture="unknown",
        protections={},
        gadgets=[],
        functions=[],
        vulnerabilities=[],
        is_stripped=False,
        is_static=False
    )

    # 1. 检查文件类型
    try:
        file_result = subprocess.run(
            ["file", file_path],
            capture_output=True,
            text=True,
            timeout=10
        )

        output = file_result.stdout

        # 架构检测
        if "x86-64" in output or "ELF 64-bit" in output:
            result.architecture = "x86_64"
        elif "Intel 80386" in output or "ELF 32-bit" in output:
            result.architecture = "x86"
        elif "ARM" in output:
            result.architecture = "arm"
        elif "MIPS" in output:
            result.architecture = "mips"

        # 是否 strip
        if "not stripped" in output:
            result.is_stripped = False
        elif "stripped" in output:
            result.is_stripped = True

        # 是否静态链接
        if "statically linked" in output:
            result.is_static = True

    except Exception as e:
        print(f"[WARNING] file command failed: {e}")

    # 2. 检查保护机制
    result.protections = check_protections(file_path)

    # 3. 查找 ROP gadgets（仅对非 strip 的二进制有效）
    if not result.is_stripped:
        result.gadgets = find_rop_gadgets(file_path)

    # 4. 分析漏洞
    result.vulnerabilities = analyze_vulnerabilities(result)

    return result


def analyze_vulnerabilities(result: BinaryAnalysisResult) -> List[str]:
    """基于分析结果生成漏洞报告"""
    vulns = []

    # 检查各种危险配置
    if not result.has_nx:
        vulns.append(
            "⚠️  可执行栈 (NX disabled): 攻击者可通过栈注入代码执行"
        )

    if not result.has_canary:
        vulns.append(
            "⚠️  无栈保护 (No Canary): 无法检测栈溢出"
        )

    if not result.has_pie:
        vulns.append(
            "⚠️  无 PIE 保护: 二进制地址固定，易于 ROP 攻击"
        )

    if not result.has_relro:
        vulns.append(
            "⚠️  RELRO 未启用: GOT 表可写，可被劫持"
        )

    # 检查危险 gadgets
    syscall_gadgets = [g for g in result.gadgets if "syscall" in g.category.lower()]
    if syscall_gadgets:
        vulns.append(
            f"🔴 发现 {len(syscall_gadgets)} 个 syscall gadgets，可能用于执行任意系统调用"
        )

    pop_rdi = [g for g in result.gadgets if "pop rdi" in g.instruction.lower()]
    if pop_rdi:
        vulns.append(
            "🟠 发现 'pop rdi; ret' gadget，配合 one-gadget 可获取 shell"
        )

    return vulns


def print_binary_analysis(result: BinaryAnalysisResult):
    """打印二进制分析结果"""
    print("\n" + "=" * 60)
    print("🔍 二进制安全分析报告")
    print("=" * 60)
    print(f"📄 文件: {result.file_path}")
    print(f"🏗️  架构: {result.architecture}")
    print(f"📦 静态链接: {'是' if result.is_static else '否'}")
    print(f"🏷️  Stripped: {'是' if result.is_stripped else '否'}")
    print("")

    print("🛡️  安全保护机制:")
    print(f"  {'✅' if result.has_nx else '❌'} NX (Non-Executable Stack)")
    print(f"  {'✅' if result.has_canary else '❌'} Stack Canary")
    print(f"  {'✅' if result.has_pie else '❌'} PIE")
    print(f"  {'✅' if result.has_relro else '❌'} RELRO")
    print(f"  {'✅' if result.has_relro else '❌'} FORTIFY_SOURCE")
    print(f"  {'✅' if result.has_aslr else '❌'} ASLR")
    print("")

    print(f"⚔️  综合危险等级: {result.danger_level}/10")

    if result.vulnerabilities:
        print("\n🚨 漏洞发现:")
        for vuln in result.vulnerabilities:
            print(f"  {vuln}")

    if result.gadgets:
        print(f"\n🔧 发现 {len(result.gadgets)} 个 ROP gadgets")
        print("  最危险的 gadgets:")
        dangerous = sorted(result.gadgets, key=lambda x: x.danger_level, reverse=True)[:5]
        for gadget in dangerous:
            print(f"    {gadget.address}: {gadget.instruction} [危险级: {gadget.danger_level}]")
