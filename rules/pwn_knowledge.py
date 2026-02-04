"""
CTF Pwn 知识库 - 漏洞模式和利用技术百科
"""
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional


class VulnerabilityCategory(Enum):
    """漏洞类别"""
    STACK_OVERFLOW = "stack_overflow"
    HEAP_EXPLOITATION = "heap_exploitation"
    FORMAT_STRING = "format_string"
    INTEGER_EXPLOITATION = "integer_exploitation"
    RACE_CONDITION = "race_condition"
    BINARY_EXPLOITATION = "binary_exploitation"
    WEB_EXPLOITATION = "web_exploitation"
    CRYPTO_EXPLOITATION = "crypto_exploitation"


@dataclass
class Technique:
    """利用技术"""
    name: str
    category: VulnerabilityCategory
    description: str
    prerequisites: List[str]  # 前置条件
    steps: List[str]  # 利用步骤
    mitigations: List[str]  # 缓解措施
    difficulty: int  # 1-10
    examples: List[str]  # 示例链接或说明


# CTF Pwn 核心技术百科
PWN_TECHNIQUES = [
    # ========== 栈溢出系列 ==========
    {
        "name": "Basic Stack Overflow",
        "category": VulnerabilityCategory.STACK_OVERFLOW,
        "description": "最基础的栈溢出，通过溢出覆盖返回地址控制执行流",
        "prerequisites": ["无 NX/Canary", "可控的输入缓冲区"],
        "steps": [
            "1. 发送超长字符串溢出缓冲区",
            "2. 覆盖返回地址 (return address)",
            "3. 跳转到 shellcode 或 ROP 链",
        ],
        "mitigations": ["NX (Non-Executable Stack)", "Stack Canary", "PIE"],
        "difficulty": 2,
        "examples": ["经典 ret2libc", "直接跳转 shellcode"],
    },
    {
        "name": "ROP (Return-Oriented Programming)",
        "category": VulnerabilityCategory.BINARY_EXPLOITATION,
        "description": "返回导向编程，通过串联现有代码片段 (gadgets) 执行任意操作",
        "prerequisites": ["NX 启用", "可预测的栈地址", "存在可用的 gadgets"],
        "steps": [
            "1. 泄露 libc 地址 (如通过 puts)",
            "2. 计算 libc 基址",
            "3. 构造 ROP 链: pop rdi; ret → /bin/sh → system",
        ],
        "mitigations": ["Stack Canary", "PIE", "CFI (Control Flow Integrity)"],
        "difficulty": 5,
        "examples": ["ret2libc", "ROP chain to execve"],
    },
    {
        "name": "SROP (Sigreturn ROP)",
        "category": VulnerabilityCategory.BINARY_EXPLOITATION,
        "description": "利用 sigreturn 系统调用伪造信号处理帧来执行任意代码",
        "prerequisites": ["可控制栈内容", "存在 syscall/sigreturn gadget"],
        "steps": [
            "1. 控制栈布局",
            "2. 构造伪造的 ucontext 结构体",
            "3. 调用 sigreturn",
            "4. 执行任意系统调用 (如 execve)",
        ],
        "mitigations": ["Signal Guard", "NX", "减少 sigaction 使用"],
        "difficulty": 8,
        "examples": ["SROP + ROP 组合"],
    },
    {
        "name": "ret2dlresolve",
        "category": VulnerabilityCategory.BINARY_EXPLOITATION,
        "description": "利用动态链接器解析漏洞，绕过 ASLR 泄露和利用",
        "prerequisites": ["部分 RELRO", "可控的解析参数"],
        "steps": [
            "1. 伪造 fake link_map",
            "2. 控制 _dl_runtime_resolve 参数",
            "3. 解析任意符号到目标地址",
        ],
        "mitigations": ["Full RELRO", "DFL (Direct Function Launch)"],
        "difficulty": 9,
        "examples": ["Fake link_map technique"],
    },

    # ========== 堆利用系列 ==========
    {
        "name": "Use After Free (UAF)",
        "category": VulnerabilityCategory.HEAP_EXPLOITATION,
        "description": "释放后使用，通过重新分配获取对象控制权",
        "prerequisites": ["可触发 free", "可触发 malloc", "对象包含函数指针或虚表"],
        "steps": [
            "1. 触发第一个对象的分配",
            "2. 释放该对象",
            "3. 分配恶意内容到同一位置",
            "4. 触发 use，劫持控制流",
        ],
        "mitigations": ["Heap Canary", "Safe Unlinking", "CFI"],
        "difficulty": 4,
        "examples": ["House of Spirit + UAF", "Tcache UAF"],
    },
    {
        "name": "Double Free",
        "category": VulnerabilityCategory.HEAP_EXPLOITATION,
        "description": "双重释放，可用于修改 tcache/bin 链表指针",
        "prerequisites": ["可触发两次 free"],
        "steps": [
            "1. 第一次 free (进入 tcache)",
            "2. 第二次 free (指向同一个地址)",
            "3. 修改 fd 指针",
            "4. 分配到任意地址",
        ],
        "mitigations": ["Tcache Sanity Checks", "Double Free Detection"],
        "difficulty": 4,
        "examples": ["Tcache Double Free"],
    },
    {
        "name": "House of Spirit",
        "category": VulnerabilityCategory.HEAP_EXPLOITATION,
        "description": "在栈上构造伪 chunk，欺骗分配器",
        "prerequisites": ["可控的栈内容", "可触发 malloc"],
        "steps": [
            "1. 在栈上构造 fake chunk (prev_size, size, fd, bk)",
            "2. 确保绕过 unlink 检查",
            "3. 触发 malloc 分配到 fake chunk",
        ],
        "mitigations": ["Safe Unlinking", "Stack Canary"],
        "difficulty": 7,
        "examples": ["Stack fake chunk"],
    },
    {
        "name": "House of Force",
        "category": VulnerabilityCategory.HEAP_EXPLOITATION,
        "description": "利用 top chunk 溢出，分配到任意地址",
        "prerequisites": ["可控制 malloc 大小为负数或大整数", "无 top chunk guard"],
        "steps": [
            "1. 溢出 top chunk 的 size 字段",
            "2. malloc 一个负大小，top chunk 移到目标地址",
            "3. 再次 malloc 分配到任意地址",
        ],
        "mitigations": ["Top Chunk Guard", "Chunk Size Validation"],
        "difficulty": 8,
        "examples": ["House of Force -> malloc to target"],
    },
    {
        "name": "House of Lore",
        "category": VulnerabilityCategory.HEAP_EXPLOITATION,
        "description": "伪造 small bin，进行任意地址读写",
        "prerequisites": ["存在 small bin 分配", "可控的堆内容"],
        "steps": [
            "1. 分配两个 chunk A, B",
            "2. 释放 A，进入 unsorted bin",
            "3. 修改 A 的 bk 指针到目标地址-0x10",
            "4. malloc 分配到目标地址附近",
        ],
        "mitigations": ["Safe Unlinking", "Bin Sanity Checks"],
        "difficulty": 8,
        "examples": ["Small bin attack"],
    },
    {
        "name": "Unsorted Bin Attack",
        "category": VulnerabilityCategory.HEAP_EXPLOITATION,
        "description": "利用 unsorted bin 的bk指针写入任意地址",
        "prerequisites": ["可控的 unsorted chunk bk 指针"],
        "steps": [
            "1. 释放一个 chunk 到 unsorted bin",
            "2. 修改该 chunk 的 bk 指针到目标地址-0x10",
            "3. 触发 malloc (需要精确大小)",
            "4. bk 指针被写入目标地址",
        ],
        "mitigations": ["Unsorted Bin Sanity Checks"],
        "difficulty": 6,
        "examples": ["修改 global_max_fast", "劫持 _IO_list_all"],
    },
    {
        "name": "House of Einherjar",
        "category": VulnerabilityCategory.HEAP_EXPLOITATION,
        "description": "利用单字节溢出向前合并 chunk",
        "prerequisites": ["可控的 prev_size", "可触发单字节溢出"],
        "steps": [
            "1. 分配 chunk A, B",
            "2. 溢出 A 的 prev_size 字段",
            "3. 触发向前合并",
            "4. 分配到任意地址",
        ],
        "mitigations": ["Consolidate Validation", "Boundary Checks"],
        "difficulty": 8,
        "examples": ["Single byte overflow consolidation"],
    },

    # ========== 格式化字符串 ==========
    {
        "name": "Format String Leak",
        "category": VulnerabilityCategory.FORMAT_STRING,
        "description": "通过格式化字符串泄露任意内存",
        "prerequisites": ["存在格式化字符串漏洞"],
        "steps": [
            "1. 使用 %p 泄露栈和 libc 地址",
            "2. 计算 libc 基址",
            "3. 定位 system 和 /bin/sh",
        ],
        "mitigations": ["FORTIFY_SOURCE", "PIE"],
        "difficulty": 3,
        "examples": ["%p leak", "任意地址泄露"],
    },
    {
        "name": "Format String Write",
        "category": VulnerabilityCategory.FORMAT_STRING,
        "description": "通过 %n 写入任意地址",
        "prerequisites": ["存在格式化字符串漏洞", "可写内存"],
        "steps": [
            "1. 使用 %n 写入目标地址",
            "2. 构造栈布局控制写入值",
            "3. 修改 GOT 或返回地址",
        ],
        "mitigations": ["FORTIFY_SOURCE", "RELRO", "PIE"],
        "difficulty": 4,
        "examples": ["GOT hijacking with %n"],
    },

    # ========== 整数溢出 ==========
    {
        "name": "Integer Overflow to Buffer Overflow",
        "category": VulnerabilityCategory.INTEGER_EXPLOITATION,
        "description": "整数溢出导致分配过小缓冲区",
        "prerequisites": ["整数运算后用于分配大小"],
        "steps": [
            "1. 输入特殊值导致整数溢出 (如 size = size1 + size2 溢出为小值)",
            "2. malloc 过小缓冲区",
            "3. 写入数据时溢出",
        ],
        "mitigations": ["Integer Overflow Checks", "Size Validation"],
        "difficulty": 5,
        "examples": ["size_t overflow", "int to size_t conversion"],
    },
    {
        "name": "Signed to Unsigned",
        "category": VulnerabilityCategory.INTEGER_EXPLOITATION,
        "description": "有符号转无符号导致负数变成大正数",
        "prerequisites": ["有符号数转 size_t 使用"],
        "steps": [
            "1. 输入负数",
            "2. 转换为无符号后变成大正数",
            "3. 绕过长度检查",
        ],
        "mitigations": ["Signed/Unsigned Checks", "Bounds Validation"],
        "difficulty": 5,
        "examples": ["negative index bypass"],
    },

    # ========== 条件竞争 ==========
    {
        "name": "TOCTOU Race",
        "category": VulnerabilityCategory.RACE_CONDITION,
        "description": "检查-使用时间竞争，替换文件",
        "prerequisites": ["检查文件与使用文件之间存在时间窗口"],
        "steps": [
            "1. 创建符号链接指向 /etc/passwd",
            "2. 触发权限检查",
            "3. 快速切换符号链接指向恶意文件",
        ],
        "mitigations": ["Atomic Operations", "Use file descriptors directly"],
        "difficulty": 6,
        "examples": ["symlink attack", "File replacement"],
    },
    {
        "name": "Fork and Brk/Write Race",
        "category": VulnerabilityCategory.RACE_CONDITION,
        "description": "利用 fork 复制地址空间进行竞争",
        "prerequisites": ["fork 后可继续触发漏洞"],
        "steps": [
            "1. fork 子进程",
            "2. 父进程修改数据",
            "3. 子进程利用修改后的数据",
        ],
        "mitigations": ["Seccomp", "Canary"],
        "difficulty": 7,
        "examples": ["Fork + UAF", "Fork + heap overflow"],
    },
]


@dataclass
class ProtectionMechanism:
    """保护机制"""
    name: str
    description: str
    bypass_techniques: List[str]  # 绕过技术
    effectiveness: int  # 1-10, 10 表示完全防护


PROTECTION_MECHANISMS = [
    {
        "name": "NX (Non-Executable Stack)",
        "description": "栈和堆不可执行，阻止 shellcode 执行",
        "bypass_techniques": ["ROP", "SROP", "JOP", "ret2libc"],
        "effectiveness": 8,
    },
    {
        "name": "Stack Canary",
        "description": "栈上放置 canary 值，检测栈溢出",
        "bypass_techniques": ["泄露 canary", "逐字节爆破", "overwrite with same value"],
        "effectiveness": 7,
    },
    {
        "name": "PIE (Position Independent Executable)",
        "description": "程序加载地址随机化",
        "bypass_techniques": ["泄露地址计算偏移", "partial overwrite", "ret2dlresolve"],
        "effectiveness": 8,
    },
    {
        "name": "ASLR (Address Space Layout Randomization)",
        "description": "整个地址空间随机化",
        "bypass_techniques": ["信息泄露", "partial RELRO bypass", "stack pivot"],
        "effectiveness": 9,
    },
    {
        "name": "RELRO (RELocation Read-Only)",
        "description": "GOT 表只读",
        "bypass_techniques": ["Partial RELRO", "ret2dlresolve", "伪造 vtable"],
        "effectiveness": 9,
    },
    {
        "name": "FORTIFY_SOURCE",
        "description": "编译时检查缓冲区溢出",
        "bypass_techniques": ["格式化字符串 %n", "绕过检查的溢出"],
        "effectiveness": 7,
    },
    {
        "name": "Safe Unlinking",
        "description": "堆释放时检查链表完整性",
        "bypass_techniques": ["House of Spirit", "Tcache attack", "Unsorted bin attack"],
        "effectiveness": 8,
    },
    {
        "name": "Tcache Sanity Checks",
        "description": "Tcache 安全性检查",
        "bypass_techniques": ["Double free (旧版本)", "House of Force"],
        "effectiveness": 6,
    },
]


def get_technique(name: str) -> Optional[Dict]:
    """获取特定技术信息"""
    for tech in PWN_TECHNIQUES:
        if tech["name"] == name:
            return tech
    return None


def get_techniques_by_category(category: VulnerabilityCategory) -> List[Dict]:
    """按类别获取技术列表"""
    return [t for t in PWN_TECHNIQUES if t["category"] == category]


def get_protection_info(name: str) -> Optional[Dict]:
    """获取保护机制信息"""
    for prot in PROTECTION_MECHANISMS:
        if prot["name"] == name:
            return prot
    return None


def get_bypass_techniques(protection_name: str) -> List[str]:
    """获取绕过特定保护的技术"""
    prot = get_protection_info(protection_name)
    if prot:
        return prot["bypass_techniques"]
    return []
