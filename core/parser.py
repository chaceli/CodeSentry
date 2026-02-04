"""
代码解析器 - 使用正则表达式 + 简单 AST 解析 C/C++ 代码
兼容 Python 3.14，无需 tree-sitter
"""
import re
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass


@dataclass
class CodeBlock:
    """代码块信息"""
    type: str  # function, if, for, while, etc.
    name: Optional[str]
    start_line: int
    end_line: int
    content: str
    children: List["CodeBlock"]


class CodeParser:
    """C/C++ 代码解析器"""

    # 关键函数/危险操作模式
    DANGEROUS_PATTERNS = {
        "strcpy": r"\bstrcpy\s*\(",
        "strncpy": r"\bstrncpy\s*\(",
        "strcat": r"\bstrcat\s*\(",
        "sprintf": r"\bsprintf\s*\(",
        "snprintf": r"\bsnprintf\s*\(",
        "vsprintf": r"\bvsprintf\s*\(",
        "gets": r"\bgets\s*\(",  # C11 已移除
        "scanf": r"\bscanf\s*\(",
        "printf": r"\bprintf\s*\(",  # 需要检查参数
        "fprintf": r"\bfprintf\s*\(",
        "malloc": r"\bmalloc\s*\(",
        "calloc": r"\bcalloc\s*\(",
        "realloc": r"\brealloc\s*\(",
        "free": r"\bfree\s*\(",
        "system": r"\bsystem\s*\(",
        "popen": r"\bpopen\s*\(",
        "exec": r"\bexec\w*\s*\(",  # execve, execl, etc.
        "memcpy": r"\bmemcpy\s*\(",
        "memmove": r"\bmemmove\s*\(",
        "strlen": r"\bstrlen\s*\(",
        "strncpy": r"\bstrncpy\s*\(",
        "snprintf": r"\bsnprintf\s*\(",
        "fread": r"\bfread\s*\(",
        "fwrite": r"\bfwrite\s*\(",
        "open": r"\bopen\s*\(",  # POSIX
        "read": r"\bread\s*\(",
        "write": r"\bwrite\s*\(",
        "send": r"\bsend\s*\(",
        "recv": r"\brecv\s*\(",
        "sprintf": r"\bsprintf\s*\(",
        "snprintf": r"\bsnprintf\s*\(",
        "tmpfile": r"\btmpfile\s*\(",
        "tmpnam": r"\btmpnam\s*\(",
        "tempnam": r"\btempnam\s*\(",
        "mktemp": r"\bmktemp\s*\(",  # 不安全
        "getenv": r"\bgetenv\s*\(",
        "putenv": r"\bputenv\s*\(",
        "setenv": r"\bsetenv\s*\(",
        "chmod": r"\bchmod\s*\(",
        "chown": r"\bchown\s*\(",
        "umask": r"\bumask\s*\(",
        "dlopen": r"\bdlopen\s*\(",
        "dlsym": r"\bdlsym\s*\(",
    }

    def __init__(self):
        self.dangerous_patterns = self.DANGEROUS_PATTERNS

    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """解析单个文件"""
        path = Path(file_path)
        if not path.exists():
            return None

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            return self.parse_content(content, file_path)
        except Exception as e:
            print(f"[ERROR] 解析文件失败 {file_path}: {e}")
            return None

    def parse_content(self, content: str, file_path: str = "unknown") -> Dict[str, Any]:
        """解析代码内容"""
        lines = content.split("\n")

        # 提取信息
        info = {
            "file": file_path,
            "total_lines": len(lines),
            "functions": self._extract_functions(content),
            "includes": self._extract_includes(content),
            "dangerous_calls": self._find_dangerous_calls(content),
            "raw_content": content,
            "lines": lines,
        }

        return info

    def _extract_functions(self, content: str) -> List[Dict]:
        """提取函数定义"""
        functions = []

        # 函数定义模式
        patterns = [
            # C 风格函数定义
            r"(?:void|int|char|short|long|float|double|bool|unsigned|struct\s+\w+|typedef\s+\w+)\s+\*?\s*(\w+)\s*\(([^)]*)\)\s*\{",
            # C++ 风格（可能包含 template、const 等）
            r"(?:template\s*<[^>]*>\s*)?(?:const\s+)?(?:void|int|char|short|long|float|double|bool|unsigned|auto|auto|decltype|sizeof)\s+(?:\w+::)?\*?\s*(\w+)\s*\([^)]*\)\s*(?:const)?\s*\{",
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, content, re.MULTILINE):
                func_name = match.group(1)
                params = match.group(2) if match.group_count() > 1 else ""

                # 计算行号
                start_line = content[:match.start()].count("\n") + 1

                # 找到对应的闭合括号
                brace_count = 1
                pos = match.end()
                end_pos = pos
                while brace_count > 0 and pos < len(content):
                    if content[pos] == "{":
                        brace_count += 1
                    elif content[pos] == "}":
                        brace_count -= 1
                    if brace_count > 0:
                        end_pos = pos + 1
                    pos += 1

                functions.append({
                    "name": func_name,
                    "params": params.strip(),
                    "start_line": start_line,
                    "end_line": content[:end_pos].count("\n") + 1 if end_pos <= len(content) else start_line,
                })

        return functions

    def _extract_includes(self, content: str) -> List[str]:
        """提取头文件引用"""
        includes = []
        pattern = r"#\s*include\s*[<\"]([^>\"]+)[>\"]"
        for match in re.finditer(pattern, content):
            includes.append(match.group(1))
        return includes

    def _find_dangerous_calls(self, content: str) -> List[Dict]:
        """查找危险函数调用"""
        calls = []

        for pattern_name, pattern in self.dangerous_patterns.items():
            for match in re.finditer(pattern, content):
                line_no = content[:match.start()].count("\n") + 1

                # 获取上下文（前后几行）
                lines = content.split("\n")
                context_start = max(0, line_no - 2)
                context_end = min(len(lines), line_no + 2)

                code_snippet = []
                for i in range(context_start, context_end):
                    prefix = ">>>" if i == line_no - 1 else "   "
                    code_snippet.append(f"{prefix} {i+1:4d} | {lines[i]}")

                calls.append({
                    "function": pattern_name,
                    "line": line_no,
                    "code": lines[line_no - 1].strip() if 0 < line_no <= len(lines) else "",
                    "context": "\n".join(code_snippet),
                })

        return calls

    def get_code_snippet(self, content: str, line: int, context: int = 3) -> str:
        """获取代码片段（带上下文）"""
        lines = content.split("\n")

        start = max(0, line - context - 1)
        end = min(len(lines), line + context)

        snippet = []
        for i in range(start, end):
            prefix = ">>> " if i == line - 1 else "    "
            snippet.append(f"{prefix}{i+1:4d} | {lines[i]}")

        return "\n".join(snippet)


# 单例解析器
parser = CodeParser()
