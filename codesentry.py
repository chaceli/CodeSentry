"""
命令行入口 - 极简版本
"""
import sys
import time
from pathlib import Path

from core.analyzer import analyze_directory, analyze_file, ScanResult


def main():
    if len(sys.argv) < 2:
        print("用法: python codesentry.py <文件或目录>")
        print("示例: python codesentry.py /path/to/project")
        sys.exit(1)

    target = sys.argv[1]
    path = Path(target)

    if not path.exists():
        print(f"错误: 目标不存在: {target}")
        sys.exit(1)

    print(f"🔍 正在扫描: {target}")

    start_time = time.time()

    if path.is_file():
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        result = ScanResult(
            target=str(path),
            total_files=1,
            total_lines=content.count("\n"),
            vulnerabilities=analyze_file(str(path), content),
        )
    else:
        result = analyze_directory(str(path))

    result.scan_time_seconds = time.time() - start_time

    # 打印结果
    from core.analyzer import print_result
    print_result(result)

    # 返回适当的退出码
    if result.critical_count > 0 or result.high_count > 0:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
