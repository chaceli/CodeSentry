"""
命令行入口
"""
import argparse
import sys
import time
from pathlib import Path

from core.analyzer import analyzer
from ai.validator import validator
from output.reporter import ReportGenerator
from utils.logger import log


def create_parser():
    """创建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        description="🔒 CodeSentry - AI驱动的代码安全审计工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 扫描单个文件
  python -m cli.main scan path/to/file.c

  # 扫描整个目录
  python -m cli.main scan path/to/project/

  # 输出 JSON 格式报告
  python -m cli.main scan path/to/file.c --format json --output report.json

  # 跳过 AI 验证（快速模式）
  python -m cli.main scan path/to/file.c --no-ai

  # 详细输出
  python -m cli.main scan path/to/file.c --verbose
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    # scan 命令
    scan_parser = subparsers.add_parser("scan", help="扫描代码")
    scan_parser.add_argument("target", help="目标文件或目录")
    scan_parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "sarif"],
        default="text",
        help="输出格式 (默认: text)"
    )
    scan_parser.add_argument(
        "--output", "-o",
        help="输出文件路径"
    )
    scan_parser.add_argument(
        "--no-ai",
        action="store_true",
        help="跳过 AI 验证（快速模式）"
    )
    scan_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="详细输出"
    )
    scan_parser.add_argument(
        "--include-tests",
        action="store_true",
        help="包含测试目录"
    )

    # version 命令
    version_parser = subparsers.add_parser("version", help="显示版本")

    return parser


def cmd_scan(args):
    """执行扫描命令"""
    target = Path(args.target)

    if not target.exists():
        log.error(f"目标不存在: {target}")
        sys.exit(1)

    log.info(f"🔍 开始扫描: {target}")

    # 记录开始时间
    start_time = time.time()

    # 执行扫描
    if target.is_file():
        with open(target, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        result = analyzer.analyze_file(str(target), content)
        scan_result = analyzer.analyze_file(str(target), content)

        # 手动创建 ScanResult
        from core.models import ScanResult
        scan_result = ScanResult(
            target=str(target),
            total_files=1,
            total_lines=content.count("\n"),
            vulnerabilities=result,
        )
    else:
        # 目录扫描
        extensions = [".c", ".cpp", ".h", ".hpp"]
        scan_result = analyzer.analyze_directory(str(target), extensions)

    # 记录扫描时间
    scan_result.scan_time_seconds = time.time() - start_time

    # AI 验证（可选）
    if not args.no_ai:
        log.info("🤖 开始 AI 验证...")
        scan_result = validator.validate_result(scan_result, use_ai=True)

    # 输出报告
    reporter = ReportGenerator(scan_result)

    if args.output:
        reporter.save(args.output, format=args.format)
    else:
        print("\n" + reporter.to_text(verbose=args.verbose))

    # 统计信息
    if scan_result.vulnerabilities:
        log.warning(f"发现 {len(scan_result.vulnerabilities)} 个潜在漏洞")
        if scan_result.critical_count > 0:
            log.error(f"🔴 Critical: {scan_result.critical_count}")
        if scan_result.high_count > 0:
            log.warning(f"🟠 High: {scan_result.high_count}")
    else:
        log.success("✅ 未发现漏洞")

    # 返回适当的退出码
    if scan_result.critical_count > 0 or scan_result.high_count > 0:
        sys.exit(2)  # 发现高危漏洞
    sys.exit(0)


def cmd_version(args):
    """显示版本信息"""
    print("CodeSentry v0.1.0")
    print("AI驱动的 C/C++ 代码安全审计工具")
    print()
    print("依赖: tree-sitter, OpenAI/Claude API")


def main():
    """主函数"""
    parser = create_parser()
    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "version":
        cmd_version(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
