"""
漏洞验证器 - 使用 AI 减少误报
"""
from typing import Optional, List
import time

from core.analyzer import Vulnerability, ScanResult


class VulnerabilityValidator:
    """漏洞验证器 - AI 驱动的二次验证"""

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.ai_engine = None

    def _get_ai_engine(self):
        """懒加载 AI 引擎"""
        if self.ai_engine is None:
            try:
                from ai.engine import ai_engine
                self.ai_engine = ai_engine
            except ImportError:
                pass
        return self.ai_engine

    def validate_result(self, result: ScanResult, use_ai: bool = True) -> ScanResult:
        """验证扫描结果中的所有漏洞"""
        engine = self._get_ai_engine()

        if not use_ai or not engine or not engine.is_available():
            print("⚠️  AI 验证未跳过（或引擎不可用）")
            return result

        print(f"🤖 开始 AI 验证 {len(result.vulnerabilities)} 个漏洞...")

        validated_vulns = []
        for vuln in result.vulnerabilities:
            try:
                validated = self._validate_single(vuln, engine)
                validated_vulns.append(validated)
                time.sleep(0.5)  # 避免 API 限流
            except Exception as e:
                print(f"[ERROR] 验证漏洞失败: {e}")
                validated_vulns.append(vuln)

        result.vulnerabilities = validated_vulns
        return result

    def _validate_single(self, vuln: Vulnerability, engine) -> Vulnerability:
        """验证单个漏洞"""
        verification = engine.verify_vulnerability(
            code_snippet=vuln.code_snippet,
            vulnerability_type=vuln.type.name,
            context=f"文件: {vuln.location.file}, 行: {vuln.location.line}",
        )

        vuln.ai_analysis = verification.get("analysis", "")
        vuln.ai_verification_result = verification.get("verdict", "uncertain")

        if verification.get("verdict") == "confirmed":
            vuln.confidence = min(1.0, vuln.confidence + 0.3)
            vuln.ai_verified = True
            print(f"✅ 验证确认: {vuln.title} at {vuln.location}")
        elif verification.get("verdict") == "false_positive":
            vuln.confidence = max(0.0, vuln.confidence - 0.5)
            vuln.ai_verified = False
            print(f"❌ 误报排除: {vuln.title} at {vuln.location}")
        else:
            vuln.ai_verified = False
            print(f"⚠️  验证不确定: {vuln.title} at {vuln.location}")

        if verification.get("suggested_fix"):
            vuln.fix_suggestion = verification["suggested_fix"]

        return vuln


# 单例验证器
validator = VulnerabilityValidator()
