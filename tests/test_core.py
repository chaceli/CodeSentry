# 单元测试
import unittest
from pathlib import Path

from core.parser import CodeParser
from core.analyzer import StaticAnalyzer
from core.models import Vulnerability, Severity, VulnerabilityType, ScanResult


class TestParser(unittest.TestCase):
    """解析器测试"""

    @classmethod
    def setUpClass(cls):
        cls.parser = CodeParser()

    def test_parse_simple_code(self):
        """测试解析简单代码"""
        code = """
int main() {
    printf("Hello");
    return 0;
}
"""
        tree = self.parser.parse_content(code)
        self.assertIsNotNone(tree)
        self.assertIsNotNone(tree.root_node)

    def test_get_functions(self):
        """测试提取函数"""
        code = """
void foo() {
    printf("foo");
}

int bar(int x) {
    return x + 1;
}
"""
        tree = self.parser.parse_content(code)
        functions = self.parser.get_functions(tree)
        self.assertGreater(len(functions), 0)


class TestAnalyzer(unittest.TestCase):
    """分析器测试"""

    @classmethod
    def setUpClass(cls):
        cls.analyzer = StaticAnalyzer()

    def test_analyze_safe_code(self):
        """测试安全代码应该不报漏洞"""
        code = """
int safe_add(int a, int b) {
    return a + b;
}
"""
        vulnerabilities = self.analyzer.analyze_file("test.c", code)
        self.assertEqual(len(vulnerabilities), 0)

    def test_detect_strcpy(self):
        """测试检测 strcpy"""
        code = """
void test() {
    char dest[100];
    char src[] = "hello";
    strcpy(dest, src);
}
"""
        vulnerabilities = self.analyzer.analyze_file("test.c", code)

        # 应该检测到 buffer overflow
        self.assertGreater(len(vulnerabilities), 0)

        # 检查是否有 strcpy 相关的漏洞
        has_strcpy = any(
            "strcpy" in v.code_snippet.lower()
            for v in vulnerabilities
        )
        self.assertTrue(has_strcpy)

    def test_detect_format_string(self):
        """测试检测 format string 漏洞"""
        code = """
void test(char *input) {
    printf(input);  // 危险的 format string
}
"""
        vulnerabilities = self.analyzer.analyze_file("test.c", code)
        self.assertGreater(len(vulnerabilities), 0)

    def test_directory_scan(self):
        """测试目录扫描"""
        # 使用测试样例目录
        test_dir = Path(__file__).parent / "samples"
        if test_dir.exists():
            result = self.analyzer.analyze_directory(str(test_dir))
            self.assertIsInstance(result, ScanResult)
            self.assertGreater(result.total_files, 0)


class TestModels(unittest.TestCase):
    """数据模型测试"""

    def test_vulnerability_creation(self):
        """测试漏洞对象创建"""
        vuln = Vulnerability(
            id="test-001",
            type=VulnerabilityType.BUFFER_OVERFLOW,
            severity=Severity.HIGH,
            title="Test Vulnerability",
            description="A test vulnerability",
            location=Location(file="test.c", line=10),
            code_snippet="strcpy(a, b);",
            cwe_id="CWE-120",
        )
        self.assertEqual(vuln.type, VulnerabilityType.BUFFER_OVERFLOW)
        self.assertEqual(vuln.severity, Severity.HIGH)

    def test_scan_result_summary(self):
        """测试扫描结果汇总"""
        result = ScanResult(
            target="test",
            total_files=5,
            total_lines=1000,
        )
        # 添加一些漏洞
        result.vulnerabilities = [
            Vulnerability(
                id=f"v{i}",
                type=VulnerabilityType.BUFFER_OVERFLOW,
                severity=Severity.CRITICAL if i < 2 else Severity.HIGH,
                title=f"Vuln {i}",
                description="desc",
                location=Location(file="test.c", line=i),
                code_snippet="code",
                cwe_id="CWE-120",
            )
            for i in range(5)
        ]

        self.assertEqual(result.critical_count, 2)
        self.assertEqual(result.high_count, 3)


if __name__ == "__main__":
    unittest.main()
