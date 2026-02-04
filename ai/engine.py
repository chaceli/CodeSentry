"""
AI 引擎 - 大模型集成
"""
import os
from typing import Optional
from abc import ABC, abstractmethod

from openai import OpenAI, AnthropicBedrock
from anthropic import Anthropic

from config.settings import settings, ModelConfig
from utils.logger import log


class BaseLLMEngine(ABC):
    """大模型引擎基类"""

    @abstractmethod
    def analyze(self, prompt: str) -> str:
        pass

    @abstractmethod
    def verify_vulnerability(
        self,
        code_snippet: str,
        vulnerability_type: str,
        context: str
    ) -> dict:
        pass


class OpenAIEngine(BaseLLMEngine):
    """OpenAI GPT 系列引擎"""

    def __init__(self, config: ModelConfig = None):
        self.config = config or settings.ai.model
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not set")

        self.client = OpenAI(api_key=api_key)

    def analyze(self, prompt: str) -> str:
        """发送分析请求"""
        try:
            response = self.client.chat.completions.create(
                model=self.config.name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security expert specializing in C/C++ code auditing. "
                                   "Analyze code for vulnerabilities and provide detailed analysis. "
                                   "Be precise and focus on real security issues."
                    },
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
            )

            return response.choices[0].message.content
        except Exception as e:
            log.error(f"OpenAI API error: {e}")
            return ""

    def verify_vulnerability(
        self,
        code_snippet: str,
        vulnerability_type: str,
        context: str = ""
    ) -> dict:
        """验证漏洞是否为真阳性"""

        prompt = f"""
You are a security expert reviewing C/C++ code for potential vulnerabilities.

## Vulnerability to Review
- Type: {vulnerability_type}
- Context: {context}

## Code Under Review
```
{code_snippet}
```

## Task
Analyze whether this code truly contains a security vulnerability of type {vulnerability_type}.

Consider:
1. Is this a real vulnerability or a false positive?
2. What are the exact conditions for exploitation?
3. Is there proper input validation or sanitization?
4. What is the actual risk level?

## Response Format
Provide your analysis in this exact format:

VERDICT: [confirmed|false_positive|uncertain]

ANALYSIS: [Your detailed reasoning - at least 2-3 sentences]

RISK_LEVEL: [critical|high|medium|low|none]

SUGGESTED_FIX: [Optional - brief fix suggestion or "none"]
"""

        result = self.analyze(prompt)

        # 解析结果
        verdict = "uncertain"
        analysis = ""
        risk = "medium"
        fix = "none"

        for line in result.split("\n"):
            line = line.strip()
            if line.startswith("VERDICT:"):
                verdict = line.split(":")[1].strip().lower()
            elif line.startswith("ANALYSIS:"):
                analysis = line.split(":", 1)[1].strip()
            elif line.startswith("RISK_LEVEL:"):
                risk = line.split(":")[1].strip().lower()
            elif line.startswith("SUGGESTED_FIX:"):
                fix = line.split(":", 1)[1].strip()

        return {
            "verdict": verdict,
            "analysis": analysis,
            "risk_level": risk,
            "suggested_fix": fix,
            "raw_response": result,
        }


class ClaudeEngine(BaseLLMEngine):
    """Anthropic Claude 引擎"""

    def __init__(self, config: ModelConfig = None):
        self.config = config or settings.ai.model
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")

        self.client = Anthropic(api_key=api_key)

    def analyze(self, prompt: str) -> str:
        """发送分析请求"""
        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                system="You are a security expert specializing in C/C++ code auditing. "
                       "Analyze code for vulnerabilities and provide detailed analysis. "
                       "Be precise and focus on real security issues.",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            return response.content[0].text
        except Exception as e:
            log.error(f"Claude API error: {e}")
            return ""

    def verify_vulnerability(
        self,
        code_snippet: str,
        vulnerability_type: str,
        context: str = ""
    ) -> dict:
        """验证漏洞"""
        # Claude 专用提示词
        prompt = f"""
Review this C/C++ code for a {vulnerability_type} vulnerability:

```
{code_snippet}
```

Context: {context}

Determine:
1. Is this a real vulnerability? (confirmed/false_positive/uncertain)
2. Detailed reasoning
3. Risk level (critical/high/medium/low/none)
4. Fix suggestion (or "none")

Respond in this format:
VERDICT: ...
ANALYSIS: ...
RISK_LEVEL: ...
SUGGESTED_FIX: ...
"""

        result = self.analyze(prompt)

        # 解析结果（与 OpenAI 相同的解析逻辑）
        verdict = "uncertain"
        analysis = ""
        risk = "medium"
        fix = "none"

        for line in result.split("\n"):
            line = line.strip()
            if line.startswith("VERDICT:"):
                verdict = line.split(":")[1].strip().lower()
            elif line.startswith("ANALYSIS:"):
                analysis = line.split(":", 1)[1].strip()
            elif line.startswith("RISK_LEVEL:"):
                risk = line.split(":")[1].strip().lower()
            elif line.startswith("SUGGESTED_FIX:"):
                fix = line.split(":", 1)[1].strip()

        return {
            "verdict": verdict,
            "analysis": analysis,
            "risk_level": risk,
            "suggested_fix": fix,
            "raw_response": result,
        }


class AIEngine:
    """AI 引擎管理器"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.engine = self._create_engine()
        self._initialized = True

    def _create_engine(self) -> Optional[BaseLLMEngine]:
        """创建合适的引擎"""
        if os.getenv("OPENAI_API_KEY"):
            log.info("使用 OpenAI 引擎")
            return OpenAIEngine()
        elif os.getenv("ANTHROPIC_API_KEY"):
            log.info("使用 Claude 引擎")
            return ClaudeEngine()
        else:
            log.warning("未配置任何 API Key，AI 功能将不可用")
            return None

    def is_available(self) -> bool:
        """检查引擎是否可用"""
        return self.engine is not None

    def verify_vulnerability(
        self,
        code_snippet: str,
        vulnerability_type: str,
        context: str = ""
    ) -> dict:
        """验证漏洞（入口）"""
        if not self.is_available():
            return {
                "verdict": "unavailable",
                "analysis": "AI engine not configured",
                "risk_level": "unknown",
                "suggested_fix": "none",
            }

        return self.engine.verify_vulnerability(
            code_snippet, vulnerability_type, context
        )

    def analyze_code(self, code: str, focus: str = "") -> str:
        """深度分析代码"""
        if not self.is_available():
            return "AI engine not configured"

        prompt = f"""
Analyze this C/C++ code for security vulnerabilities:

{focus}

```c
{code}
```

Provide a detailed security analysis focusing on:
1. Potential vulnerabilities
2. Exploitation scenarios
3. Risk assessment
4. Recommended mitigations
"""

        return self.engine.analyze(prompt)


# 全局 AI 引擎实例
ai_engine = AIEngine()
