"""
配置管理模块
"""
import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field


class ModelConfig(BaseModel):
    """模型配置"""
    name: str = "gpt-4o"
    fallback: str = "gpt-3.5-turbo"
    max_tokens: int = 4096
    temperature: float = 0.1
    timeout: int = 60


class AIConfig(BaseModel):
    """AI 引擎配置"""
    enabled: bool = True
    model: ModelConfig = Field(default_factory=ModelConfig)
    validation_enabled: bool = True  # 是否启用 AI 验证漏洞


class RulesConfig(BaseModel):
    """规则配置"""
    enable_cwe: bool = True
    enable_custom: bool = False
    cwe_top10_only: bool = True  # 只启用 CWE Top 10


class ScannerConfig(BaseModel):
    """扫描器配置"""
    languages: list[str] = ["c", "cpp"]
    recursive: bool = True
    extensions: list[str] = [".c", ".cpp", ".h", ".hpp"]
    exclude_patterns: list[str] = [
        "*/test/*",
        "*/tests/*",
        "*/third_party/*",
        "*/vendor/*",
        "*/node_modules/*",
    ]


class Settings(BaseModel):
    """全局配置"""
    ai: AIConfig = Field(default_factory=AIConfig)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "Settings":
        """从环境变量或配置文件加载配置"""
        # 加载 .env 文件
        env_path = Path(config_path).parent / ".env" if config_path else Path(".env")
        if env_path.exists():
            load_dotenv(env_path)

        return cls(
            ai=AIConfig(
                enabled=os.getenv("AI_ENABLED", "true").lower() == "true",
                model=ModelConfig(
                    name=os.getenv("DEFAULT_MODEL", "gpt-4o"),
                    fallback=os.getenv("FALLBACK_MODEL", "gpt-3.5-turbo"),
                    max_tokens=int(os.getenv("MAX_TOKENS", 4096)),
                    temperature=float(os.getenv("TEMPERATURE", 0.1)),
                    timeout=int(os.getenv("TIMEOUT", 60)),
                ),
            ),
            rules=RulesConfig(
                enable_cwe=os.getenv("ENABLE_CWE_RULES", "true").lower() == "true",
                enable_custom=os.getenv("ENABLE_CUSTOM_RULES", "false").lower() == "true",
            ),
            scanner=ScannerConfig(
                recursive=os.getenv("RECURSIVE_SCAN", "true").lower() == "true",
            ),
        )


# 全局配置实例
settings = Settings.load()
