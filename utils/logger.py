"""
日志模块
"""
from loguru import logger
import sys
from pathlib import Path


def setup_logger(log_dir: str = "logs", level: str = "INFO"):
    """配置日志系统"""
    log_path = Path(log_dir)
    log_path.mkdir(exist_ok=True)

    # 移除默认 handler
    logger.remove()

    # 添加控制台输出
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
               "<level>{level: <8}</level> | "
               "<cyan>{message}</cyan>",
        level=level,
        colorize=True,
    )

    # 添加文件输出
    logger.add(
        log_path / "codesentry_{time:YYYY-MM-DD}.log",
        rotation="00:00",  # 每天零点切割
        retention="7 days",  # 保留7天
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}",
        level="DEBUG",
    )

    return logger


# 默认日志配置
log = setup_logger()
