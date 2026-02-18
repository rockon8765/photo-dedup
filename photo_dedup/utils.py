"""共用工具函式"""

from . import __version__

VERSION = __version__


def format_size(size_bytes: int) -> str:
    """將 bytes 轉成可讀格式 (B / KB / MB / GB)"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
