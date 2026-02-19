"""共用工具函式"""

from . import __version__

VERSION = __version__
DEFAULT_BACKUP_DIR_NAME = "_duplicates_backup"
CORE_SKIP_DIR_NAMES = frozenset({".git", "__pycache__"})
SCAN_SKIP_DIR_NAMES = CORE_SKIP_DIR_NAMES | frozenset({DEFAULT_BACKUP_DIR_NAME})


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
