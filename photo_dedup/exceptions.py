"""自訂例外類別，供 CLI 層捕捉後統一輸出錯誤訊息"""


class PhotoDedupError(Exception):
    """所有 photo-dedup 錯誤的基礎類別"""
    pass


class DirectoryNotFoundError(PhotoDedupError):
    """目標資料夾不存在"""
    pass


class AccessDeniedError(PhotoDedupError):
    """權限不足"""
    pass


class InvalidReportError(PhotoDedupError):
    """報告檔無效或格式錯誤"""
    pass


class PathTraversalError(PhotoDedupError):
    """路徑逸出目標資料夾（安全性違規）"""
    pass


class DirectoryMismatchError(PhotoDedupError):
    """掃描報告的 target_dir 與 clean 的 --dir 不一致"""
    pass
