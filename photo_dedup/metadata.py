"""
檔案日期 metadata 讀取與日期檔名產生

提供兩個核心功能：
  1. 從檔案讀取建立日期（EXIF → filesystem fallback）
  2. 產生日期格式的檔名（YYYYMMDD / YYYYMMDD_N）

日期讀取優先順序：
  - EXIF DateTimeOriginal (tag 36867)
  - EXIF DateTimeDigitized (tag 36868)
  - 檔案系統 st_mtime（修改時間，跨平台一致）

安全措施：
  - 任何 EXIF 讀取錯誤均靜默 fallback 到 st_mtime
  - 不修改任何檔案，僅讀取
"""

import logging
import os
from datetime import datetime, timezone

from .hasher import IMAGE_EXTENSIONS

logger = logging.getLogger(__name__)

# EXIF tag IDs
_EXIF_DATETIME_ORIGINAL = 36867
_EXIF_DATETIME_DIGITIZED = 36868

# 常見的 EXIF 日期時間格式
_EXIF_DATETIME_FORMATS = [
    "%Y:%m:%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
]

MAX_DATE_FILENAME_SUFFIX = 10_000


def _parse_exif_datetime(value: str) -> datetime | None:
    """
    嘗試解析 EXIF 日期字串。

    Returns:
        datetime (UTC-aware) 或 None（格式無法辨識時）
    """
    if not isinstance(value, str) or not value.strip():
        return None

    clean = value.strip().rstrip('\x00')
    for fmt in _EXIF_DATETIME_FORMATS:
        try:
            dt = datetime.strptime(clean, fmt)
            # EXIF 日期通常是本地時間，但我們只需要日期部分做檔名
            # 不做 timezone 轉換，直接視為 UTC 存放
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return None


def _get_exif_date(filepath: str) -> datetime | None:
    """
    嘗試從圖片 EXIF 讀取拍攝日期。

    Returns:
        datetime 或 None（非圖片檔/無 EXIF/讀取失敗時）
    """
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in IMAGE_EXTENSIONS:
        return None

    try:
        from PIL import Image

        with Image.open(filepath) as img:
            exif_data = img.getexif()
            if not exif_data:
                return None

            # 優先 DateTimeOriginal，其次 DateTimeDigitized
            for tag_id in (_EXIF_DATETIME_ORIGINAL, _EXIF_DATETIME_DIGITIZED):
                raw = exif_data.get(tag_id)
                if raw:
                    dt = _parse_exif_datetime(str(raw))
                    if dt:
                        return dt

    except Exception as e:
        logger.debug("EXIF read failed for %s: %s", os.path.basename(filepath), e)

    return None


def get_file_date(filepath: str) -> datetime | None:
    """
    取得檔案的建立日期。

    優先順序：EXIF DateTimeOriginal → DateTimeDigitized → st_mtime

    Args:
        filepath: 檔案的絕對路徑

    Returns:
        datetime (UTC-aware) 或 None（檔案不存在時）
    """
    if not os.path.isfile(filepath):
        return None

    # 嘗試 EXIF
    exif_dt = _get_exif_date(filepath)
    if exif_dt:
        return exif_dt

    # Fallback: st_mtime
    try:
        mtime = os.path.getmtime(filepath)
        return datetime.fromtimestamp(mtime, tz=timezone.utc)
    except OSError:
        return None


def get_earliest_date(filepaths: list[str]) -> datetime | None:
    """
    從多個檔案中取得最早的建立日期。

    Args:
        filepaths: 檔案絕對路徑列表

    Returns:
        最早的 datetime 或 None（所有檔案都無法讀取時）
    """
    dates = []
    for fp in filepaths:
        dt = get_file_date(fp)
        if dt:
            dates.append(dt)

    return min(dates) if dates else None


def generate_date_filename(
    dt: datetime,
    ext: str,
    existing_names: set[str],
) -> str:
    """
    從日期產生檔名，衝突時自動加後綴。

    格式：YYYYMMDD.ext → YYYYMMDD_1.ext → YYYYMMDD_2.ext → ...

    Args:
        dt: 用於命名的日期
        ext: 副檔名（含點號，例如 ".jpg"）
        existing_names: 同目錄下已存在的檔名集合（用於衝突偵測）

    Returns:
        不衝突的新檔名（basename only）
    """
    date_stem = dt.strftime("%Y%m%d")
    candidate = f"{date_stem}{ext}"

    if candidate not in existing_names:
        return candidate

    counter = 1
    while counter <= MAX_DATE_FILENAME_SUFFIX:
        candidate = f"{date_stem}_{counter}{ext}"
        if candidate not in existing_names:
            return candidate
        counter += 1

    raise ValueError(
        "Too many filename conflicts while generating date filename: "
        f"{date_stem}{ext}"
    )
