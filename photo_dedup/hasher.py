"""
檔案 hash 計算模組

提供兩種 hash 策略：
  - 全檔 MD5：適用非圖片檔
  - 像素 MD5：用 Pillow 解碼後只比對像素資料，忽略 EXIF / ICC profile 差異
"""

import hashlib
import os


# 支援像素比對的圖片副檔名
IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.heic', '.webp', '.dng'}


def get_file_md5(filepath: str, chunk_size: int = 65536) -> str:
    """計算整個檔案的 MD5 hash"""
    h = hashlib.md5()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def get_pixel_hash(filepath: str) -> str:
    """
    用 Pillow 解碼圖片，取出純像素資料的 MD5。
    忽略 EXIF、ICC profile 等 metadata 差異。
    """
    from PIL import Image
    try:
        with Image.open(filepath) as img:
            img_rgb = img.convert('RGB')
            pixel_data = img_rgb.tobytes()
            return hashlib.md5(pixel_data).hexdigest()
    except Exception as e:
        print(f"  [WARN] fallback to file MD5: {os.path.basename(filepath)} ({e})")
        return "FILE:" + get_file_md5(filepath)


def compute_hash(filepath: str, ext: str, use_pixel: bool = True) -> str:
    """
    根據副檔名和設定選擇 hash 策略。

    Args:
        filepath: 檔案路徑
        ext: 副檔名 (小寫, 含點號)
        use_pixel: 是否對圖片使用像素比對
    """
    if use_pixel and ext in IMAGE_EXTENSIONS:
        return get_pixel_hash(filepath)
    else:
        return "FILE:" + get_file_md5(filepath)


def init_heic_support() -> bool:
    """嘗試載入 HEIC 支援，回傳是否成功"""
    try:
        from pillow_heif import register_heif_opener
        register_heif_opener()
        return True
    except ImportError:
        IMAGE_EXTENSIONS.discard('.heic')
        return False
