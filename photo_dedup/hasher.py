"""
檔案 hash 計算模組

提供兩種 hash 策略：
  - 全檔 MD5：適用非圖片檔
  - 像素 MD5：用 Pillow 解碼後只比對像素資料，忽略 EXIF / ICC profile 差異

安全措施：
  - 限制最大圖片像素數，超過上限自動 fallback 到全檔 MD5
  - 使用分塊讀取避免記憶體溢出
"""

import hashlib
import os

# 支援像素比對的圖片副檔名
IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.heic', '.webp', '.dng'}

# 像素上限 (100 megapixels)，超過此值 fallback 到全檔 MD5
# 避免解壓縮炸彈或超大圖造成記憶體溢出
MAX_IMAGE_PIXELS = 100_000_000


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

    安全措施：
      - 設定 MAX_IMAGE_PIXELS 防止解壓縮炸彈
      - 超大圖自動 fallback 到全檔 MD5
    """
    from PIL import Image

    # 設定像素上限
    original_max = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS

    try:
        with Image.open(filepath) as img:
            # 檢查像素數量
            width, height = img.size
            pixel_count = width * height
            if pixel_count > MAX_IMAGE_PIXELS:
                print(
                    f"  [WARN] image too large ({pixel_count:,} pixels), "
                    f"fallback to file MD5: {os.path.basename(filepath)}"
                )
                return "FILE:" + get_file_md5(filepath)

            img_rgb = img.convert('RGB')

            # 分塊計算 hash，避免一次載入全部像素到記憶體
            h = hashlib.md5()
            raw = img_rgb.tobytes()
            chunk_size = 1024 * 1024  # 1MB chunks
            for i in range(0, len(raw), chunk_size):
                h.update(raw[i:i + chunk_size])
            return h.hexdigest()

    except Exception as e:
        print(
            f"  [WARN] fallback to file MD5: "
            f"{os.path.basename(filepath)} ({e})"
        )
        return "FILE:" + get_file_md5(filepath)
    finally:
        Image.MAX_IMAGE_PIXELS = original_max


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
