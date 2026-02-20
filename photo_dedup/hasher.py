"""
檔案 hash 計算模組

提供三種 hash 策略：
  - 全檔 MD5：適用非圖片檔
  - 像素 MD5：用 Pillow 解碼後比對像素資料，忽略 EXIF / ICC profile 差異
  - 感知雜湊 (dHash)：縮圖後差分比對，跨解析度偵測相似圖片

安全措施：
  - 限制最大圖片像素數，超過上限自動 fallback 到全檔 MD5
  - 像素 hash 需要將整張圖的 RGB 資料載入記憶體 (Pillow 限制)
  - MAX_IMAGE_PIXELS 限制確保記憶體用量不超過 ~180MB/張 (60MP × 3 bytes)
"""

import hashlib
import logging
import os
from typing import NamedTuple

logger = logging.getLogger(__name__)

# 支援像素比對的圖片副檔名
IMAGE_EXTENSIONS = frozenset({'.jpg', '.jpeg', '.png', '.heic', '.webp', '.dng'})

# 像素上限 (60 megapixels → 最大 ~180MB RAM per image)
# Pillow 的 tobytes() 會一次載入整張圖的 RGB 資料，
# 無法真正串流讀取，因此用此上限控制記憶體用量。
MAX_IMAGE_PIXELS = 60_000_000

# --- 感知雜湊 (dHash) 相關常數 ---
# dHash 尺寸：hash_size=16 → 產出 16×16=256-bit hash
DHASH_SIZE = 16

# Hamming distance 門檻（256-bit hash 下）
# 同張圖不同解析度 / JPEG 重壓通常 < 15；20 留些餘裕
HAMMING_THRESHOLD = 20

# RMS 像素差門檻（0-255 scale）
# JPEG 重壓 + resize 的 RMS 通常在 2-6，8.0 留些餘裕
RMS_THRESHOLD = 8.0


class HashResult(NamedTuple):
    """hash 結果，區分 hash 方法"""
    method: str  # "pixel" or "file"
    digest: str  # hex digest

    def __str__(self) -> str:
        if self.method == "file":
            return f"FILE:{self.digest}"
        return self.digest


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


def get_file_partial_md5(filepath: str, chunk_size: int = 65536) -> str:
    """
    計算檔案「頭 + 尾」的 partial MD5，用於非圖片預篩。

    - 小檔案 (<= 2 * chunk_size): 直接 hash 全檔
    - 大檔案: hash 前 chunk + 檔案大小 + 後 chunk
    """
    file_size = os.path.getsize(filepath)
    h = hashlib.md5()

    with open(filepath, "rb") as f:
        if file_size <= chunk_size * 2:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
            return h.hexdigest()

        head = f.read(chunk_size)
        h.update(head)
        h.update(file_size.to_bytes(8, byteorder="little", signed=False))
        f.seek(-chunk_size, os.SEEK_END)
        tail = f.read(chunk_size)
        h.update(tail)

    return h.hexdigest()


def get_pixel_hash(filepath: str) -> HashResult:
    """
    用 Pillow 解碼圖片，取出純像素資料的 MD5。
    忽略 EXIF、ICC profile 等 metadata 差異。

    記憶體說明：
      Pillow 不支援逐列串流讀取像素，img.tobytes() 會產生
      width × height × 3 bytes 的完整 buffer。
      MAX_IMAGE_PIXELS 限制確保單張圖最多使用 ~180MB。

    不修改全域 Image.MAX_IMAGE_PIXELS，改為函式內自行檢查尺寸。
    """
    from PIL import Image, ImageOps

    try:
        with Image.open(filepath) as img:
            width, height = img.size
            pixel_count = width * height
            if pixel_count > MAX_IMAGE_PIXELS:
                logger.warning(
                    "Image too large (%s px), fallback to file MD5: %s",
                    f"{pixel_count:,}",
                    os.path.basename(filepath),
                )
                return HashResult("file", get_file_md5(filepath))

            # 先正規化 EXIF orientation，再做像素比對
            img_normalized = ImageOps.exif_transpose(img)
            try:
                img_rgb = img_normalized.convert('RGB')
            finally:
                if img_normalized is not img:
                    img_normalized.close()
                del img_normalized

        # img 已關閉，img_rgb 仍可用
        raw = img_rgb.tobytes()
        del img_rgb  # 盡快釋放 PIL Image

        h = hashlib.md5()
        chunk_size = 1024 * 1024  # 1MB
        for i in range(0, len(raw), chunk_size):
            h.update(raw[i:i + chunk_size])

        del raw  # 盡快釋放 bytes buffer
        return HashResult("pixel", h.hexdigest())

    except Image.DecompressionBombError:
        logger.warning(
            "Decompression bomb detected, fallback to file MD5: %s",
            os.path.basename(filepath),
        )
        return HashResult("file", get_file_md5(filepath))
    except Exception as e:
        logger.warning(
            "Cannot decode image, fallback to file MD5: %s (%s)",
            os.path.basename(filepath),
            e,
        )
        return HashResult("file", get_file_md5(filepath))


def compute_hash(filepath: str, ext: str, use_pixel: bool = True) -> str:
    """
    根據副檔名和設定選擇 hash 策略。

    Args:
        filepath: 檔案路徑
        ext: 副檔名 (小寫, 含點號)
        use_pixel: 是否對圖片使用像素比對

    Returns:
        hash 字串（pixel hash 為純 hex，file hash 帶 "FILE:" 前綴）
    """
    if use_pixel and ext in IMAGE_EXTENSIONS:
        return str(get_pixel_hash(filepath))
    else:
        return f"FILE:{get_file_md5(filepath)}"


def get_dhash(filepath: str, hash_size: int = DHASH_SIZE) -> bytes:
    """
    計算圖片的 difference hash (dHash)。

    將圖片縮放到 (hash_size+1, hash_size) 灰階後，
    比較相鄰像素的亮度差異，產出固定長度的 hash。
    天然具備 resolution-invariance，適合跨解析度比對。

    Args:
        filepath: 圖片路徑
        hash_size: hash 邊長，產出 hash_size² bits

    Returns:
        packed bytes (hash_size² // 8 bytes)

    Raises:
        Exception: 圖片無法開啟或解碼時
    """
    import numpy as np
    from PIL import Image, ImageOps

    with Image.open(filepath) as img:
        width, height = img.size
        pixel_count = width * height
        if pixel_count > MAX_IMAGE_PIXELS:
            raise ValueError(
                f"Image too large for dHash ({pixel_count:,} px): "
                f"{os.path.basename(filepath)}"
            )

        img_normalized = ImageOps.exif_transpose(img)
        try:
            img_small = img_normalized.resize(
                (hash_size + 1, hash_size), Image.LANCZOS,
            ).convert('L')
        finally:
            if img_normalized is not img:
                img_normalized.close()
            del img_normalized

    pixels = np.asarray(img_small, dtype=np.int16)
    del img_small

    # 水平差分：右邊像素 > 左邊像素 → 1, 否則 → 0
    diff = (pixels[:, 1:] > pixels[:, :-1]).flatten()

    # pack bool array → bytes
    # numpy packbits 輸出 big-endian bit order
    packed = np.packbits(diff).tobytes()
    return packed


def hamming_distance(a: bytes, b: bytes) -> int:
    """
    計算兩個 bytes 的 Hamming distance (不同 bit 數)。

    使用整數 XOR + popcount，效率高。
    """
    int_a = int.from_bytes(a, byteorder='big')
    int_b = int.from_bytes(b, byteorder='big')
    return (int_a ^ int_b).bit_count()


def compute_rms_difference(
    path_a: str,
    path_b: str,
    target_size: tuple[int, int] = (256, 256),
) -> float:
    """
    計算兩張圖片 resize 到相同尺寸後的 RMS 像素差。

    兩張圖各自做 EXIF transpose → resize → RGB，
    然後計算 per-pixel RMS difference。

    Args:
        path_a: 第一張圖路徑
        path_b: 第二張圖路徑
        target_size: 統一的目標尺寸 (width, height)

    Returns:
        RMS 值 (0-255 scale)。0 = 完全相同，值越大差異越大。
        任一張開圖失敗 → float('inf')（安全預設：不合併）
    """
    import numpy as np
    from PIL import Image, ImageOps

    def _load_resized(path: str) -> np.ndarray:
        with Image.open(path) as img:
            width, height = img.size
            pixel_count = width * height
            if pixel_count > MAX_IMAGE_PIXELS:
                raise ValueError(
                    f"Image too large for RMS comparison ({pixel_count:,} px): "
                    f"{os.path.basename(path)}"
                )
            img_normalized = ImageOps.exif_transpose(img)
            try:
                img_resized = img_normalized.resize(
                    target_size, Image.LANCZOS,
                ).convert('RGB')
            finally:
                if img_normalized is not img:
                    img_normalized.close()
                del img_normalized
        arr = np.asarray(img_resized, dtype=np.float64)
        del img_resized
        return arr

    try:
        arr_a = _load_resized(path_a)
        arr_b = _load_resized(path_b)
    except Exception as e:
        logger.warning(
            "RMS comparison failed: %s vs %s (%s)",
            os.path.basename(path_a),
            os.path.basename(path_b),
            e,
        )
        return float('inf')

    diff = arr_a - arr_b
    rms = float(np.sqrt(np.mean(diff * diff)))
    del arr_a, arr_b, diff
    return rms


def init_heic_support() -> bool:
    """嘗試載入 HEIC 支援，回傳是否成功"""
    try:
        from pillow_heif import register_heif_opener
        register_heif_opener()
        return True
    except ImportError:
        # 不修改 IMAGE_EXTENSIONS，避免測試與執行期出現全域副作用。
        # 無 HEIC 解碼器時，compute_hash() 會在 get_pixel_hash() 中自動 fallback。
        return False
