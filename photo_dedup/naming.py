"""
檔名可讀性評分與改名邏輯

用於在重複組中選出最具可讀性的檔名，
讓保留的檔案擁有最好辨識的名稱。

安全限制：
  - 永遠保留原檔的副檔名，不做副檔名變更
  - 避免副檔名與實際內容不符（例如 PNG 資料被改名為 .jpg）
"""

import re
from pathlib import Path


def is_meaningless(filename: str) -> bool:
    """
    判定檔名是否無意義，需要被改為日期格式。

    判定條件（任一成立即為 True）：
      - 純短數字 (1-9 位)：例如 "1", "23", "123456789"
      - 純 Unix 時間戳 (10-13 位數字)：例如 "1609753382985"
      - 亂碼：高比例非 ASCII 且無可辨識語義結構

    以下不視為無意義：
      - 日期格式 (YYYYMMDD)
      - 相機前綴 (IMG_, DSC_, PANO_, ...)
      - 含有描述性英文/中文文字
    """
    stem = Path(filename).stem

    # 移除副本標記
    clean_stem = re.sub(r'\s*\(\d+\)', '', stem).strip()

    if not clean_stem:
        return True

    # 有日期格式 → 不是無意義（需驗證月份 01-12、日期 01-31）
    m = re.match(r'^(\d{4})[-_]?(\d{2})[-_]?(\d{2})', clean_stem)
    if m:
        year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if 1900 <= year <= 2099 and 1 <= month <= 12 and 1 <= day <= 31:
            return False

    # 有相機前綴 → 不是無意義
    if re.match(
        r'^(IMG|DSC|DCIM|PANO|VID|MOV|Screenshot)',
        clean_stem,
        re.IGNORECASE,
    ):
        return False

    # 純數字（含 Unix 時間戳）→ 無意義
    if re.match(r'^\d{1,13}$', clean_stem):
        return True

    # 亂碼偵測：非 ASCII 且無可辨識語義（無英文字母、無 CJK 字元）
    has_alpha = bool(re.search(r'[a-zA-Z]', clean_stem))
    has_cjk = bool(re.search(r'[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff]', clean_stem))

    if not has_alpha and not has_cjk:
        # 非字母非 CJK，檢查是否高比例非 ASCII
        non_ascii_count = sum(1 for c in clean_stem if ord(c) > 127)
        if non_ascii_count > 0 and non_ascii_count / len(clean_stem) > 0.5:
            return True

    return False


def readability_score(filename: str) -> float:
    """
    評估檔名的可讀性。分數越高 = 越可讀。

    評分規則：
      +15  YYYYMMDD_HHMMSS 日期時間格式
      +10  YYYYMMDD 日期格式
      +3   IMG_, DSC_, PANO_ 等相機前綴
      +2   包含描述性文字 (英文/中文)
      -10  純 Unix 時間戳 (10-13 位數字)
      -5   純短數字 (無意義編號)
      -20  含 (1), (2) 等副本標記
    """
    stem = Path(filename).stem
    score = 0.0

    # 移除副本標記後的基本名稱
    clean_stem = re.sub(r'\s*\(\d+\)', '', stem).strip()

    # --- 扣分: 有副本標記 ---
    if re.search(r'\(\d+\)', stem):
        score -= 20

    # --- 加分: YYYYMMDD 日期格式 ---
    if re.match(r'^(\d{4}[-_]?\d{2}[-_]?\d{2})', clean_stem):
        score += 10

    # --- 加分: YYYYMMDD_HHMMSS 完整日期時間 ---
    if re.match(r'^\d{8}[_-]\d{6}', clean_stem):
        score += 5

    # --- 加分: 有 IMG_, DSC_ 等相機前綴 ---
    if re.match(
        r'^(IMG|DSC|DCIM|PANO|VID|MOV|Screenshot)',
        clean_stem,
        re.IGNORECASE,
    ):
        score += 3

    # --- 加分: 有描述性文字 ---
    if re.search(r'[a-zA-Z\u4e00-\u9fff]', clean_stem):
        score += 2

    # --- 扣分: 純長數字 (Unix 毫秒時間戳) ---
    if re.match(r'^\d{10,13}$', clean_stem):
        score -= 10

    # --- 扣分: 純短數字 (無意義編號) ---
    if re.match(r'^\d{1,9}$', clean_stem):
        score -= 5

    # 微調: 較短的檔名略微偏好
    score -= len(clean_stem) * 0.01

    return score


def find_best_name(
    keep_name: str,
    delete_names: list[str],
) -> tuple[str, bool]:
    """
    在同組所有檔案中，找出可讀性最高的 stem，
    但永遠保留 keep 檔的原始副檔名（不做轉碼就不改副檔名）。

    Args:
        keep_name: 目前保留的檔名 (basename)
        delete_names: 同組中待刪除的檔名列表 (basenames)

    Returns:
        (new_name, should_rename):
            new_name: 建議的新檔名（保留原副檔名）
            should_rename: 是否需要改名
    """
    all_names = [keep_name] + delete_names

    # 選最可讀的 stem
    best_name = max(all_names, key=readability_score)
    best_stem = Path(best_name).stem
    # 移除副本標記
    best_stem = re.sub(r'\s*\(\d+\)', '', best_stem).strip()

    # 永遠保留 keep 檔的原始副檔名
    keep_ext = Path(keep_name).suffix
    new_name = best_stem + keep_ext

    should_rename = (new_name != keep_name)
    return new_name, should_rename
