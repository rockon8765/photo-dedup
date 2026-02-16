"""
檔名可讀性評分與改名邏輯

用於在重複組中選出最具可讀性的檔名，
讓保留的檔案擁有最好辨識的名稱。
"""

import re
from pathlib import Path


# 常見圖片副檔名優先順序 (越前面越優先)
EXTENSION_PRIORITY = {
    '.jpg': 10,
    '.jpeg': 9,
    '.png': 8,
    '.heic': 7,
    '.webp': 6,
    '.dng': 5,
}


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


def extension_score(ext: str) -> int:
    """評估副檔名的優先順序。分數越高表示越通用/優先。"""
    return EXTENSION_PRIORITY.get(ext.lower(), 0)


def find_best_name(
    keep_name: str,
    delete_names: list[str],
) -> tuple[str, bool]:
    """
    在同組所有檔案中，找出最佳的檔名與副檔名組合。

    策略：
      1. 從所有檔名中選出可讀性最高的 stem
      2. 從所有副檔名中選出最優先的 extension
      3. 組合為新檔名

    Args:
        keep_name: 目前保留的檔名 (basename)
        delete_names: 同組中待刪除的檔名列表 (basenames)

    Returns:
        (new_name, should_rename):
            new_name: 建議的新檔名
            should_rename: 是否需要改名
    """
    all_names = [keep_name] + delete_names

    # 1. 選最可讀的 stem
    best_name = max(all_names, key=readability_score)
    best_stem = Path(best_name).stem
    # 移除副本標記
    best_stem = re.sub(r'\s*\(\d+\)', '', best_stem).strip()

    # 2. 選最優先的副檔名
    all_exts = [Path(n).suffix for n in all_names]
    # 優先使用 keep 檔的副檔名，除非有更優先的
    keep_ext = Path(keep_name).suffix
    best_ext = keep_ext  # default

    # 找出最高優先的副檔名
    ext_scores = [(ext, extension_score(ext)) for ext in set(all_exts)]
    ext_scores.sort(key=lambda x: -x[1])
    if ext_scores and ext_scores[0][1] > extension_score(keep_ext):
        best_ext = ext_scores[0][0]

    # 3. 組合
    new_name = best_stem + best_ext

    should_rename = (new_name != keep_name)
    return new_name, should_rename
