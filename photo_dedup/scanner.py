"""
掃描模組 — 找出資料夾中的重複檔案

流程：
  1. 用 os.scandir 快速收集所有檔案
  2. 非圖片檔按大小分組預篩（大小不同不可能重複）
  3. 計算 hash（圖片: 像素 MD5 / 其他: 全檔 MD5）
  4. 產出報告 + 待刪清單
"""

import os
import sys
import time
from collections import defaultdict
from pathlib import Path

from .hasher import IMAGE_EXTENSIONS, compute_hash, init_heic_support
from .utils import format_size

# 掃描時要排除的檔案
SKIP_NAMES = {
    'find_duplicates.py', 'delete_duplicates.py',
    'duplicates_report.txt', 'duplicates_to_delete.txt',
    'scan.py', 'clean.py',
}


def collect_files(target_dir: str) -> list[tuple[str, int, str]]:
    """
    收集目標資料夾中的所有檔案。

    Returns:
        list of (path, size, ext)
    """
    all_files = []
    for entry in os.scandir(target_dir):
        if entry.is_file(follow_symlinks=False):
            name = entry.name
            if name in SKIP_NAMES or name.startswith('_duplicates_backup') or name.startswith('.'):
                continue
            try:
                stat = entry.stat()
                ext = os.path.splitext(name)[1].lower()
                all_files.append((entry.path, stat.st_size, ext))
            except OSError:
                pass
    return all_files


def categorize_files(
    all_files: list[tuple[str, int, str]],
    use_pixel: bool,
) -> tuple[list, list]:
    """
    分類檔案：決定哪些需要計算 hash。

    非圖片檔只有大小相同時才需要比對。
    圖片檔因為 metadata 差異會導致大小不同，全部都需要比對。

    Returns:
        (image_candidates, non_image_candidates)
    """
    image_files = []
    non_image_by_size = defaultdict(list)

    for path, size, ext in all_files:
        if use_pixel and ext in IMAGE_EXTENSIONS:
            image_files.append((path, size, ext))
        else:
            non_image_by_size[size].append((path, size, ext))

    non_image_candidates = []
    for size, files in non_image_by_size.items():
        if len(files) > 1:
            non_image_candidates.extend(files)

    return image_files, non_image_candidates


def compute_hashes(
    candidates: list[tuple[str, int, str]],
    use_pixel: bool,
    total: int,
) -> tuple[dict[str, list], dict[str, int]]:
    """
    計算所有候選檔案的 hash。

    Returns:
        (hash_groups, size_map)
    """
    hash_groups = defaultdict(list)
    size_map = {}
    processed = 0
    errors = 0
    start_time = time.time()

    for path, size, ext in candidates:
        try:
            h = compute_hash(path, ext, use_pixel)
            hash_groups[h].append(path)
            size_map[path] = size
        except Exception as e:
            errors += 1
            print(f"  [ERROR] {os.path.basename(path)}: {e}")

        processed += 1
        if processed % 1000 == 0:
            elapsed = time.time() - start_time
            speed = processed / elapsed if elapsed > 0 else 0
            remaining = (total - processed) / speed if speed > 0 else 0
            print(
                f"  Progress: {processed}/{total} "
                f"({processed * 100 // total}%) "
                f"ETA: {remaining:.0f}s"
            )

    elapsed = time.time() - start_time
    print(f"  Done! {elapsed:.1f}s, {errors} errors")
    return hash_groups, size_map


def generate_report(
    dup_groups: dict,
    size_map: dict,
    total_files: int,
    target_dir: str,
    output_dir: str,
) -> tuple[int, int, list]:
    """
    產出報告和待刪清單。

    Returns:
        (total_dup_files, total_saveable, to_delete_paths)
    """
    total_dup_files = 0
    total_saveable = 0
    to_delete = []

    report_path = os.path.join(output_dir, "duplicates_report.txt")
    delete_list_path = os.path.join(output_dir, "duplicates_to_delete.txt")

    with open(report_path, 'w', encoding='utf-8') as report:
        report.write("=" * 70 + "\n")
        report.write("Duplicate File Report / 重複檔案掃描報告\n")
        report.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write(f"Directory: {target_dir}\n")
        report.write("=" * 70 + "\n\n")

        group_num = 0
        for h, files in sorted(dup_groups.items(), key=lambda x: -len(x[1])):
            group_num += 1

            files_with_size = [(f, size_map.get(f, 0)) for f in files]
            files_with_size.sort(key=lambda x: -x[1])

            keep_file, keep_size = files_with_size[0]
            delete_files = files_with_size[1:]

            group_saveable = sum(s for _, s in delete_files)
            total_saveable += group_saveable
            total_dup_files += len(delete_files)

            report.write(f"--- Group #{group_num} ({len(files)} files) ---\n")
            report.write(
                f"  KEEP: {os.path.basename(keep_file)} "
                f"({format_size(keep_size)})\n"
            )
            for df, ds in delete_files:
                report.write(
                    f"  DEL:  {os.path.basename(df)} "
                    f"({format_size(ds)})\n"
                )
                to_delete.append(df)
            report.write(f"  Save: {format_size(group_saveable)}\n\n")

        report.write("=" * 70 + "\n")
        report.write("Summary\n")
        report.write("=" * 70 + "\n")
        report.write(f"Total files: {total_files}\n")
        report.write(f"Duplicate groups: {group_num}\n")
        report.write(f"Duplicate files (deletable): {total_dup_files}\n")
        report.write(f"Space saveable: {format_size(total_saveable)}\n")
        report.write(f"Files remaining: {total_files - total_dup_files}\n")

    with open(delete_list_path, 'w', encoding='utf-8') as f:
        for df in to_delete:
            f.write(df + "\n")

    return total_dup_files, total_saveable, to_delete


def scan(target_dir: str, output_dir: str | None = None, use_pixel: bool = True):
    """
    主掃描流程。

    Args:
        target_dir: 要掃描的資料夾路徑
        output_dir: 報告輸出路徑 (預設 = target_dir)
        use_pixel: 是否使用像素比對 (預設 True)
    """
    sys.stdout.reconfigure(line_buffering=True)

    if output_dir is None:
        output_dir = target_dir

    target_dir = os.path.abspath(target_dir)
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 50)
    print("Photo Dedup — Duplicate Scanner")
    print("=" * 50)
    print(f"Target:  {target_dir}")
    print(f"Output:  {output_dir}")
    print(f"Mode:    {'Pixel comparison' if use_pixel else 'File MD5 only'}")
    print()

    # Step 1
    print("[1/4] Collecting files...")
    all_files = collect_files(target_dir)
    print(f"  Found {len(all_files)} files")

    if not all_files:
        print("  No files to scan. Exiting.")
        return

    # Step 2
    print("[2/4] Categorizing...")
    image_candidates, non_image_candidates = categorize_files(all_files, use_pixel)

    total_to_hash = len(image_candidates) + len(non_image_candidates)
    print(f"  Images (pixel hash): {len(image_candidates)}")
    print(f"  Non-images (file MD5, size-matched): {len(non_image_candidates)}")
    print(f"  Total to process: {total_to_hash}")

    # Step 3: HEIC support
    if use_pixel:
        heic_ok = init_heic_support()
        print(f"  HEIC support: {'OK' if heic_ok else 'NOT AVAILABLE (will use file MD5)'}")

    # Step 4
    print(f"[3/4] Computing hashes...")
    all_candidates = image_candidates + non_image_candidates
    hash_groups, size_map = compute_hashes(all_candidates, use_pixel, total_to_hash)

    # Step 5
    print("[4/4] Generating report...")
    dup_groups = {h: files for h, files in hash_groups.items() if len(files) > 1}
    total_dup, total_save, _ = generate_report(
        dup_groups, size_map, len(all_files), target_dir, output_dir
    )

    remaining = len(all_files) - total_dup
    print()
    print("=" * 50)
    print("DONE!")
    print(f"  Total files:         {len(all_files)}")
    print(f"  Duplicate groups:    {len(dup_groups)}")
    print(f"  Deletable:           {total_dup}")
    print(f"  Space saveable:      {format_size(total_save)}")
    print(f"  Remaining:           {remaining}")
    print()
    print(f"  Report:      {os.path.join(output_dir, 'duplicates_report.txt')}")
    print(f"  Delete list: {os.path.join(output_dir, 'duplicates_to_delete.txt')}")
    print()
    print("Review the report, then run: python clean.py --dir <DIR>")
