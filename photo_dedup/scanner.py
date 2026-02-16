"""
掃描模組 — 找出資料夾中的重複檔案

流程：
  1. 驗證輸入參數
  2. 用 os.walk (遞迴) 或 os.scandir (平面) 收集所有檔案
  3. 非圖片檔按大小分組預篩（大小不同不可能重複）
  4. 計算 hash（圖片: 像素 MD5 / 其他: 全檔 MD5）
  5. 產出 JSON 結構化報告 + 可讀文字報告
"""

import json
import os
import sys
import time
from collections import defaultdict

from .hasher import IMAGE_EXTENSIONS, compute_hash, init_heic_support
from .utils import format_size


def validate_scan_args(target_dir: str, output_dir: str):
    """驗證掃描參數，失敗時直接 sys.exit"""
    if not os.path.exists(target_dir):
        print(f"❌ Directory not found: {target_dir}")
        sys.exit(1)

    if not os.path.isdir(target_dir):
        print(f"❌ Not a directory: {target_dir}")
        sys.exit(1)

    if not os.access(target_dir, os.R_OK):
        print(f"❌ No read permission: {target_dir}")
        sys.exit(1)

    # 確保 output_dir 可寫
    os.makedirs(output_dir, exist_ok=True)
    if not os.access(output_dir, os.W_OK):
        print(f"❌ No write permission: {output_dir}")
        sys.exit(1)


def collect_files(
    target_dir: str,
    recursive: bool = True,
) -> list[tuple[str, int, str]]:
    """
    收集目標資料夾中的所有檔案。

    Args:
        target_dir: 目標資料夾
        recursive: 是否遞迴掃描子資料夾

    Returns:
        list of (absolute_path, size, ext)
    """
    skip_dirs = {'_duplicates_backup', '.git', '__pycache__'}
    all_files = []

    if recursive:
        for dirpath, dirnames, filenames in os.walk(target_dir):
            # 跳過特定目錄
            dirnames[:] = [
                d for d in dirnames
                if d not in skip_dirs and not d.startswith('.')
            ]
            for name in filenames:
                if name.startswith('.'):
                    continue
                filepath = os.path.join(dirpath, name)
                try:
                    size = os.path.getsize(filepath)
                    ext = os.path.splitext(name)[1].lower()
                    all_files.append((filepath, size, ext))
                except OSError:
                    pass
    else:
        for entry in os.scandir(target_dir):
            if entry.is_file(follow_symlinks=False) and not entry.name.startswith('.'):
                try:
                    stat = entry.stat()
                    ext = os.path.splitext(entry.name)[1].lower()
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


def build_groups(
    dup_groups: dict[str, list[str]],
    size_map: dict[str, int],
    target_dir: str,
) -> list[dict]:
    """
    建構重複組的結構化資料。

    Returns:
        list of group dicts, 每個包含 keep 和 delete 資訊
    """
    groups = []

    for h, files in sorted(dup_groups.items(), key=lambda x: -len(x[1])):
        files_with_size = [(f, size_map.get(f, 0)) for f in files]
        files_with_size.sort(key=lambda x: -x[1])  # 最大的排前面

        keep_path, keep_size = files_with_size[0]
        delete_files = files_with_size[1:]

        group = {
            "hash": h,
            "keep": {
                "path": os.path.relpath(keep_path, target_dir),
                "size": keep_size,
            },
            "delete": [
                {
                    "path": os.path.relpath(dp, target_dir),
                    "size": ds,
                }
                for dp, ds in delete_files
            ],
        }
        groups.append(group)

    return groups


def write_json_report(
    groups: list[dict],
    total_files: int,
    target_dir: str,
    output_dir: str,
    settings: dict,
):
    """寫入 JSON 結構化報告"""
    total_dup = sum(len(g["delete"]) for g in groups)
    total_save = sum(
        sum(d["size"] for d in g["delete"])
        for g in groups
    )

    report = {
        "version": "1.1.0",
        "scan_time": time.strftime('%Y-%m-%d %H:%M:%S'),
        "target_dir": target_dir,
        "settings": settings,
        "summary": {
            "total_files": total_files,
            "duplicate_groups": len(groups),
            "deletable_files": total_dup,
            "space_saveable_bytes": total_save,
            "space_saveable": format_size(total_save),
            "files_remaining": total_files - total_dup,
        },
        "groups": groups,
    }

    json_path = os.path.join(output_dir, "duplicates_data.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    return report


def write_text_report(
    report_data: dict,
    output_dir: str,
):
    """從 JSON 資料生成可讀文字報告"""
    report_path = os.path.join(output_dir, "duplicates_report.txt")
    summary = report_data["summary"]

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("Duplicate File Report / 重複檔案掃描報告\n")
        f.write(f"Time: {report_data['scan_time']}\n")
        f.write(f"Directory: {report_data['target_dir']}\n")
        f.write("=" * 70 + "\n\n")

        for i, group in enumerate(report_data["groups"], 1):
            total_in_group = 1 + len(group["delete"])
            f.write(f"--- Group #{i} ({total_in_group} files) ---\n")
            f.write(
                f"  KEEP: {group['keep']['path']} "
                f"({format_size(group['keep']['size'])})\n"
            )
            for d in group["delete"]:
                f.write(
                    f"  DEL:  {d['path']} "
                    f"({format_size(d['size'])})\n"
                )
            group_save = sum(d["size"] for d in group["delete"])
            f.write(f"  Save: {format_size(group_save)}\n\n")

        f.write("=" * 70 + "\n")
        f.write("Summary\n")
        f.write("=" * 70 + "\n")
        f.write(f"Total files: {summary['total_files']}\n")
        f.write(f"Duplicate groups: {summary['duplicate_groups']}\n")
        f.write(f"Duplicate files (deletable): {summary['deletable_files']}\n")
        f.write(f"Space saveable: {summary['space_saveable']}\n")
        f.write(f"Files remaining: {summary['files_remaining']}\n")


def scan(
    target_dir: str,
    output_dir: str | None = None,
    use_pixel: bool = True,
    recursive: bool = True,
):
    """
    主掃描流程。

    Args:
        target_dir: 要掃描的資料夾路徑
        output_dir: 報告輸出路徑 (預設 = target_dir)
        use_pixel: 是否使用像素比對 (預設 True)
        recursive: 是否遞迴掃描子資料夾 (預設 True)
    """
    sys.stdout.reconfigure(line_buffering=True)

    if output_dir is None:
        output_dir = target_dir

    target_dir = os.path.abspath(target_dir)
    output_dir = os.path.abspath(output_dir)

    # 驗證參數
    validate_scan_args(target_dir, output_dir)

    settings = {
        "use_pixel": use_pixel,
        "recursive": recursive,
    }

    print("=" * 50)
    print("Photo Dedup — Duplicate Scanner")
    print("=" * 50)
    print(f"Target:    {target_dir}")
    print(f"Output:    {output_dir}")
    print(f"Mode:      {'Pixel comparison' if use_pixel else 'File MD5 only'}")
    print(f"Recursive: {'Yes' if recursive else 'No'}")
    print()

    # Step 1
    print("[1/4] Collecting files...")
    all_files = collect_files(target_dir, recursive=recursive)
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

    # HEIC support
    if use_pixel:
        heic_ok = init_heic_support()
        print(
            f"  HEIC support: "
            f"{'OK' if heic_ok else 'NOT AVAILABLE (will use file MD5)'}"
        )

    # Step 3
    print("[3/4] Computing hashes...")
    all_candidates = image_candidates + non_image_candidates
    hash_groups, size_map = compute_hashes(
        all_candidates, use_pixel, total_to_hash
    )

    # Step 4
    print("[4/4] Generating reports...")
    dup_groups = {
        h: files for h, files in hash_groups.items() if len(files) > 1
    }

    groups = build_groups(dup_groups, size_map, target_dir)
    report_data = write_json_report(
        groups, len(all_files), target_dir, output_dir, settings
    )
    write_text_report(report_data, output_dir)

    summary = report_data["summary"]
    print()
    print("=" * 50)
    print("DONE!")
    print(f"  Total files:         {summary['total_files']}")
    print(f"  Duplicate groups:    {summary['duplicate_groups']}")
    print(f"  Deletable:           {summary['deletable_files']}")
    print(f"  Space saveable:      {summary['space_saveable']}")
    print(f"  Remaining:           {summary['files_remaining']}")
    print()
    print(f"  JSON:   {os.path.join(output_dir, 'duplicates_data.json')}")
    print(f"  Report: {os.path.join(output_dir, 'duplicates_report.txt')}")
    print()
    print("Review the report, then run: python clean.py --dir <DIR>")
