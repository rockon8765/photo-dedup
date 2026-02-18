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
import logging
import os
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import datetime, timezone
from typing import NamedTuple

from .exceptions import AccessDeniedError, DirectoryNotFoundError
from .hasher import IMAGE_EXTENSIONS, compute_hash, init_heic_support
from .utils import VERSION, format_size

logger = logging.getLogger(__name__)


class FileEntry(NamedTuple):
    """Represents a file found during scanning."""
    path: str
    size: int
    ext: str


def validate_scan_args(target_dir: str, output_dir: str):
    """
    驗證掃描參數。

    Raises:
        DirectoryNotFoundError: 目標資料夾不存在
        AccessDeniedError: 權限不足
    """
    if not os.path.exists(target_dir):
        raise DirectoryNotFoundError(f"Directory not found: {target_dir}")

    if not os.path.isdir(target_dir):
        raise DirectoryNotFoundError(f"Not a directory: {target_dir}")

    if not os.access(target_dir, os.R_OK):
        raise AccessDeniedError(f"No read permission: {target_dir}")

    # 確保 output_dir 可寫
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        raise AccessDeniedError(
            f"Cannot create output directory: {output_dir} ({e})"
        )

    if not os.access(output_dir, os.W_OK):
        raise AccessDeniedError(f"No write permission: {output_dir}")


def collect_files(
    target_dir: str,
    recursive: bool = True,
) -> tuple[list[FileEntry], list[str]]:
    """
    收集目標資料夾中的所有檔案。

    Args:
        target_dir: 目標資料夾
        recursive: 是否遞迴掃描子資料夾

    Returns:
        (files, errors):
            files: list of FileEntry(path, size, ext)
            errors: list of error messages for skipped files
    """
    skip_dirs = {'_duplicates_backup', '.git', '__pycache__'}
    all_files: list[FileEntry] = []
    errors: list[str] = []

    if recursive:
        def _walk_onerror(e: OSError) -> None:
            location = e.filename or target_dir
            errors.append(f"{location}: {e}")

        # followlinks=False: 防止符號連結逃逸目標目錄
        for dirpath, dirnames, filenames in os.walk(
            target_dir, followlinks=False, onerror=_walk_onerror,
        ):
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
                    all_files.append(FileEntry(filepath, size, ext))
                except OSError as e:
                    errors.append(f"{filepath}: {e}")
    else:
        for entry in os.scandir(target_dir):
            if entry.is_file(follow_symlinks=False) and not entry.name.startswith('.'):
                try:
                    stat = entry.stat()
                    ext = os.path.splitext(entry.name)[1].lower()
                    all_files.append(FileEntry(entry.path, stat.st_size, ext))
                except OSError as e:
                    errors.append(f"{entry.path}: {e}")

    return all_files, errors


def categorize_files(
    all_files: list[FileEntry],
    use_pixel: bool,
) -> tuple[list[FileEntry], list[FileEntry]]:
    """
    分類檔案：決定哪些需要計算 hash。

    非圖片檔只有大小相同時才需要比對。
    圖片檔因為 metadata 差異會導致大小不同，全部都需要比對。

    Returns:
        (image_candidates, non_image_candidates)
    """
    image_files: list[FileEntry] = []
    non_image_by_size: dict[int, list[FileEntry]] = defaultdict(list)

    for entry in all_files:
        if use_pixel and entry.ext in IMAGE_EXTENSIONS:
            image_files.append(entry)
        else:
            non_image_by_size[entry.size].append(entry)

    non_image_candidates: list[FileEntry] = []
    for size, files in non_image_by_size.items():
        if len(files) > 1:
            non_image_candidates.extend(files)

    return image_files, non_image_candidates


def _hash_one(args: tuple[str, str, bool]) -> tuple[str, str] | None:
    """Worker function for parallel hashing. Returns (path, hash) or None."""
    path, ext, use_pixel = args
    try:
        return (path, compute_hash(path, ext, use_pixel))
    except Exception as e:
        logger.error("Hash failed: %s: %s", os.path.basename(path), e)
        return None


def compute_hashes(
    candidates: list[FileEntry],
    use_pixel: bool,
    total: int,
) -> tuple[dict[str, list[str]], dict[str, int]]:
    """
    計算所有候選檔案的 hash。
    圖片檔使用 ProcessPoolExecutor (CPU-bound)，
    非圖片檔使用 ThreadPoolExecutor (I/O-bound)。

    Returns:
        (hash_groups, size_map)
    """
    hash_groups: dict[str, list[str]] = defaultdict(list)
    size_map: dict[str, int] = {}
    processed = 0
    errors = 0
    start_time = time.time()

    # 分離圖片和非圖片候選
    image_candidates = [
        e for e in candidates
        if use_pixel and e.ext in IMAGE_EXTENSIONS
    ]
    non_image_candidates = [
        e for e in candidates
        if not (use_pixel and e.ext in IMAGE_EXTENSIONS)
    ]

    def _process_results(
        results,
        entries: list[FileEntry],
    ) -> None:
        nonlocal processed, errors
        for entry, result in zip(entries, results):
            if result is not None:
                path, h = result
                hash_groups[h].append(path)
                size_map[path] = entry.size
            else:
                errors += 1
            processed += 1
            if processed % 1000 == 0:
                elapsed = time.time() - start_time
                speed = processed / elapsed if elapsed > 0 else 0
                remaining = (total - processed) / speed if speed > 0 else 0
                logger.info(
                    "Progress: %d/%d (%d%%) ETA: %.0fs",
                    processed, total, processed * 100 // total, remaining,
                )

    # 非圖片: I/O-bound, 用 ThreadPoolExecutor
    if non_image_candidates:
        args_list = [(e.path, e.ext, use_pixel) for e in non_image_candidates]
        with ThreadPoolExecutor() as pool:
            results = pool.map(_hash_one, args_list)
        _process_results(results, non_image_candidates)

    # 圖片: CPU-bound, 用 ProcessPoolExecutor
    if image_candidates:
        args_list = [(e.path, e.ext, use_pixel) for e in image_candidates]
        try:
            with ProcessPoolExecutor() as pool:
                results = pool.map(_hash_one, args_list, chunksize=8)
            _process_results(results, image_candidates)
        except Exception:
            # ProcessPoolExecutor 可能在某些環境下失敗，fallback 到序列
            logger.warning(
                "ProcessPool failed, falling back to sequential",
                exc_info=True,
            )
            results = (_hash_one(a) for a in args_list)
            _process_results(results, image_candidates)

    elapsed = time.time() - start_time
    logger.info("Done! %.1fs, %d errors", elapsed, errors)
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
        # 先按大小遞減，再按路徑字典序，確保同大小時結果穩定可重現
        files_with_size.sort(key=lambda x: (-x[1], os.path.normcase(x[0])))

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
        "version": VERSION,
        "scan_time": datetime.now(timezone.utc).isoformat(),
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

    Raises:
        DirectoryNotFoundError: 目標資料夾不存在
        AccessDeniedError: 權限不足
    """

    if output_dir is None:
        output_dir = target_dir

    target_dir = os.path.abspath(target_dir)
    output_dir = os.path.abspath(output_dir)

    # 驗證參數（會拋出自訂例外）
    validate_scan_args(target_dir, output_dir)

    settings = {
        "use_pixel": use_pixel,
        "recursive": recursive,
    }

    logger.info("=" * 50)
    logger.info("Photo Dedup -- Duplicate Scanner")
    logger.info("=" * 50)
    logger.info("Target:    %s", target_dir)
    logger.info("Output:    %s", output_dir)
    logger.info("Mode:      %s", 'Pixel comparison' if use_pixel else 'File MD5 only')
    logger.info("Recursive: %s", 'Yes' if recursive else 'No')

    # Step 1
    logger.info("[1/4] Collecting files...")
    all_files, collect_errors = collect_files(target_dir, recursive=recursive)
    logger.info("  Found %d files", len(all_files))

    if collect_errors:
        logger.warning("Skipped %d files due to errors:", len(collect_errors))
        for err in collect_errors[:5]:
            logger.warning("  %s", err)
        if len(collect_errors) > 5:
            logger.warning("  ... and %d more", len(collect_errors) - 5)

    if not all_files:
        logger.info("  No files to scan. Writing empty reports...")
        report_data = write_json_report(
            groups=[],
            total_files=0,
            target_dir=target_dir,
            output_dir=output_dir,
            settings=settings,
        )
        write_text_report(report_data, output_dir)
        logger.info("  JSON:   %s", os.path.join(output_dir, 'duplicates_data.json'))
        logger.info("  Report: %s", os.path.join(output_dir, 'duplicates_report.txt'))
        return

    # Step 2
    logger.info("[2/4] Categorizing...")
    image_candidates, non_image_candidates = categorize_files(all_files, use_pixel)

    total_to_hash = len(image_candidates) + len(non_image_candidates)
    logger.info("  Images (pixel hash): %d", len(image_candidates))
    logger.info("  Non-images (file MD5, size-matched): %d", len(non_image_candidates))
    logger.info("  Total to process: %d", total_to_hash)

    # HEIC support
    if use_pixel:
        heic_ok = init_heic_support()
        logger.info(
            "  HEIC support: %s",
            'OK' if heic_ok else 'NOT AVAILABLE (will use file MD5)',
        )

    # Step 3
    logger.info("[3/4] Computing hashes...")
    all_candidates = image_candidates + non_image_candidates
    hash_groups, size_map = compute_hashes(
        all_candidates, use_pixel, total_to_hash
    )

    # Step 4
    logger.info("[4/4] Generating reports...")
    dup_groups = {
        h: files for h, files in hash_groups.items() if len(files) > 1
    }

    groups = build_groups(dup_groups, size_map, target_dir)
    report_data = write_json_report(
        groups, len(all_files), target_dir, output_dir, settings
    )
    write_text_report(report_data, output_dir)

    summary = report_data["summary"]
    logger.info("")
    logger.info("=" * 50)
    logger.info("DONE!")
    logger.info("  Total files:         %d", summary['total_files'])
    logger.info("  Duplicate groups:    %d", summary['duplicate_groups'])
    logger.info("  Deletable:           %d", summary['deletable_files'])
    logger.info("  Space saveable:      %s", summary['space_saveable'])
    logger.info("  Remaining:           %d", summary['files_remaining'])
    logger.info("")
    logger.info("  JSON:   %s", os.path.join(output_dir, 'duplicates_data.json'))
    logger.info("  Report: %s", os.path.join(output_dir, 'duplicates_report.txt'))
    logger.info("")
    logger.info("Review the report, then run: python clean.py --dir <DIR>")
