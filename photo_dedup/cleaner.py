"""
清理模組 — 安全刪除重複檔案 + 改名保留檔

流程：
  1. 解析 duplicates_report.txt 取得分組資訊
  2. 為每組選出最可讀的檔名
  3. 將重複檔案移到備份資料夾
  4. 將保留的檔案改名為最可讀的名稱
"""

import os
import re
import shutil
import sys
from pathlib import Path

from .naming import find_best_name, readability_score
from .utils import format_size


def parse_report(report_path: str) -> list[dict]:
    """
    解析 duplicates_report.txt。

    Returns:
        list of {'keep': filename, 'delete': [filenames]}
    """
    groups = []
    current_group = None

    with open(report_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip()

            if line.startswith('--- Group #'):
                current_group = {'keep': None, 'delete': []}
                continue

            if current_group is not None:
                m = re.match(r'\s+KEEP:\s+(.+?)\s+\(', line)
                if m:
                    current_group['keep'] = m.group(1)
                    continue

                m = re.match(r'\s+DEL:\s+(.+?)\s+\(', line)
                if m:
                    current_group['delete'].append(m.group(1))
                    continue

                if line.startswith('  Save:'):
                    if current_group['keep']:
                        groups.append(current_group)
                    current_group = None

    return groups


def clean(
    target_dir: str,
    report_path: str | None = None,
    backup_dir: str | None = None,
    do_rename: bool = True,
    dry_run: bool = False,
):
    """
    主清理流程。

    Args:
        target_dir: 照片資料夾路徑
        report_path: 報告檔路徑 (預設: <target_dir>/duplicates_report.txt)
        backup_dir: 備份資料夾路徑 (預設: <target_dir>/_duplicates_backup)
        do_rename: 是否改名保留檔案 (預設 True)
        dry_run: 預覽模式，不實際操作 (預設 False)
    """
    sys.stdout.reconfigure(line_buffering=True)

    target_dir = os.path.abspath(target_dir)

    if report_path is None:
        report_path = os.path.join(target_dir, "duplicates_report.txt")
    else:
        report_path = os.path.abspath(report_path)

    if backup_dir is None:
        backup_dir = os.path.join(target_dir, "_duplicates_backup")
    else:
        backup_dir = os.path.abspath(backup_dir)

    delete_list_path = os.path.join(
        os.path.dirname(report_path), "duplicates_to_delete.txt"
    )

    # 驗證檔案存在
    if not os.path.exists(report_path):
        print(f"❌ Report not found: {report_path}")
        print("   Run scan.py first to generate the report.")
        sys.exit(1)

    if not os.path.exists(delete_list_path):
        print(f"❌ Delete list not found: {delete_list_path}")
        sys.exit(1)

    # 讀取待刪清單
    with open(delete_list_path, 'r', encoding='utf-8') as f:
        files_to_delete = set(line.strip() for line in f if line.strip())

    # 解析報告
    print("Parsing report...")
    groups = parse_report(report_path)
    print(f"  {len(groups)} duplicate groups")

    # 計算改名清單
    rename_list = []
    if do_rename:
        for g in groups:
            new_name, should_rename = find_best_name(g['keep'], g['delete'])
            if should_rename:
                old_path = os.path.join(target_dir, g['keep'])
                new_path = os.path.join(target_dir, new_name)
                rename_list.append((old_path, new_path, g['keep'], new_name))
        print(f"  Files to rename: {len(rename_list)}")

    # 顯示改名範例
    if rename_list:
        print()
        print("Rename examples (first 10):")
        for _, _, old_n, new_n in rename_list[:10]:
            print(f"  {old_n}")
            print(f"    → {new_n}")
        if len(rename_list) > 10:
            print(f"  ... and {len(rename_list) - 10} more")

    print()
    print("=" * 50)
    print("Operation Summary")
    print("=" * 50)
    print(f"  Move to backup:  {len(files_to_delete)} files")
    print(f"  Rename kept:     {len(rename_list)} files")
    print(f"  Backup dir:      {backup_dir}")
    if dry_run:
        print("  *** DRY RUN — no changes will be made ***")
    print()

    if dry_run:
        print("Dry run complete. No files were modified.")
        return

    answer = input("Proceed? (y/N) ").strip().lower()
    if answer != 'y':
        print("Cancelled.")
        return

    # --- Phase A: 移動重複檔案 ---
    print(f"\n[1/2] Moving duplicates to backup...")
    os.makedirs(backup_dir, exist_ok=True)

    moved = 0
    skipped = 0
    total_size = 0
    move_errors = []

    for filepath_str in files_to_delete:
        filepath = Path(filepath_str)
        if not filepath.exists():
            skipped += 1
            continue

        try:
            file_size = filepath.stat().st_size
            dest = Path(backup_dir) / filepath.name

            if dest.exists():
                stem = filepath.stem
                suffix = filepath.suffix
                counter = 1
                while dest.exists():
                    dest = Path(backup_dir) / f"{stem}_dup{counter}{suffix}"
                    counter += 1

            shutil.move(str(filepath), str(dest))
            moved += 1
            total_size += file_size

            if moved % 500 == 0:
                print(f"  Moved {moved} files...")

        except Exception as e:
            move_errors.append((filepath_str, str(e)))

    print(f"  Done: moved {moved}, skipped {skipped}, errors {len(move_errors)}")
    print(f"  Space freed: {format_size(total_size)}")

    # --- Phase B: 改名保留檔案 ---
    if rename_list:
        print(f"\n[2/2] Renaming kept files...")
        renamed = 0
        rename_skipped = 0
        rename_errors = []

        for old_path, new_path, old_name, new_name in rename_list:
            if not os.path.exists(old_path):
                rename_skipped += 1
                continue

            if os.path.exists(new_path):
                rename_skipped += 1
                continue

            try:
                os.rename(old_path, new_path)
                renamed += 1
            except Exception as e:
                rename_errors.append((old_name, new_name, str(e)))

        print(f"  Done: renamed {renamed}, skipped {rename_skipped}, errors {len(rename_errors)}")

        if rename_errors:
            print(f"\n  Rename errors:")
            for old, new, err in rename_errors[:5]:
                print(f"    {old} → {new}: {err}")

    # --- 總結 ---
    print()
    print("=" * 50)
    print("ALL DONE!")
    print(f"  Moved:   {moved} files ({format_size(total_size)})")
    if rename_list:
        print(f"  Renamed: {renamed} files")
    print(f"  Backup:  {backup_dir}")
    print()
    print("Delete the backup folder when you're confident everything is correct.")

    if move_errors:
        print(f"\nMove errors ({len(move_errors)}):")
        for fp, err in move_errors[:5]:
            print(f"  {fp}: {err}")
