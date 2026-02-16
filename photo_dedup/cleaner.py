"""
清理模組 — 安全刪除重複檔案 + 改名保留檔

流程：
  1. 讀取 JSON 結構化報告 (duplicates_data.json)
  2. 為每組選出最可讀的檔名
  3. 將重複檔案移到備份資料夾 (保留原始目錄結構)
  4. 將保留的檔案改名為最可讀的名稱
  5. 記錄 transaction log 供回滾使用

安全措施：
  - 備份保留來源目錄結構，方便追溯
  - Transaction log 支援 --undo 回滾
  - --dry-run 預覽模式
  - --yes 非互動模式
"""

import json
import os
import shutil
import sys
import time
from pathlib import Path

from .naming import find_best_name
from .utils import format_size


def validate_clean_args(
    target_dir: str,
    json_path: str,
    backup_dir: str,
):
    """驗證清理參數，失敗時直接 sys.exit"""
    if not os.path.isdir(target_dir):
        print(f"❌ Directory not found: {target_dir}")
        sys.exit(1)

    if not os.access(target_dir, os.W_OK):
        print(f"❌ No write permission: {target_dir}")
        sys.exit(1)

    if not os.path.isfile(json_path):
        print(f"❌ JSON report not found: {json_path}")
        print("   Run scan.py first to generate the report.")
        sys.exit(1)

    # 確保備份目錄可建立
    try:
        os.makedirs(backup_dir, exist_ok=True)
    except OSError as e:
        print(f"❌ Cannot create backup directory: {backup_dir} ({e})")
        sys.exit(1)

    if not os.access(backup_dir, os.W_OK):
        print(f"❌ No write permission for backup: {backup_dir}")
        sys.exit(1)


def load_json_report(json_path: str) -> dict:
    """載入 JSON 結構化報告"""
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    if "groups" not in data:
        print(f"❌ Invalid JSON report: missing 'groups' key")
        sys.exit(1)

    return data


def clean(
    target_dir: str,
    json_path: str | None = None,
    backup_dir: str | None = None,
    do_rename: bool = True,
    dry_run: bool = False,
    auto_yes: bool = False,
):
    """
    主清理流程。

    Args:
        target_dir: 照片資料夾路徑
        json_path: JSON 報告路徑 (預設: <target_dir>/duplicates_data.json)
        backup_dir: 備份資料夾路徑 (預設: <target_dir>/_duplicates_backup)
        do_rename: 是否改名保留檔案 (預設 True)
        dry_run: 預覽模式，不實際操作 (預設 False)
        auto_yes: 跳過互動確認 (預設 False)
    """
    sys.stdout.reconfigure(line_buffering=True)

    target_dir = os.path.abspath(target_dir)

    if json_path is None:
        json_path = os.path.join(target_dir, "duplicates_data.json")
    else:
        json_path = os.path.abspath(json_path)

    if backup_dir is None:
        backup_dir = os.path.join(target_dir, "_duplicates_backup")
    else:
        backup_dir = os.path.abspath(backup_dir)

    # 驗證參數
    validate_clean_args(target_dir, json_path, backup_dir)

    # 載入 JSON 報告
    print("Loading JSON report...")
    report_data = load_json_report(json_path)
    groups = report_data["groups"]
    print(f"  {len(groups)} duplicate groups")

    # 計算改名清單
    rename_list = []  # [(old_rel, new_rel, old_name, new_name)]
    if do_rename:
        for g in groups:
            keep_name = os.path.basename(g["keep"]["path"])
            delete_names = [
                os.path.basename(d["path"]) for d in g["delete"]
            ]
            new_name, should_rename = find_best_name(keep_name, delete_names)
            if should_rename:
                keep_rel = g["keep"]["path"]
                keep_dir = os.path.dirname(keep_rel)
                new_rel = os.path.join(keep_dir, new_name) if keep_dir else new_name
                rename_list.append((keep_rel, new_rel, keep_name, new_name))
        print(f"  Files to rename: {len(rename_list)}")

    # 建立待刪清單 (相對路徑)
    files_to_delete = []
    for g in groups:
        for d in g["delete"]:
            files_to_delete.append(d["path"])

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

    if not auto_yes:
        answer = input("Proceed? (y/N) ").strip().lower()
        if answer != 'y':
            print("Cancelled.")
            return

    # Transaction log — 記錄所有操作以支援回滾
    transaction_log = {
        "version": "1.1.0",
        "time": time.strftime('%Y-%m-%d %H:%M:%S'),
        "target_dir": target_dir,
        "backup_dir": backup_dir,
        "moves": [],   # [{"from": abs, "to": abs}]
        "renames": [],  # [{"from": abs, "to": abs}]
        "status": "in_progress",
    }
    log_path = os.path.join(backup_dir, "_cleanup_log.json")

    # --- Phase A: 移動重複檔案 ---
    print(f"\n[1/2] Moving duplicates to backup...")
    os.makedirs(backup_dir, exist_ok=True)

    moved = 0
    skipped = 0
    total_size = 0
    move_errors = []

    for rel_path in files_to_delete:
        src = os.path.join(target_dir, rel_path)

        if not os.path.exists(src):
            skipped += 1
            continue

        # 保留來源目錄結構
        dest = os.path.join(backup_dir, rel_path)
        dest_dir = os.path.dirname(dest)
        os.makedirs(dest_dir, exist_ok=True)

        # 處理同名衝突
        if os.path.exists(dest):
            stem = Path(dest).stem
            suffix = Path(dest).suffix
            counter = 1
            while os.path.exists(dest):
                dest = os.path.join(
                    dest_dir, f"{stem}_dup{counter}{suffix}"
                )
                counter += 1

        try:
            file_size = os.path.getsize(src)
            shutil.move(src, dest)
            moved += 1
            total_size += file_size
            transaction_log["moves"].append({"from": src, "to": dest})

            if moved % 500 == 0:
                print(f"  Moved {moved} files...")
                # 中途儲存 log
                _save_log(log_path, transaction_log)

        except Exception as e:
            move_errors.append((rel_path, str(e)))

    print(f"  Done: moved {moved}, skipped {skipped}, errors {len(move_errors)}")
    print(f"  Space freed: {format_size(total_size)}")

    # 儲存 Phase A log
    transaction_log["status"] = "moves_complete"
    _save_log(log_path, transaction_log)

    # --- Phase B: 改名保留檔案 ---
    if rename_list:
        print(f"\n[2/2] Renaming kept files...")
        renamed = 0
        rename_skipped = 0
        rename_errors = []

        for old_rel, new_rel, old_name, new_name in rename_list:
            old_abs = os.path.join(target_dir, old_rel)
            new_abs = os.path.join(target_dir, new_rel)

            if not os.path.exists(old_abs):
                rename_skipped += 1
                continue

            if os.path.exists(new_abs):
                rename_skipped += 1
                continue

            try:
                os.rename(old_abs, new_abs)
                renamed += 1
                transaction_log["renames"].append({
                    "from": old_abs,
                    "to": new_abs,
                })
            except Exception as e:
                rename_errors.append((old_name, new_name, str(e)))

        print(
            f"  Done: renamed {renamed}, "
            f"skipped {rename_skipped}, "
            f"errors {len(rename_errors)}"
        )

        if rename_errors:
            print(f"\n  Rename errors:")
            for old, new, err in rename_errors[:5]:
                print(f"    {old} → {new}: {err}")

    # --- 完成 ---
    transaction_log["status"] = "complete"
    _save_log(log_path, transaction_log)

    print()
    print("=" * 50)
    print("ALL DONE!")
    print(f"  Moved:   {moved} files ({format_size(total_size)})")
    if rename_list:
        print(f"  Renamed: {renamed} files")
    print(f"  Backup:  {backup_dir}")
    print(f"  Log:     {log_path}")
    print()
    print("To undo: python clean.py --dir <DIR> --undo")
    print("To permanently delete: remove the backup folder")

    if move_errors:
        print(f"\nMove errors ({len(move_errors)}):")
        for fp, err in move_errors[:5]:
            print(f"  {fp}: {err}")


def undo(target_dir: str, backup_dir: str | None = None):
    """
    回滾清理操作：
      1. 還原改名 (逆序)
      2. 還原移動 (逆序)
    """
    sys.stdout.reconfigure(line_buffering=True)

    target_dir = os.path.abspath(target_dir)

    if backup_dir is None:
        backup_dir = os.path.join(target_dir, "_duplicates_backup")
    else:
        backup_dir = os.path.abspath(backup_dir)

    log_path = os.path.join(backup_dir, "_cleanup_log.json")

    if not os.path.isfile(log_path):
        print(f"❌ Transaction log not found: {log_path}")
        print("   Cannot undo without a log file.")
        sys.exit(1)

    with open(log_path, 'r', encoding='utf-8') as f:
        log = json.load(f)

    renames = log.get("renames", [])
    moves = log.get("moves", [])

    print("=" * 50)
    print("Photo Dedup — Undo")
    print("=" * 50)
    print(f"  Renames to revert: {len(renames)}")
    print(f"  Moves to revert:   {len(moves)}")
    print()

    answer = input("Proceed with undo? (y/N) ").strip().lower()
    if answer != 'y':
        print("Cancelled.")
        return

    # 1. 還原改名 (逆序)
    if renames:
        print("\n[1/2] Reverting renames...")
        reverted = 0
        for entry in reversed(renames):
            src = entry["to"]   # 現在的位置
            dst = entry["from"]  # 原始位置
            if os.path.exists(src) and not os.path.exists(dst):
                try:
                    os.rename(src, dst)
                    reverted += 1
                except Exception as e:
                    print(f"  [ERROR] {src}: {e}")
        print(f"  Reverted {reverted} renames")

    # 2. 還原移動 (逆序)
    if moves:
        print("\n[2/2] Restoring moved files...")
        restored = 0
        for entry in reversed(moves):
            src = entry["to"]   # 備份位置
            dst = entry["from"]  # 原始位置
            if os.path.exists(src):
                try:
                    dst_dir = os.path.dirname(dst)
                    os.makedirs(dst_dir, exist_ok=True)
                    shutil.move(src, dst)
                    restored += 1
                except Exception as e:
                    print(f"  [ERROR] {src}: {e}")

            if restored % 500 == 0 and restored > 0:
                print(f"  Restored {restored} files...")

        print(f"  Restored {restored} files")

    # 更新 log
    log["status"] = "undone"
    log["undo_time"] = time.strftime('%Y-%m-%d %H:%M:%S')
    _save_log(log_path, log)

    print()
    print("Undo complete!")


def _save_log(log_path: str, log: dict):
    """儲存 transaction log"""
    with open(log_path, 'w', encoding='utf-8') as f:
        json.dump(log, f, ensure_ascii=False, indent=2)
