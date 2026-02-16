"""
清理模組 — 安全刪除重複檔案 + 改名保留檔

流程：
  1. 讀取 JSON 結構化報告 (duplicates_data.json)
  2. 驗證路徑安全性（防止路徑逸出）
  3. 比對報告的 target_dir 與當前 --dir
  4. 為每組選出最可讀的檔名
  5. 將重複檔案移到備份資料夾 (保留原始目錄結構)
  6. 將保留的檔案改名為最可讀的名稱
  7. 每次操作後即寫入 transaction log 供回滾使用

安全措施：
  - 路徑逸出防護（不接受 .. 或絕對路徑）
  - target_dir 一致性校驗
  - 備份保留來源目錄結構
  - 逐筆寫入 transaction log
  - --dry-run 不建立任何目錄
  - --yes 非互動模式
"""

import json
import os
import shutil
import sys
import time
from pathlib import Path

from .exceptions import (
    DirectoryMismatchError,
    DirectoryNotFoundError,
    InvalidReportError,
    PathTraversalError,
    PermissionError_,
)
from .naming import find_best_name
from .utils import VERSION, format_size


# ── 安全性 ────────────────────────────────────────


def _validate_relative_path(rel_path: str, target_dir: str) -> str:
    """
    驗證相對路徑的安全性。

    檢查：
      1. 不可為絕對路徑
      2. 不可包含 ..
      3. resolve() 後必須仍在 target_dir 之下

    Returns:
        resolve 後的絕對路徑

    Raises:
        PathTraversalError: 路徑逸出目標資料夾
    """
    # 拒絕絕對路徑
    if os.path.isabs(rel_path):
        raise PathTraversalError(
            f"Absolute path in report (security violation): {rel_path}"
        )

    # 拒絕 ..
    if '..' in rel_path.replace('\\', '/').split('/'):
        raise PathTraversalError(
            f"Path traversal detected (..): {rel_path}"
        )

    # resolve 後必須在 target_dir 之下
    abs_path = os.path.normpath(os.path.join(target_dir, rel_path))
    target_norm = os.path.normpath(target_dir)

    if not abs_path.startswith(target_norm + os.sep) and abs_path != target_norm:
        raise PathTraversalError(
            f"Path escapes target directory: {rel_path} → {abs_path}"
        )

    return abs_path


def _validate_all_paths(groups: list[dict], target_dir: str):
    """驗證報告中所有路徑的安全性"""
    for i, g in enumerate(groups):
        try:
            _validate_relative_path(g["keep"]["path"], target_dir)
            for d in g["delete"]:
                _validate_relative_path(d["path"], target_dir)
        except PathTraversalError as e:
            raise PathTraversalError(
                f"Group #{i + 1}: {e}"
            )


def validate_clean_args(
    target_dir: str,
    json_path: str,
):
    """
    驗證清理參數。

    Raises:
        DirectoryNotFoundError: 目標資料夾不存在
        PermissionError_: 權限不足
        InvalidReportError: 報告檔不存在
    """
    if not os.path.isdir(target_dir):
        raise DirectoryNotFoundError(
            f"Directory not found: {target_dir}"
        )

    if not os.access(target_dir, os.W_OK):
        raise PermissionError_(
            f"No write permission: {target_dir}"
        )

    if not os.path.isfile(json_path):
        raise InvalidReportError(
            f"JSON report not found: {json_path}\n"
            f"Run scan.py first to generate the report."
        )


def validate_dir_match(
    report_data: dict,
    target_dir: str,
    force: bool = False,
):
    """
    比對報告的 target_dir 與 clean 的 --dir。

    Raises:
        DirectoryMismatchError: 目錄不一致且未使用 --force
    """
    report_dir = os.path.normpath(report_data.get("target_dir", ""))
    current_dir = os.path.normpath(target_dir)

    if report_dir != current_dir:
        if force:
            print(
                f"  ⚠ Directory mismatch (--force used):\n"
                f"    Report:  {report_dir}\n"
                f"    Current: {current_dir}"
            )
        else:
            raise DirectoryMismatchError(
                f"Report was generated for:\n"
                f"    {report_dir}\n"
                f"  but --dir is:\n"
                f"    {current_dir}\n"
                f"  Use --force to override this check."
            )


# ── Transaction Log ───────────────────────────────


def _init_log(target_dir: str, backup_dir: str) -> dict:
    """建立初始 transaction log"""
    return {
        "version": VERSION,
        "time": time.strftime('%Y-%m-%d %H:%M:%S'),
        "target_dir": target_dir,
        "backup_dir": backup_dir,
        "moves": [],
        "renames": [],
        "status": "in_progress",
    }


def _append_and_save_log(log: dict, log_path: str):
    """寫入 transaction log 並 fsync"""
    with open(log_path, 'w', encoding='utf-8') as f:
        json.dump(log, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())


# ── 主流程 ────────────────────────────────────────


def load_json_report(json_path: str) -> dict:
    """
    載入 JSON 結構化報告。

    Raises:
        InvalidReportError: JSON 格式錯誤
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise InvalidReportError(f"Invalid JSON: {json_path} ({e})")

    if "groups" not in data:
        raise InvalidReportError(
            f"Invalid report format: missing 'groups' key"
        )

    return data


def clean(
    target_dir: str,
    json_path: str | None = None,
    backup_dir: str | None = None,
    do_rename: bool = True,
    dry_run: bool = False,
    auto_yes: bool = False,
    force_mismatch: bool = False,
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
        force_mismatch: 允許 target_dir 不一致 (預設 False)

    Raises:
        DirectoryNotFoundError, PermissionError_, InvalidReportError,
        PathTraversalError, DirectoryMismatchError
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

    # 驗證參數（不建立任何目錄）
    validate_clean_args(target_dir, json_path)

    # 載入 JSON 報告
    print("Loading JSON report...")
    report_data = load_json_report(json_path)
    groups = report_data["groups"]
    print(f"  {len(groups)} duplicate groups")

    # 比對 target_dir
    validate_dir_match(report_data, target_dir, force=force_mismatch)

    # 路徑安全性驗證
    print("  Validating paths...")
    _validate_all_paths(groups, target_dir)
    print("  ✓ All paths safe")

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
                new_rel = (
                    os.path.join(keep_dir, new_name) if keep_dir else new_name
                )
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

    # 正式執行：建立備份目錄和 transaction log
    os.makedirs(backup_dir, exist_ok=True)
    log = _init_log(target_dir, backup_dir)
    log_path = os.path.join(backup_dir, "_cleanup_log.json")
    _append_and_save_log(log, log_path)  # 開始前先落盤

    # --- Phase A: 移動重複檔案 ---
    print(f"\n[1/2] Moving duplicates to backup...")

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

            # 逐筆記錄 + 寫入 log
            log["moves"].append({"from": src, "to": dest})
            _append_and_save_log(log, log_path)

            if moved % 500 == 0:
                print(f"  Moved {moved} files...")

        except Exception as e:
            move_errors.append((rel_path, str(e)))

    print(
        f"  Done: moved {moved}, "
        f"skipped {skipped}, "
        f"errors {len(move_errors)}"
    )
    print(f"  Space freed: {format_size(total_size)}")

    # 更新 Phase A 狀態
    log["status"] = "moves_complete"
    _append_and_save_log(log, log_path)

    # --- Phase B: 改名保留檔案 ---
    renamed = 0
    if rename_list:
        print(f"\n[2/2] Renaming kept files...")
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

                # 逐筆記錄 + 寫入 log
                log["renames"].append({"from": old_abs, "to": new_abs})
                _append_and_save_log(log, log_path)

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
    log["status"] = "complete"
    _append_and_save_log(log, log_path)

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

    Raises:
        InvalidReportError: 找不到 transaction log
    """
    sys.stdout.reconfigure(line_buffering=True)

    target_dir = os.path.abspath(target_dir)

    if backup_dir is None:
        backup_dir = os.path.join(target_dir, "_duplicates_backup")
    else:
        backup_dir = os.path.abspath(backup_dir)

    log_path = os.path.join(backup_dir, "_cleanup_log.json")

    if not os.path.isfile(log_path):
        raise InvalidReportError(
            f"Transaction log not found: {log_path}\n"
            f"Cannot undo without a log file."
        )

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
            src = entry["to"]
            dst = entry["from"]
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
            src = entry["to"]
            dst = entry["from"]
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
    _append_and_save_log(log, log_path)

    print()
    print("Undo complete!")
