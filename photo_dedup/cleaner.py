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
import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .exceptions import (
    AccessDeniedError,
    DirectoryMismatchError,
    DirectoryNotFoundError,
    InvalidReportError,
    PathTraversalError,
)
from .naming import find_best_name
from .utils import VERSION, format_size

logger = logging.getLogger(__name__)


# Transaction log filenames
LOG_META_FILENAME = "_cleanup_log.json"
LOG_EVENTS_FILENAME = "_cleanup_log.events.jsonl"
LOG_FSYNC_INTERVAL = 50


# ── 安全性 ────────────────────────────────────────


def _normalize_abs(path: str) -> str:
    """回傳標準化絕對路徑（解析符號連結 + Windows 大小寫正規化）"""
    return os.path.normcase(os.path.realpath(path))


def _is_within_root(path: str, root: str) -> bool:
    """檢查 path 是否位於 root 之下（含 root 本身）"""
    path_norm = _normalize_abs(path)
    root_norm = _normalize_abs(root)
    try:
        return os.path.commonpath([path_norm, root_norm]) == root_norm
    except ValueError:
        # 例如不同磁碟機 C: / D:
        return False


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
    if not isinstance(rel_path, str) or rel_path.strip() == "":
        raise PathTraversalError(
            "Empty path in report (security violation)"
        )

    normalized_rel = rel_path.replace("\\", "/").strip()

    # 拒絕相對路徑的目錄本身
    if normalized_rel in {".", "./"}:
        raise PathTraversalError(
            f"Path points to target directory itself: {rel_path}"
        )

    # Windows: 拒絕 drive-relative 路徑，例如 C:file.txt / D:foo\bar
    first_part = normalized_rel.split("/", 1)[0]
    if len(first_part) >= 2 and first_part[1] == ":":
        raise PathTraversalError(
            f"Drive-relative path is not allowed: {rel_path}"
        )

    # 拒絕絕對路徑
    if os.path.isabs(rel_path):
        raise PathTraversalError(
            f"Absolute path in report (security violation): {rel_path}"
        )

    # 拒絕 ..
    if '..' in normalized_rel.split('/'):
        raise PathTraversalError(
            f"Path traversal detected (..): {rel_path}"
        )

    # resolve 後必須在 target_dir 之下
    abs_path = os.path.abspath(os.path.join(target_dir, rel_path))
    if not _is_within_root(abs_path, target_dir):
        raise PathTraversalError(
            f"Path escapes target directory: {rel_path} => {abs_path}"
        )

    if _normalize_abs(abs_path) == _normalize_abs(target_dir):
        raise PathTraversalError(
            f"Path points to target directory itself: {rel_path}"
        )

    return abs_path


def _validate_all_paths(groups: list[dict], target_dir: str):
    """驗證報告中所有路徑的安全性"""
    if not isinstance(groups, list):
        raise InvalidReportError("Invalid report format: 'groups' must be a list")

    seen_abs_paths: set[str] = set()

    for i, g in enumerate(groups):
        try:
            keep_obj = g["keep"]
            delete_list = g["delete"]
            keep_path = keep_obj["path"]
            if not isinstance(delete_list, list):
                raise InvalidReportError(
                    f"Invalid report format in group #{i + 1}: 'delete' must be a list"
                )

            keep_abs = _normalize_abs(
                _validate_relative_path(keep_path, target_dir)
            )
            if keep_abs in seen_abs_paths:
                raise InvalidReportError(
                    f"Duplicate path in report (group #{i + 1} keep): {keep_path}"
                )
            seen_abs_paths.add(keep_abs)

            group_abs_paths = {keep_abs}
            for d in delete_list:
                delete_path = d["path"]
                delete_abs = _normalize_abs(
                    _validate_relative_path(delete_path, target_dir)
                )
                if delete_abs == keep_abs:
                    raise InvalidReportError(
                        f"Invalid report in group #{i + 1}: "
                        f"keep and delete refer to the same path: {delete_path}"
                    )
                if delete_abs in group_abs_paths:
                    raise InvalidReportError(
                        f"Duplicate path in report (group #{i + 1}): {delete_path}"
                    )
                if delete_abs in seen_abs_paths:
                    raise InvalidReportError(
                        f"Duplicate path in report (group #{i + 1} delete): {delete_path}"
                    )
                group_abs_paths.add(delete_abs)
                seen_abs_paths.add(delete_abs)
        except (KeyError, TypeError):
            raise InvalidReportError(
                f"Invalid report format in group #{i + 1}: missing keep/delete path"
            )
        except PathTraversalError as e:
            raise PathTraversalError(
                f"Group #{i + 1}: {e}"
            )


def validate_clean_args(
    target_dir: str,
    json_path: str,
    require_write: bool = True,
):
    """
    驗證清理參數。

    Raises:
        DirectoryNotFoundError: 目標資料夾不存在
        AccessDeniedError: 權限不足
        InvalidReportError: 報告檔不存在
    """
    if not os.path.isdir(target_dir):
        raise DirectoryNotFoundError(
            f"Directory not found: {target_dir}"
        )

    if require_write and not os.access(target_dir, os.W_OK):
        raise AccessDeniedError(
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
    report_dir = _normalize_abs(report_data.get("target_dir", ""))
    current_dir = _normalize_abs(target_dir)

    if report_dir != current_dir:
        if force:
            logger.warning(
                "Directory mismatch (--force used):\n"
                "    Report:  %s\n"
                "    Current: %s",
                report_dir,
                current_dir,
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
        "time": datetime.now(timezone.utc).isoformat(),
        "target_dir": target_dir,
        "backup_dir": backup_dir,
        "events_file": LOG_EVENTS_FILENAME,
        "move_count": 0,
        "rename_count": 0,
        "status": "in_progress",
    }


def _save_log_meta(log: dict, log_path: str):
    """寫入 transaction meta（小檔案，可接受全量覆寫）"""
    with open(log_path, 'w', encoding='utf-8') as f:
        json.dump(log, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())


def _append_event(log_fp, event: dict, pending_ops: int) -> int:
    """
    追寫單筆 event 到 JSONL。
    只在每 LOG_FSYNC_INTERVAL 筆做一次 fsync，避免大量小檔案 sync 拖慢速度。
    """
    log_fp.write(json.dumps(event, ensure_ascii=False) + "\n")
    pending_ops += 1
    if pending_ops >= LOG_FSYNC_INTERVAL:
        log_fp.flush()
        os.fsync(log_fp.fileno())
        pending_ops = 0
    return pending_ops


def _finalize_event_log(log_fp):
    """收尾：確保 event log 完整落盤"""
    log_fp.flush()
    os.fsync(log_fp.fileno())


def _load_undo_entries(log: dict, backup_dir: str) -> tuple[list[dict], list[dict]]:
    """
    讀取 undo 需要的 renames / moves。
    優先讀取 JSONL events；若不存在則回退到舊版 log 欄位。
    """
    events_file = log.get("events_file", LOG_EVENTS_FILENAME)
    events_path = os.path.join(backup_dir, events_file)

    if not os.path.isfile(events_path):
        return log.get("renames", []), log.get("moves", [])

    renames = []
    moves = []

    with open(events_path, 'r', encoding='utf-8') as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as e:
                raise InvalidReportError(
                    f"Invalid event log at line {lineno}: {e}"
                )

            event_type = event.get("type")
            from_val = event.get("from")
            to_val = event.get("to")

            # 型別驗證：防止被竄改的 JSONL 注入非字串值
            if not isinstance(from_val, str) or not isinstance(to_val, str):
                raise InvalidReportError(
                    f"Invalid event log at line {lineno}: "
                    f"'from' and 'to' must be strings"
                )

            entry = {"from": from_val, "to": to_val}
            if event_type == "rename":
                renames.append(entry)
            elif event_type == "move":
                moves.append(entry)
            else:
                raise InvalidReportError(
                    f"Invalid event type at line {lineno}: {event_type}"
                )

    return renames, moves


def _validate_undo_entries(
    renames: list[dict],
    moves: list[dict],
    target_dir: str,
    backup_dir: str,
):
    """驗證 undo entries 是否限制在 target/backup 目錄範圍內"""
    for i, entry in enumerate(renames, 1):
        src = entry.get("to")
        dst = entry.get("from")
        if not src or not dst:
            raise InvalidReportError(f"Invalid rename entry #{i}: missing path")
        if not _is_within_root(src, target_dir) or not _is_within_root(dst, target_dir):
            raise PathTraversalError(
                f"Rename entry #{i} escapes target_dir: {src} -> {dst}"
            )

    for i, entry in enumerate(moves, 1):
        src = entry.get("to")
        dst = entry.get("from")
        if not src or not dst:
            raise InvalidReportError(f"Invalid move entry #{i}: missing path")
        if not _is_within_root(src, backup_dir) or not _is_within_root(dst, target_dir):
            raise PathTraversalError(
                f"Move entry #{i} escapes allowed roots: {src} -> {dst}"
            )


def _prune_empty_subdirs(root_dir: str):
    """刪除 root_dir 底下的空子目錄（保留 root_dir 本身）"""
    for dirpath, dirnames, _filenames in os.walk(root_dir, topdown=False):
        if os.path.abspath(dirpath) == os.path.abspath(root_dir):
            continue
        if not dirnames and not os.listdir(dirpath):
            try:
                os.rmdir(dirpath)
            except OSError:
                # 目錄可能在 race condition 中被重新建立或不可刪，忽略即可
                pass


def _make_temp_rename_path(original_path: str) -> str:
    """建立同目錄下的暫存改名路徑，避免 rename 衝突。"""
    directory = os.path.dirname(original_path)
    basename = os.path.basename(original_path)

    # 理論上碰撞機率極低，仍保留重試保護
    for _ in range(20):
        candidate = os.path.join(
            directory,
            f".__photo_dedup_tmp_{uuid.uuid4().hex}_{basename}",
        )
        if not os.path.exists(candidate):
            return candidate

    raise OSError(f"Cannot allocate temporary rename path for: {original_path}")


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
    except OSError as e:
        raise InvalidReportError(f"Cannot read JSON report: {json_path} ({e})")

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
        DirectoryNotFoundError, AccessDeniedError, InvalidReportError,
        PathTraversalError, DirectoryMismatchError
    """
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
    validate_clean_args(target_dir, json_path, require_write=not dry_run)

    # 載入 JSON 報告
    logger.info("Loading JSON report...")
    report_data = load_json_report(json_path)
    groups = report_data["groups"]
    logger.info("  %d duplicate groups", len(groups))

    # 比對 target_dir
    validate_dir_match(report_data, target_dir, force=force_mismatch)

    # 路徑安全性驗證
    logger.info("  Validating paths...")
    _validate_all_paths(groups, target_dir)
    logger.info("  [OK] All paths safe")

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
        logger.info("  Files to rename: %d", len(rename_list))

    # 建立待刪清單 (相對路徑)
    files_to_delete = []
    for g in groups:
        for d in g["delete"]:
            files_to_delete.append(d["path"])

    # 顯示改名範例
    if rename_list:
        logger.info("")
        logger.info("Rename examples (first 10):")
        for _, _, old_n, new_n in rename_list[:10]:
            logger.info("  %s", old_n)
            logger.info("    -> %s", new_n)
        if len(rename_list) > 10:
            logger.info("  ... and %d more", len(rename_list) - 10)

    logger.info("")
    logger.info("=" * 50)
    logger.info("Operation Summary")
    logger.info("=" * 50)
    logger.info("  Move to backup:  %d files", len(files_to_delete))
    logger.info("  Rename kept:     %d files", len(rename_list))
    logger.info("  Backup dir:      %s", backup_dir)
    if dry_run:
        logger.info("  *** DRY RUN -- no changes will be made ***")
    logger.info("")

    if dry_run:
        logger.info("Dry run complete. No files were modified.")
        return

    if not auto_yes:
        answer = input("Proceed? (y/N) ").strip().lower()
        if answer != 'y':
            print("Cancelled.")
            return

    # 檢查是否已有未完成的 event log，防止覆蓋
    os.makedirs(backup_dir, exist_ok=True)
    log_path = os.path.join(backup_dir, LOG_META_FILENAME)
    events_path = os.path.join(backup_dir, LOG_EVENTS_FILENAME)

    if os.path.isfile(log_path):
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                existing_log = json.load(f)
            existing_status = existing_log.get("status", "")
            if existing_status not in ("complete", "undone"):
                raise InvalidReportError(
                    f"An incomplete cleanup log exists (status={existing_status}).\n"
                    f"Run --undo first, or delete {backup_dir} to start fresh."
                )
        except (json.JSONDecodeError, KeyError):
            pass  # 損壞的 log，允許覆蓋

    # 正式執行：建立 transaction log
    log = _init_log(target_dir, backup_dir)
    _save_log_meta(log, log_path)  # 開始前先落盤
    pending_ops = 0
    with open(events_path, 'w', encoding='utf-8') as events_fp:
        # --- Phase A: 移動重複檔案 ---
        logger.info("[1/2] Moving duplicates to backup...")

        moved = 0
        skipped = 0
        total_size = 0
        move_errors = []

        for rel_path in files_to_delete:
            src = os.path.join(target_dir, rel_path)

            if not os.path.exists(src):
                skipped += 1
                continue

            if not os.path.isfile(src):
                skipped += 1
                move_errors.append((rel_path, "not a file"))
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

                # 追寫 event（O(1)），週期性 fsync
                pending_ops = _append_event(
                    events_fp,
                    {"type": "move", "from": src, "to": dest},
                    pending_ops,
                )
                log["move_count"] += 1

                if moved % 500 == 0:
                    logger.info("  Moved %d files...", moved)

            except Exception as e:
                move_errors.append((rel_path, str(e)))

        logger.info(
            "  Done: moved %d, skipped %d, errors %d",
            moved, skipped, len(move_errors),
        )
        logger.info("  Space freed: %s", format_size(total_size))

        _finalize_event_log(events_fp)
        # 更新 Phase A 狀態
        log["status"] = "moves_complete"
        _save_log_meta(log, log_path)

        # --- Phase B: 改名保留檔案 ---
        renamed = 0
        if rename_list:
            logger.info("[2/2] Renaming kept files...")
            rename_skipped = 0
            rename_errors = []
            raw_candidates = []
            for old_rel, new_rel, old_name, new_name in rename_list:
                old_abs = os.path.join(target_dir, old_rel)
                new_abs = os.path.join(target_dir, new_rel)
                if not os.path.exists(old_abs):
                    rename_skipped += 1
                    continue
                raw_candidates.append(
                    {
                        "old_abs": old_abs,
                        "new_abs": new_abs,
                        "old_name": old_name,
                        "new_name": new_name,
                    }
                )

            # 允許目標路徑目前存在於「其他待改名來源」中，稍後透過暫存名騰挪。
            source_paths = {
                _normalize_abs(c["old_abs"]) for c in raw_candidates
            }
            executable = []
            for c in raw_candidates:
                new_norm = _normalize_abs(c["new_abs"])
                if os.path.exists(c["new_abs"]) and new_norm not in source_paths:
                    rename_skipped += 1
                    logger.warning(
                        "Rename target already exists, skipped: %s -> %s",
                        c["old_name"], c["new_name"],
                    )
                    continue
                executable.append(c)

            # Phase 1: old -> temp（先騰空所有來源，解開鏈式衝突）
            staged = []
            for c in executable:
                try:
                    temp_abs = _make_temp_rename_path(c["old_abs"])
                    os.rename(c["old_abs"], temp_abs)
                    c["temp_abs"] = temp_abs
                    staged.append(c)
                except Exception as e:
                    rename_errors.append(
                        (c["old_name"], c["new_name"], f"stage failed: {e}")
                    )

            # Phase 2: temp -> final
            for c in staged:
                old_abs = c["old_abs"]
                new_abs = c["new_abs"]
                temp_abs = c["temp_abs"]

                if os.path.exists(new_abs):
                    # 目標仍被占用（常見於其來源未成功 stage），回滾本檔
                    try:
                        os.rename(temp_abs, old_abs)
                    except Exception as rollback_err:
                        rename_errors.append(
                            (
                                c["old_name"],
                                c["new_name"],
                                f"target exists; rollback failed: {rollback_err}",
                            )
                        )
                    else:
                        rename_skipped += 1
                        logger.warning(
                            "Rename target still exists, skipped: %s -> %s",
                            c["old_name"], c["new_name"],
                        )
                    continue

                try:
                    os.rename(temp_abs, new_abs)
                    renamed += 1

                    pending_ops = _append_event(
                        events_fp,
                        {"type": "rename", "from": old_abs, "to": new_abs},
                        pending_ops,
                    )
                    log["rename_count"] += 1

                except Exception as e:
                    # 失敗時盡量把 temp 還原回 old，避免遺留暫存檔
                    try:
                        os.rename(temp_abs, old_abs)
                    except Exception as rollback_err:
                        rename_errors.append(
                            (
                                c["old_name"],
                                c["new_name"],
                                f"{e}; rollback failed: {rollback_err}",
                            )
                        )
                    else:
                        rename_errors.append((c["old_name"], c["new_name"], str(e)))

            logger.info(
                "  Done: renamed %d, skipped %d, errors %d",
                renamed, rename_skipped, len(rename_errors),
            )

            if rename_errors:
                logger.error("Rename errors:")
                for old, new, err in rename_errors[:5]:
                    logger.error("  %s -> %s: %s", old, new, err)

        # --- 完成 ---
        _finalize_event_log(events_fp)
        log["status"] = "complete"
        _save_log_meta(log, log_path)

    logger.info("")
    logger.info("=" * 50)
    logger.info("ALL DONE!")
    logger.info("  Moved:   %d files (%s)", moved, format_size(total_size))
    if rename_list:
        logger.info("  Renamed: %d files", renamed)
    logger.info("  Backup:  %s", backup_dir)
    logger.info("  Log:     %s", log_path)
    logger.info("")
    logger.info("To undo: python clean.py --dir <DIR> --undo")
    logger.info("To permanently delete: remove the backup folder")

    if move_errors:
        logger.error("Move errors (%d):", len(move_errors))
        for fp, err in move_errors[:5]:
            logger.error("  %s: %s", fp, err)


def undo(
    target_dir: str,
    backup_dir: str | None = None,
    auto_yes: bool = False,
):
    """
    回滾清理操作：
      1. 還原改名 (逆序)
      2. 還原移動 (逆序)

    Raises:
        InvalidReportError: 找不到或無法解析 transaction log
        PathTraversalError: log 內路徑逸出安全範圍
    """

    target_dir = os.path.abspath(target_dir)

    if backup_dir is None:
        backup_dir = os.path.join(target_dir, "_duplicates_backup")
    else:
        backup_dir = os.path.abspath(backup_dir)

    log_path = os.path.join(backup_dir, LOG_META_FILENAME)

    if not os.path.isfile(log_path):
        raise InvalidReportError(
            f"Transaction log not found: {log_path}\n"
            f"Cannot undo without a log file."
        )

    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            log = json.load(f)
    except json.JSONDecodeError as e:
        raise InvalidReportError(
            f"Invalid transaction log: {log_path} ({e})"
        )
    except OSError as e:
        raise InvalidReportError(
            f"Cannot read transaction log: {log_path} ({e})"
        )

    renames, moves = _load_undo_entries(log, backup_dir)
    _validate_undo_entries(renames, moves, target_dir, backup_dir)

    print("="* 50)
    print("Photo Dedup - Undo")
    print("=" * 50)
    print(f"  Renames to revert: {len(renames)}")
    print(f"  Moves to revert:   {len(moves)}")
    print()

    if not auto_yes:
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

    # 清理還原後殘留的空備份子目錄
    _prune_empty_subdirs(backup_dir)

    # 更新 log
    log["status"] = "undone"
    log["undo_time"] = datetime.now(timezone.utc).isoformat()
    _save_log_meta(log, log_path)

    print()
    print("Undo complete!")
