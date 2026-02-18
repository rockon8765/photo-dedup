"""
自動化測試 — 核心功能回歸保護

測試類別：
  1. 路徑安全性 (path traversal)
  2. 檔名可讀性與改名策略
  3. 掃描 + 清理 + 回滾端到端流程
  4. Hasher 行為
  5. 工具函式
"""

import builtins
import json
import logging
import os
import tempfile
from unittest.mock import patch

import pytest

from photo_dedup.cleaner import (
    _validate_relative_path,
    clean,
    load_json_report,
    undo,
    validate_dir_match,
)
from photo_dedup.exceptions import (
    AccessDeniedError,
    DirectoryMismatchError,
    InvalidReportError,
    PathTraversalError,
)
from photo_dedup.hasher import IMAGE_EXTENSIONS, init_heic_support
from photo_dedup.naming import find_best_name, readability_score
from photo_dedup.scanner import FileEntry, build_groups, collect_files, scan
from photo_dedup.utils import format_size


# ── 路徑安全性 ──────────────────────────────────


class TestPathSafety:
    """路徑安全性測試"""

    def test_reject_absolute_path(self, tmp_path):
        """絕對路徑應被拒絕"""
        with pytest.raises(PathTraversalError):
            _validate_relative_path("/etc/passwd", str(tmp_path))

    def test_reject_windows_absolute_path(self, tmp_path):
        """Windows 絕對路徑應被拒絕"""
        with pytest.raises(PathTraversalError):
            _validate_relative_path("C:\\Windows\\System32", str(tmp_path))

    def test_reject_dotdot(self, tmp_path):
        """.. 路徑應被拒絕"""
        with pytest.raises(PathTraversalError):
            _validate_relative_path("../../../etc/passwd", str(tmp_path))

    def test_reject_hidden_dotdot(self, tmp_path):
        """隱藏在子目錄中的 .. 應被拒絕"""
        with pytest.raises(PathTraversalError):
            _validate_relative_path("subdir/../../secret.txt", str(tmp_path))

    def test_reject_drive_relative_path(self, tmp_path):
        """Windows drive-relative path 應被拒絕"""
        with pytest.raises(PathTraversalError):
            _validate_relative_path("D:subdir\\file.jpg", str(tmp_path))

    def test_accept_normal_path(self, tmp_path):
        """正常的相對路徑應被接受"""
        result = _validate_relative_path("photo.jpg", str(tmp_path))
        expected = os.path.normpath(os.path.join(str(tmp_path), "photo.jpg"))
        assert result == expected

    def test_accept_nested_path(self, tmp_path):
        """子目錄中的正常路徑應被接受"""
        result = _validate_relative_path("2021/01/photo.jpg", str(tmp_path))
        assert "2021" in result

    def test_reject_empty_path(self, tmp_path):
        """空路徑應被拒絕"""
        with pytest.raises(PathTraversalError):
            _validate_relative_path("", str(tmp_path))

    def test_reject_current_dir_path(self, tmp_path):
        """指向目標資料夾本身的路徑應被拒絕"""
        with pytest.raises(PathTraversalError):
            _validate_relative_path(".", str(tmp_path))

    def test_reject_symlink_escape_path(self, tmp_path):
        """符號連結若導向目標外部，應視為路徑逸出"""
        outside_dir = tempfile.mkdtemp(prefix="photo_dedup_outside_")
        outside_file = os.path.join(outside_dir, "secret.txt")
        with open(outside_file, "w", encoding="utf-8") as f:
            f.write("secret")

        symlink_path = tmp_path / "link_out"
        try:
            os.symlink(outside_dir, symlink_path, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("Symlink is not supported in this environment")

        with pytest.raises(PathTraversalError):
            _validate_relative_path("link_out/secret.txt", str(tmp_path))


# ── 檔名可讀性 ──────────────────────────────────


class TestNaming:
    """檔名可讀性與改名策略測試"""

    def test_date_beats_timestamp(self):
        """日期格式應優於 Unix 時間戳"""
        assert readability_score("20210103_081230.jpg") > readability_score(
            "1609753382985.jpeg"
        )

    def test_copy_suffix_penalized(self):
        """(1) (2) 副本標記應被扣分"""
        assert readability_score("photo.jpg") > readability_score("photo (2).jpg")

    def test_camera_prefix_bonus(self):
        """IMG_ DSC_ 等前綴應加分"""
        assert readability_score("IMG_20210103.jpg") > readability_score("12345.jpg")

    def test_find_best_name_keeps_extension(self):
        """改名應保留 keep 檔的原始副檔名"""
        new_name, should = find_best_name(
            "1609753382985.png",
            ["20210103_081230.jpg"],
        )
        assert new_name == "20210103_081230.png"
        assert should is True

    def test_find_best_name_no_rename_needed(self):
        """已經是最佳名稱時不應改名"""
        new_name, should = find_best_name(
            "20210103_081230.jpg",
            ["1609753382985.jpeg"],
        )
        assert new_name == "20210103_081230.jpg"
        assert should is False

    def test_find_best_name_removes_copy_suffix(self):
        """應移除 (1) (2) 副本標記"""
        new_name, should = find_best_name(
            "photo (2).jpg",
            ["photo.jpg"],
        )
        assert new_name == "photo.jpg"
        assert should is True

    def test_cross_extension_preserves_keep_ext(self):
        """跨副檔名組應保留 keep 檔的副檔名"""
        new_name, should = find_best_name(
            "timestamp.heic",
            ["20210103_081230.jpg"],
        )
        assert new_name == "20210103_081230.heic"
        assert should is True


# ── 端到端流程 ──────────────────────────────────


class TestEndToEnd:
    """端到端流程測試"""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path):
        self.test_dir = str(tmp_path)
        self._write_file("a.txt", "hello world")
        self._write_file("b.txt", "hello world")
        self._write_file("c.txt", "different content")

    def _write_file(self, name: str, content: str) -> None:
        path = os.path.join(self.test_dir, name)
        with open(path, "w") as f:
            f.write(content)

    def test_invalid_report_raises(self):
        """無效的 JSON 報告應拋出 InvalidReportError"""
        bad_json = os.path.join(self.test_dir, "bad.json")
        with open(bad_json, "w") as f:
            f.write("not json")

        with pytest.raises(InvalidReportError):
            load_json_report(bad_json)

    def test_invalid_group_schema_raises(self):
        """groups schema 錯誤應拋出 InvalidReportError（非 KeyError）"""
        json_path = os.path.join(self.test_dir, "duplicates_data.json")
        bad_report = {
            "version": "1.3.0",
            "scan_time": "2026-01-01",
            "target_dir": self.test_dir,
            "settings": {},
            "summary": {},
            "groups": [{"hash": "x", "keep": {}, "delete": [{}]}],
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(bad_report, f)

        with pytest.raises(InvalidReportError):
            clean(
                target_dir=self.test_dir,
                json_path=json_path,
                dry_run=True,
            )

    def test_clean_rejects_duplicate_paths_across_groups(self):
        """同一路徑若在多個 group 重複出現應被拒絕"""
        json_path = os.path.join(self.test_dir, "duplicates_data.json")
        report = {
            "version": "1.3.0",
            "scan_time": "2026-01-01",
            "target_dir": self.test_dir,
            "settings": {},
            "summary": {},
            "groups": [
                {
                    "hash": "g1",
                    "keep": {"path": "a.txt", "size": 11},
                    "delete": [{"path": "b.txt", "size": 11}],
                },
                {
                    "hash": "g2",
                    "keep": {"path": "a.txt", "size": 11},
                    "delete": [{"path": "c.txt", "size": 11}],
                },
            ],
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f)

        with pytest.raises(InvalidReportError, match="Duplicate path in report"):
            clean(
                target_dir=self.test_dir,
                json_path=json_path,
                dry_run=True,
            )

    def test_clean_rejects_same_keep_and_delete_in_group(self):
        """同一 group 的 keep/delete 若是同一路徑應被拒絕"""
        json_path = os.path.join(self.test_dir, "duplicates_data.json")
        report = {
            "version": "1.3.0",
            "scan_time": "2026-01-01",
            "target_dir": self.test_dir,
            "settings": {},
            "summary": {},
            "groups": [
                {
                    "hash": "g1",
                    "keep": {"path": "a.txt", "size": 11},
                    "delete": [{"path": "a.txt", "size": 11}],
                },
            ],
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f)

        with pytest.raises(InvalidReportError, match="same path"):
            clean(
                target_dir=self.test_dir,
                json_path=json_path,
                dry_run=True,
            )

    def test_dir_mismatch_raises(self):
        """target_dir 不一致應拋出 DirectoryMismatchError"""
        report_data = {"target_dir": "/some/other/path"}
        with pytest.raises(DirectoryMismatchError):
            validate_dir_match(report_data, self.test_dir, force=False)

    def test_dir_mismatch_force_passes(self):
        """--force 應允許 target_dir 不一致"""
        report_data = {"target_dir": "/some/other/path"}
        validate_dir_match(report_data, self.test_dir, force=True)

    def test_clean_dry_run_no_side_effects(self):
        """dry-run 不應建立任何新檔案或目錄"""
        json_path = os.path.join(self.test_dir, "duplicates_data.json")
        report = {
            "version": "1.3.0",
            "scan_time": "2026-01-01",
            "target_dir": self.test_dir,
            "settings": {},
            "summary": {},
            "groups": [
                {
                    "hash": "abc",
                    "keep": {"path": "a.txt", "size": 11},
                    "delete": [{"path": "b.txt", "size": 11}],
                }
            ],
        }
        with open(json_path, "w") as f:
            json.dump(report, f)

        backup_dir = os.path.join(self.test_dir, "_duplicates_backup")

        clean(
            target_dir=self.test_dir,
            json_path=json_path,
            backup_dir=backup_dir,
            dry_run=True,
        )

        assert not os.path.exists(backup_dir)
        assert os.path.exists(os.path.join(self.test_dir, "b.txt"))

    def test_clean_dry_run_skips_write_permission_check(self, monkeypatch):
        """dry-run 應允許在目標資料夾不可寫時仍可預覽"""
        json_path = os.path.join(self.test_dir, "duplicates_data.json")
        report = {
            "version": "1.3.0",
            "scan_time": "2026-01-01",
            "target_dir": self.test_dir,
            "settings": {},
            "summary": {},
            "groups": [],
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f)

        original_access = os.access
        target_norm = os.path.normcase(os.path.abspath(self.test_dir))

        def fake_access(path, mode):
            path_norm = os.path.normcase(os.path.abspath(path))
            if path_norm == target_norm and mode == os.W_OK:
                return False
            return original_access(path, mode)

        monkeypatch.setattr("photo_dedup.cleaner.os.access", fake_access)

        clean(
            target_dir=self.test_dir,
            json_path=json_path,
            backup_dir=os.path.join(self.test_dir, "_duplicates_backup"),
            dry_run=True,
            auto_yes=True,
        )

    def test_clean_non_dry_run_still_requires_write_permission(self, monkeypatch):
        """非 dry-run 仍應要求目標資料夾可寫"""
        json_path = os.path.join(self.test_dir, "duplicates_data.json")
        report = {
            "version": "1.3.0",
            "scan_time": "2026-01-01",
            "target_dir": self.test_dir,
            "settings": {},
            "summary": {},
            "groups": [],
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f)

        original_access = os.access
        target_norm = os.path.normcase(os.path.abspath(self.test_dir))

        def fake_access(path, mode):
            path_norm = os.path.normcase(os.path.abspath(path))
            if path_norm == target_norm and mode == os.W_OK:
                return False
            return original_access(path, mode)

        monkeypatch.setattr("photo_dedup.cleaner.os.access", fake_access)

        with pytest.raises(AccessDeniedError, match="No write permission"):
            clean(
                target_dir=self.test_dir,
                json_path=json_path,
                backup_dir=os.path.join(self.test_dir, "_duplicates_backup"),
                dry_run=False,
                auto_yes=True,
            )

    def test_clean_handles_chained_rename_conflicts(self):
        """連鎖改名 (A->B, B->C, C->D) 應全部成功，不應因目標暫時存在而跳過"""
        # keep files
        keep_a = "12345678 (2).jpg"
        keep_b = "12345.jpg"
        keep_c = "IMG_1.jpg"
        self._write_file(keep_a, "content_a")
        self._write_file(keep_b, "content_b")
        self._write_file(keep_c, "content_c")

        # delete files (only used as naming candidates)
        os.makedirs(os.path.join(self.test_dir, "sub1"), exist_ok=True)
        os.makedirs(os.path.join(self.test_dir, "sub2"), exist_ok=True)
        os.makedirs(os.path.join(self.test_dir, "sub3"), exist_ok=True)
        with open(
            os.path.join(self.test_dir, "sub1", "12345.jpg"), "w", encoding="utf-8"
        ) as f:
            f.write("dup1")
        with open(
            os.path.join(self.test_dir, "sub2", "IMG_1.jpg"), "w", encoding="utf-8"
        ) as f:
            f.write("dup2")
        with open(
            os.path.join(self.test_dir, "sub3", "20210101_010101.jpg"),
            "w",
            encoding="utf-8",
        ) as f:
            f.write("dup3")

        json_path = os.path.join(self.test_dir, "duplicates_data.json")
        report = {
            "version": "1.3.0",
            "scan_time": "2026-01-01",
            "target_dir": self.test_dir,
            "settings": {},
            "summary": {},
            "groups": [
                {
                    "hash": "g1",
                    "keep": {"path": keep_a, "size": 10},
                    "delete": [{"path": os.path.join("sub1", "12345.jpg"), "size": 4}],
                },
                {
                    "hash": "g2",
                    "keep": {"path": keep_b, "size": 10},
                    "delete": [
                        {"path": os.path.join("sub2", "IMG_1.jpg"), "size": 4}
                    ],
                },
                {
                    "hash": "g3",
                    "keep": {"path": keep_c, "size": 10},
                    "delete": [
                        {
                            "path": os.path.join("sub3", "20210101_010101.jpg"),
                            "size": 4,
                        }
                    ],
                },
            ],
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f)

        backup_dir = os.path.join(self.test_dir, "_duplicates_backup")
        clean(
            target_dir=self.test_dir,
            json_path=json_path,
            backup_dir=backup_dir,
            auto_yes=True,
        )

        # chained rename should complete:
        # 1111111111.jpg -> 12345.jpg -> IMG_1.jpg -> 20210101_010101.jpg
        assert not os.path.exists(os.path.join(self.test_dir, keep_a))
        assert os.path.isfile(os.path.join(self.test_dir, "12345.jpg"))
        assert os.path.isfile(os.path.join(self.test_dir, "IMG_1.jpg"))
        assert os.path.isfile(os.path.join(self.test_dir, "20210101_010101.jpg"))

        with open(os.path.join(self.test_dir, "12345.jpg"), "r", encoding="utf-8") as f:
            assert f.read() == "content_a"
        with open(os.path.join(self.test_dir, "IMG_1.jpg"), "r", encoding="utf-8") as f:
            assert f.read() == "content_b"
        with open(
            os.path.join(self.test_dir, "20210101_010101.jpg"), "r", encoding="utf-8"
        ) as f:
            assert f.read() == "content_c"

    def test_undo_auto_yes_skips_prompt(self):
        """undo(auto_yes=True) 應跳過互動提示"""
        backup_dir = os.path.join(self.test_dir, "_duplicates_backup")
        os.makedirs(backup_dir, exist_ok=True)
        log_path = os.path.join(backup_dir, "_cleanup_log.json")
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "version": "1.3.0",
                    "target_dir": self.test_dir,
                    "backup_dir": backup_dir,
                    "status": "complete",
                    "moves": [],
                    "renames": [],
                },
                f,
                ensure_ascii=False,
                indent=2,
            )

        orig_input = builtins.input
        try:

            def _boom(_prompt):
                raise AssertionError(
                    "input() should not be called when auto_yes=True"
                )

            builtins.input = _boom
            undo(target_dir=self.test_dir, backup_dir=backup_dir, auto_yes=True)
        finally:
            builtins.input = orig_input

    def test_undo_rejects_path_outside_roots(self):
        """undo 應拒絕 log 中逸出 target/backup 的路徑"""
        backup_dir = os.path.join(self.test_dir, "_duplicates_backup")
        os.makedirs(backup_dir, exist_ok=True)
        log_path = os.path.join(backup_dir, "_cleanup_log.json")
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "version": "1.3.0",
                    "target_dir": self.test_dir,
                    "backup_dir": backup_dir,
                    "status": "complete",
                    "moves": [
                        {
                            "from": os.path.join(self.test_dir, "a.txt"),
                            "to": r"C:\Windows\System32\drivers\etc\hosts",
                        }
                    ],
                    "renames": [],
                },
                f,
                ensure_ascii=False,
                indent=2,
            )

        with pytest.raises(PathTraversalError):
            undo(target_dir=self.test_dir, backup_dir=backup_dir, auto_yes=True)

    def test_undo_prunes_empty_backup_subdirs(self):
        """undo 完成後應清掉空的備份子資料夾"""
        backup_dir = os.path.join(self.test_dir, "_duplicates_backup")
        moved_rel = os.path.join("sub", "moved.txt")
        moved_src = os.path.join(backup_dir, moved_rel)
        restored_dst = os.path.join(self.test_dir, moved_rel)

        os.makedirs(os.path.dirname(moved_src), exist_ok=True)
        with open(moved_src, "w", encoding="utf-8") as f:
            f.write("hello")

        log_path = os.path.join(backup_dir, "_cleanup_log.json")
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "version": "1.3.0",
                    "target_dir": self.test_dir,
                    "backup_dir": backup_dir,
                    "status": "complete",
                    "moves": [{"from": restored_dst, "to": moved_src}],
                    "renames": [],
                },
                f,
                ensure_ascii=False,
                indent=2,
            )

        undo(target_dir=self.test_dir, backup_dir=backup_dir, auto_yes=True)

        assert os.path.isfile(restored_dst)
        assert not os.path.isdir(os.path.join(backup_dir, "sub"))

    def test_clean_output_is_ascii_safe(self, caplog):
        """clean() 輸出不應包含 cp950 無法編碼的符號"""
        json_path = os.path.join(self.test_dir, "duplicates_data.json")
        report = {
            "version": "1.3.0",
            "scan_time": "2026-01-01",
            "target_dir": self.test_dir,
            "settings": {},
            "summary": {},
            "groups": [],
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f)

        with caplog.at_level(logging.INFO):
            clean(
                target_dir=self.test_dir,
                json_path=json_path,
                backup_dir=os.path.join(self.test_dir, "_duplicates_backup"),
                dry_run=True,
                auto_yes=True,
            )

        out = caplog.text
        for bad in ("\u2713", "\u26a0", "\u274c", "\u2192"):
            assert bad not in out

    def test_clean_rejects_incomplete_log(self):
        """若已有未完成的 event log，clean 應拒絕執行"""
        json_path = os.path.join(self.test_dir, "duplicates_data.json")
        report = {
            "version": "1.3.0",
            "scan_time": "2026-01-01",
            "target_dir": self.test_dir,
            "settings": {},
            "summary": {},
            "groups": [
                {
                    "hash": "abc",
                    "keep": {"path": "a.txt", "size": 11},
                    "delete": [{"path": "b.txt", "size": 11}],
                }
            ],
        }
        with open(json_path, "w") as f:
            json.dump(report, f)

        backup_dir = os.path.join(self.test_dir, "_duplicates_backup")
        os.makedirs(backup_dir, exist_ok=True)
        log_path = os.path.join(backup_dir, "_cleanup_log.json")
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump({"status": "in_progress", "version": "1.3.0"}, f)

        with pytest.raises(InvalidReportError, match="incomplete"):
            clean(
                target_dir=self.test_dir,
                json_path=json_path,
                backup_dir=backup_dir,
                auto_yes=True,
            )

    def test_undo_rejects_non_string_paths_in_jsonl(self):
        """undo 應拒絕 JSONL 中 from/to 為非字串型別"""
        backup_dir = os.path.join(self.test_dir, "_duplicates_backup")
        os.makedirs(backup_dir, exist_ok=True)

        log_path = os.path.join(backup_dir, "_cleanup_log.json")
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "version": "1.3.0",
                    "target_dir": self.test_dir,
                    "backup_dir": backup_dir,
                    "status": "complete",
                    "events_file": "_cleanup_log.events.jsonl",
                },
                f,
            )

        events_path = os.path.join(backup_dir, "_cleanup_log.events.jsonl")
        with open(events_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"type": "move", "from": [1, 2], "to": 999}) + "\n")

        with pytest.raises(InvalidReportError, match="must be strings"):
            undo(target_dir=self.test_dir, backup_dir=backup_dir, auto_yes=True)

    def test_undo_invalid_meta_log_raises_invalid_report_error(self):
        """undo 應把壞掉的 meta log 轉成 InvalidReportError"""
        backup_dir = os.path.join(self.test_dir, "_duplicates_backup")
        os.makedirs(backup_dir, exist_ok=True)
        log_path = os.path.join(backup_dir, "_cleanup_log.json")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("{invalid json")

        with pytest.raises(InvalidReportError, match="Invalid transaction log"):
            undo(target_dir=self.test_dir, backup_dir=backup_dir, auto_yes=True)


# ── Hasher 行為 ─────────────────────────────────


class TestHasherBehavior:
    """Hasher 行為測試"""

    def test_init_heic_support_does_not_mutate_extensions(self):
        """init_heic_support 不應修改全域 IMAGE_EXTENSIONS"""
        before = set(IMAGE_EXTENSIONS)
        orig_import = builtins.__import__

        def _import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "pillow_heif":
                raise ImportError("simulated missing pillow_heif")
            return orig_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", side_effect=_import):
            init_heic_support()

        after = set(IMAGE_EXTENSIONS)
        assert before == after

    def test_image_extensions_is_frozen(self):
        """IMAGE_EXTENSIONS 應為 frozenset，不可被意外修改"""
        assert isinstance(IMAGE_EXTENSIONS, frozenset)


# ── 工具函式 ────────────────────────────────────


class TestFormatSize:
    """format_size 各量級測試"""

    def test_bytes(self):
        assert format_size(0) == "0 B"
        assert format_size(512) == "512 B"
        assert format_size(1023) == "1023 B"

    def test_kilobytes(self):
        assert format_size(1024) == "1.0 KB"
        assert format_size(1536) == "1.5 KB"

    def test_megabytes(self):
        assert format_size(1024 * 1024) == "1.0 MB"
        assert format_size(int(1.5 * 1024 * 1024)) == "1.5 MB"

    def test_gigabytes(self):
        assert format_size(1024 * 1024 * 1024) == "1.00 GB"
        assert format_size(int(2.5 * 1024 * 1024 * 1024)) == "2.50 GB"


# ── 檔案收集 ────────────────────────────────────


class TestCollectFiles:
    """collect_files 遞迴 vs 非遞迴測試"""

    def test_recursive_finds_nested_files(self, tmp_path):
        """遞迴模式應找到子目錄中的檔案"""
        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "top.txt").write_text("a")
        (sub / "nested.txt").write_text("b")

        files, errors = collect_files(str(tmp_path), recursive=True)
        paths = [f.path for f in files]
        assert len(files) == 2
        assert any("nested.txt" in p for p in paths)
        assert not errors

    def test_non_recursive_skips_nested(self, tmp_path):
        """非遞迴模式不應掃描子目錄"""
        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "top.txt").write_text("a")
        (sub / "nested.txt").write_text("b")

        files, errors = collect_files(str(tmp_path), recursive=False)
        assert len(files) == 1
        assert "top.txt" in files[0].path

    def test_skips_backup_dir(self, tmp_path):
        """應跳過 _duplicates_backup 目錄"""
        backup = tmp_path / "_duplicates_backup"
        backup.mkdir()
        (tmp_path / "keep.txt").write_text("a")
        (backup / "skip.txt").write_text("b")

        files, _ = collect_files(str(tmp_path), recursive=True)
        paths = [f.path for f in files]
        assert len(files) == 1
        assert not any("skip.txt" in p for p in paths)

    def test_skips_hidden_files(self, tmp_path):
        """應跳過隱藏檔案（以 . 開頭）"""
        (tmp_path / ".hidden").write_text("x")
        (tmp_path / "visible.txt").write_text("y")

        files, _ = collect_files(str(tmp_path), recursive=True)
        assert len(files) == 1
        assert "visible.txt" in files[0].path

    def test_returns_file_entry_namedtuple(self, tmp_path):
        """應回傳 FileEntry NamedTuple"""
        (tmp_path / "test.jpg").write_bytes(b"\xff\xd8\xff")

        files, _ = collect_files(str(tmp_path), recursive=True)
        assert len(files) == 1
        entry = files[0]
        assert isinstance(entry, FileEntry)
        assert entry.ext == ".jpg"
        assert entry.size == 3


class TestScannerBehavior:
    """scan/build_groups 行為測試"""

    def test_scan_empty_dir_still_generates_reports(self, tmp_path):
        """空目錄掃描也應產生空報告，方便後續自動化流程"""
        scan(
            target_dir=str(tmp_path),
            output_dir=str(tmp_path),
            use_pixel=False,
            recursive=True,
        )

        json_path = tmp_path / "duplicates_data.json"
        text_path = tmp_path / "duplicates_report.txt"
        assert json_path.is_file()
        assert text_path.is_file()

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["summary"]["total_files"] == 0
        assert data["summary"]["duplicate_groups"] == 0
        assert data["summary"]["deletable_files"] == 0

    def test_build_groups_tie_breaks_same_size_by_path(self, tmp_path):
        """同大小檔案應以路徑穩定排序，避免 keep 結果受輸入順序影響"""
        f_b = os.path.join(str(tmp_path), "b.txt")
        f_a = os.path.join(str(tmp_path), "a.txt")
        dup_groups = {"h1": [f_b, f_a]}
        size_map = {f_b: 10, f_a: 10}

        groups = build_groups(dup_groups, size_map, str(tmp_path))
        assert groups[0]["keep"]["path"] == "a.txt"
