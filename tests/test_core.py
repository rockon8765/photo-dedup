"""
自動化測試 — 核心功能回歸保護

測試類別：
  1. 路徑安全性 (path traversal)
  2. 檔名可讀性與改名策略
  3. 掃描 + 清理 + 回滾端到端流程
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

# 確保可以 import photo_dedup
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from photo_dedup.cleaner import _validate_relative_path, clean, load_json_report
from photo_dedup.exceptions import (
    DirectoryMismatchError,
    InvalidReportError,
    PathTraversalError,
)
from photo_dedup.naming import find_best_name, readability_score


class TestPathSafety(unittest.TestCase):
    """路徑安全性測試"""

    def setUp(self):
        self.target_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.target_dir, ignore_errors=True)

    def test_reject_absolute_path(self):
        """絕對路徑應被拒絕"""
        with self.assertRaises(PathTraversalError):
            _validate_relative_path("/etc/passwd", self.target_dir)

    def test_reject_windows_absolute_path(self):
        """Windows 絕對路徑應被拒絕"""
        with self.assertRaises(PathTraversalError):
            _validate_relative_path("C:\\Windows\\System32", self.target_dir)

    def test_reject_dotdot(self):
        """.. 路徑應被拒絕"""
        with self.assertRaises(PathTraversalError):
            _validate_relative_path("../../../etc/passwd", self.target_dir)

    def test_reject_hidden_dotdot(self):
        """隱藏在子目錄中的 .. 應被拒絕"""
        with self.assertRaises(PathTraversalError):
            _validate_relative_path("subdir/../../secret.txt", self.target_dir)

    def test_accept_normal_path(self):
        """正常的相對路徑應被接受"""
        result = _validate_relative_path("photo.jpg", self.target_dir)
        expected = os.path.normpath(
            os.path.join(self.target_dir, "photo.jpg")
        )
        self.assertEqual(result, expected)

    def test_accept_nested_path(self):
        """子目錄中的正常路徑應被接受"""
        result = _validate_relative_path("2021/01/photo.jpg", self.target_dir)
        self.assertIn("2021", result)


class TestNaming(unittest.TestCase):
    """檔名可讀性與改名策略測試"""

    def test_date_beats_timestamp(self):
        """日期格式應優於 Unix 時間戳"""
        score_date = readability_score("20210103_081230.jpg")
        score_ts = readability_score("1609753382985.jpeg")
        self.assertGreater(score_date, score_ts)

    def test_copy_suffix_penalized(self):
        """(1) (2) 副本標記應被扣分"""
        score_clean = readability_score("photo.jpg")
        score_copy = readability_score("photo (2).jpg")
        self.assertGreater(score_clean, score_copy)

    def test_camera_prefix_bonus(self):
        """IMG_ DSC_ 等前綴應加分"""
        score_img = readability_score("IMG_20210103.jpg")
        score_num = readability_score("12345.jpg")
        self.assertGreater(score_img, score_num)

    def test_find_best_name_keeps_extension(self):
        """改名應保留 keep 檔的原始副檔名"""
        new_name, should = find_best_name(
            "1609753382985.png",
            ["20210103_081230.jpg"],
        )
        # 應使用更好的 stem，但保留 keep 的 .png
        self.assertEqual(new_name, "20210103_081230.png")
        self.assertTrue(should)

    def test_find_best_name_no_rename_needed(self):
        """已經是最佳名稱時不應改名"""
        new_name, should = find_best_name(
            "20210103_081230.jpg",
            ["1609753382985.jpeg"],
        )
        self.assertEqual(new_name, "20210103_081230.jpg")
        self.assertFalse(should)

    def test_find_best_name_removes_copy_suffix(self):
        """應移除 (1) (2) 副本標記"""
        new_name, should = find_best_name(
            "photo (2).jpg",
            ["photo.jpg"],
        )
        self.assertEqual(new_name, "photo.jpg")
        self.assertTrue(should)

    def test_cross_extension_preserves_keep_ext(self):
        """跨副檔名組應保留 keep 檔的副檔名"""
        new_name, should = find_best_name(
            "timestamp.heic",
            ["20210103_081230.jpg"],
        )
        # stem 換成更好的，但副檔名保留 .heic
        self.assertEqual(new_name, "20210103_081230.heic")
        self.assertTrue(should)


class TestEndToEnd(unittest.TestCase):
    """端到端流程測試"""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        # 建立測試檔案
        self._write_file("a.txt", "hello world")
        self._write_file("b.txt", "hello world")
        self._write_file("c.txt", "different content")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _write_file(self, name, content):
        path = os.path.join(self.test_dir, name)
        with open(path, 'w') as f:
            f.write(content)

    def test_invalid_report_raises(self):
        """無效的 JSON 報告應拋出 InvalidReportError"""
        bad_json = os.path.join(self.test_dir, "bad.json")
        with open(bad_json, 'w') as f:
            f.write("not json")

        with self.assertRaises(InvalidReportError):
            load_json_report(bad_json)

    def test_dir_mismatch_raises(self):
        """target_dir 不一致應拋出 DirectoryMismatchError"""
        from photo_dedup.cleaner import validate_dir_match

        report_data = {"target_dir": "/some/other/path"}
        with self.assertRaises(DirectoryMismatchError):
            validate_dir_match(report_data, self.test_dir, force=False)

    def test_dir_mismatch_force_passes(self):
        """--force 應允許 target_dir 不一致"""
        from photo_dedup.cleaner import validate_dir_match

        report_data = {"target_dir": "/some/other/path"}
        # 不應拋出
        validate_dir_match(report_data, self.test_dir, force=True)

    def test_clean_dry_run_no_side_effects(self):
        """dry-run 不應建立任何新檔案或目錄"""
        json_path = os.path.join(self.test_dir, "duplicates_data.json")
        report = {
            "version": "1.2.0",
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
        with open(json_path, 'w') as f:
            json.dump(report, f)

        backup_dir = os.path.join(self.test_dir, "_duplicates_backup")

        clean(
            target_dir=self.test_dir,
            json_path=json_path,
            backup_dir=backup_dir,
            dry_run=True,
        )

        # backup_dir 不應被建立
        self.assertFalse(os.path.exists(backup_dir))
        # 原始檔案不應被移動
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, "b.txt")))


if __name__ == "__main__":
    unittest.main()
