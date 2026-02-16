#!/usr/bin/env python3
"""
clean.py — 安全刪除重複檔案，並將保留檔改名為最可讀的名稱

Usage:
    python clean.py --dir <PHOTO_DIR>
    python clean.py --dir <PHOTO_DIR> --backup <BACKUP_DIR>
    python clean.py --dir <PHOTO_DIR> --no-rename
    python clean.py --dir <PHOTO_DIR> --dry-run
"""

import argparse
import sys

from photo_dedup.cleaner import clean


def main():
    parser = argparse.ArgumentParser(
        description="Safely remove duplicate files / 安全刪除重複檔案",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python clean.py --dir /path/to/photos
  python clean.py --dir /path/to/photos --backup /path/to/backup
  python clean.py --dir /path/to/photos --no-rename
  python clean.py --dir /path/to/photos --dry-run
        """,
    )
    parser.add_argument(
        "--dir", "-d",
        required=True,
        help="Photo directory / 照片資料夾路徑",
    )
    parser.add_argument(
        "--report", "-r",
        default=None,
        help="Path to duplicates_report.txt (default: <dir>/duplicates_report.txt)",
    )
    parser.add_argument(
        "--backup", "-b",
        default=None,
        help="Backup directory (default: <dir>/_duplicates_backup) / 備份資料夾路徑",
    )
    parser.add_argument(
        "--no-rename",
        action="store_true",
        help="Don't rename kept files to more readable names / 不改名保留檔案",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview only, don't actually move or rename files / 預覽模式",
    )

    args = parser.parse_args()
    clean(
        target_dir=args.dir,
        report_path=args.report,
        backup_dir=args.backup,
        do_rename=not args.no_rename,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
