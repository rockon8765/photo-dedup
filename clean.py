#!/usr/bin/env python3
"""
clean.py — 安全刪除重複檔案，並將保留檔改名為最可讀的名稱

Usage:
    python clean.py --dir <PHOTO_DIR>
    python clean.py --dir <PHOTO_DIR> --backup <BACKUP_DIR>
    python clean.py --dir <PHOTO_DIR> --dry-run
    python clean.py --dir <PHOTO_DIR> --yes
    python clean.py --dir <PHOTO_DIR> --undo
"""

import argparse
import sys

from photo_dedup.cleaner import clean, undo
from photo_dedup.exceptions import PhotoDedupError


def main():
    parser = argparse.ArgumentParser(
        description="Safely remove duplicate files / 安全刪除重複檔案",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python clean.py --dir /path/to/photos
  python clean.py --dir /path/to/photos --backup /path/to/backup
  python clean.py --dir /path/to/photos --dry-run
  python clean.py --dir /path/to/photos --yes
  python clean.py --dir /path/to/photos --undo
  python clean.py --dir /path/to/photos --force   # ignore dir mismatch
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
        help="Path to duplicates_data.json (default: <dir>/duplicates_data.json)",
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
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip interactive confirmation / 跳過確認提示（適合自動化）",
    )
    parser.add_argument(
        "--undo",
        action="store_true",
        help="Undo previous cleanup using transaction log / 回滾上次清理",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow directory mismatch between report and --dir / 忽略目錄不一致",
    )

    args = parser.parse_args()

    try:
        if args.undo:
            undo(
                target_dir=args.dir,
                backup_dir=args.backup,
            )
        else:
            clean(
                target_dir=args.dir,
                json_path=args.report,
                backup_dir=args.backup,
                do_rename=not args.no_rename,
                dry_run=args.dry_run,
                auto_yes=args.yes,
                force_mismatch=args.force,
            )
    except PhotoDedupError as e:
        print(f"\n❌ {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
