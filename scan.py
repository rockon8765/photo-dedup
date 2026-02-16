#!/usr/bin/env python3
"""
scan.py — 掃描資料夾中的重複檔案

Usage:
    python scan.py --dir <PHOTO_DIR>
    python scan.py --dir <PHOTO_DIR> --output <OUTPUT_DIR>
    python scan.py --dir <PHOTO_DIR> --no-pixel
"""

import argparse
import sys

from photo_dedup.scanner import scan


def main():
    parser = argparse.ArgumentParser(
        description="Scan a directory for duplicate files / 掃描資料夾中的重複檔案",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scan.py --dir /path/to/photos
  python scan.py --dir /path/to/photos --output /path/to/reports
  python scan.py --dir /path/to/photos --no-pixel
        """,
    )
    parser.add_argument(
        "--dir", "-d",
        required=True,
        help="Directory to scan for duplicates / 要掃描的資料夾路徑",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output directory for reports (default: same as --dir) / 報告輸出路徑",
    )
    parser.add_argument(
        "--no-pixel",
        action="store_true",
        help="Disable pixel comparison, use file MD5 only (faster) / 停用像素比對",
    )

    args = parser.parse_args()
    scan(
        target_dir=args.dir,
        output_dir=args.output,
        use_pixel=not args.no_pixel,
    )


if __name__ == "__main__":
    main()
