#!/usr/bin/env python3
"""
scan.py — 掃描資料夾中的重複檔案

Usage:
    python scan.py --dir <PHOTO_DIR>
    python scan.py --dir <PHOTO_DIR> --output <OUTPUT_DIR>
    python scan.py --dir <PHOTO_DIR> --no-pixel
    python scan.py --dir <PHOTO_DIR> --strict-verify
    python scan.py --dir <PHOTO_DIR> --no-recursive
"""

import argparse
import logging
import sys

from photo_dedup.exceptions import PhotoDedupError
from photo_dedup.scanner import scan


def _configure_logging():
    """Set up root logging: INFO to stdout."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )


def _configure_stdout():
    """Enable line buffering when stdout supports it."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)


def main():
    _configure_stdout()
    _configure_logging()

    parser = argparse.ArgumentParser(
        description="Scan a directory for duplicate files / 掃描資料夾中的重複檔案",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scan.py --dir /path/to/photos
  python scan.py --dir /path/to/photos --output /path/to/reports
  python scan.py --dir /path/to/photos --no-pixel
  python scan.py --dir /path/to/photos --strict-verify
  python scan.py --dir /path/to/photos --no-recursive
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
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Don't scan subdirectories / 不掃描子資料夾",
    )
    parser.add_argument(
        "--strict-verify",
        action="store_true",
        help=(
            "Byte-verify FILE hash matches to avoid false positives "
            "(slower, safer) / 對 FILE hash 命中做逐位元組驗證"
        ),
    )
    parser.add_argument(
        "--image-match",
        choices=["exact", "similar", "hybrid"],
        default="hybrid",
        help=(
            "Image matching mode: "
            "'exact' (pixel MD5, same resolution only), "
            "'similar' (perceptual hash, cross-resolution), "
            "'hybrid' (exact first, then similar for remaining). "
            "Default: hybrid / 圖片比對模式"
        ),
    )
    parser.add_argument(
        "--hamming-threshold",
        type=int,
        default=None,
        help="dHash Hamming distance threshold for similar mode (default: 20)",
    )
    parser.add_argument(
        "--rms-threshold",
        type=float,
        default=None,
        help="RMS pixel difference threshold (0-255) for similar mode (default: 8.0)",
    )

    args = parser.parse_args()

    # 組裝 similar 相關參數（只傳有值的，讓 scan() 用預設值）
    extra_kwargs = {}
    if args.hamming_threshold is not None:
        extra_kwargs["hamming_threshold"] = args.hamming_threshold
    if args.rms_threshold is not None:
        extra_kwargs["rms_threshold"] = args.rms_threshold

    try:
        scan(
            target_dir=args.dir,
            output_dir=args.output,
            use_pixel=not args.no_pixel,
            recursive=not args.no_recursive,
            strict_verify=args.strict_verify,
            image_match=args.image_match,
            **extra_kwargs,
        )
    except PhotoDedupError as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
