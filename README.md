# photo-dedup

Find and remove duplicate photos in your Google Photos backup (or any photo directory).

找出並移除 Google 相簿備份（或任何資料夾）中的重複照片。

## Features

- **Pixel-level comparison** — Compares decoded pixel data for images, ignoring EXIF/metadata differences. Two files with identical pixels but different metadata are correctly identified as duplicates.
- **Smart file retention** — Keeps the largest file in each duplicate group (preserves the most complete metadata).
- **Readable rename** — Renames kept files to the most human-readable name in each group (e.g. `1609753382985.jpeg` → `20210103_081230.jpeg`).
- **Safe deletion** — Moves duplicates to a backup folder instead of deleting. You can review and permanently delete later.
- **HEIC support** — Full support for Apple HEIC photos via `pillow-heif`.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Scan for duplicates
python scan.py --dir /path/to/photos

# 3. Review the report
#    → duplicates_report.txt
#    → duplicates_to_delete.txt

# 4. Clean up (moves to backup folder + renames)
python clean.py --dir /path/to/photos
```

## Usage

### `scan.py` — Scan for Duplicates

```
python scan.py --dir <DIR> [--output <OUTPUT_DIR>] [--no-pixel]
```

| Option | Description |
|---|---|
| `--dir`, `-d` | **(Required)** Directory to scan |
| `--output`, `-o` | Output dir for reports (default: same as `--dir`) |
| `--no-pixel` | Use file-level MD5 instead of pixel comparison (faster but less accurate) |

**Output files:**
- `duplicates_report.txt` — Human-readable report with all duplicate groups
- `duplicates_to_delete.txt` — List of files to delete (one per line)

### `clean.py` — Safe Deletion + Rename

```
python clean.py --dir <DIR> [--report <PATH>] [--backup <DIR>] [--no-rename] [--dry-run]
```

| Option | Description |
|---|---|
| `--dir`, `-d` | **(Required)** Photo directory |
| `--report`, `-r` | Path to report file (default: `<dir>/duplicates_report.txt`) |
| `--backup`, `-b` | Backup directory (default: `<dir>/_duplicates_backup`) |
| `--no-rename` | Skip renaming kept files |
| `--dry-run` | Preview mode — show what would happen without making changes |

## How It Works

### Duplicate Detection

```
Image files (.jpg .jpeg .png .heic .webp .dng)
  → Decode with Pillow → Convert to RGB → MD5 of pixel bytes
  → Ignores EXIF, ICC profiles, thumbnails, etc.

Other files (.mp4 .mov .gif .3gp etc.)
  → Pre-filter by file size (different size = not duplicate)
  → MD5 of entire file contents
```

### Retention Rule

For each group of duplicates, **keep the largest file** — it most likely has the most complete metadata (capture date, GPS, camera info).

### Filename Readability

After keeping the best file, rename it to the most readable name in the group:

| Score | Filename Type | Example |
|---|---|---|
| +15 | Date + time | `20210103_081230.jpg` |
| +3 | Camera prefix | `IMG_20210103.jpg` |
| -10 | Unix timestamp | `1609753382985.jpeg` |
| -20 | Copy suffix | `photo (2).jpg` |

## Requirements

- Python 3.10+
- [Pillow](https://python-pillow.org/) — Image processing
- [pillow-heif](https://github.com/bigcat88/pillow_heif) — HEIC/HEIF support (optional but recommended)

## License

MIT
