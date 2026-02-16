# photo-dedup

Find and remove duplicate photos in your Google Photos backup (or any photo directory).

找出並移除 Google 相簿備份（或任何資料夾）中的重複照片。

## Features

- **Pixel-level comparison** — Compares decoded pixel data for images, ignoring EXIF/metadata differences. Two files with identical pixels but different metadata are correctly identified as duplicates.
- **Recursive scanning** — Scans all subdirectories by default.
- **Smart file retention** — Keeps the largest file in each duplicate group (preserves the most complete metadata).
- **Readable rename** — Renames kept files to the most human-readable name and optimal extension (e.g. `1609753382985.png` → `20210103_081230.jpg`).
- **Safe deletion** — Moves duplicates to a backup folder (preserving directory structure) instead of deleting.
- **Undo support** — Transaction log enables full rollback with `--undo`.
- **JSON output** — Structured `duplicates_data.json` for machine processing; human-readable `.txt` report also generated.
- **HEIC support** — Full support for Apple HEIC photos via `pillow-heif`.
- **Memory safety** — Limits max image pixels (100MP) to prevent decompression bombs.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Scan for duplicates (recursive by default)
python scan.py --dir /path/to/photos

# 3. Review the report
#    → duplicates_data.json    (structured, machine-readable)
#    → duplicates_report.txt   (human-readable)

# 4. Preview changes (dry run)
python clean.py --dir /path/to/photos --dry-run

# 5. Clean up (moves to backup folder + renames)
python clean.py --dir /path/to/photos

# 6. If something went wrong, undo everything
python clean.py --dir /path/to/photos --undo
```

## Usage

### `scan.py` — Scan for Duplicates

```
python scan.py --dir <DIR> [options]
```

| Option | Description |
|---|---|
| `--dir`, `-d` | **(Required)** Directory to scan |
| `--output`, `-o` | Output dir for reports (default: same as `--dir`) |
| `--no-pixel` | Use file-level MD5 instead of pixel comparison (faster but less accurate) |
| `--no-recursive` | Only scan the top-level directory, skip subdirectories |

**Output files:**
- `duplicates_data.json` — Structured report (used by `clean.py`)
- `duplicates_report.txt` — Human-readable report

### `clean.py` — Safe Deletion + Rename

```
python clean.py --dir <DIR> [options]
```

| Option | Description |
|---|---|
| `--dir`, `-d` | **(Required)** Photo directory |
| `--report`, `-r` | Path to `duplicates_data.json` (default: `<dir>/duplicates_data.json`) |
| `--backup`, `-b` | Backup directory (default: `<dir>/_duplicates_backup`) |
| `--no-rename` | Skip renaming kept files |
| `--dry-run` | Preview mode — show what would happen without making changes |
| `--yes`, `-y` | Skip interactive confirmation (for automation / cron jobs) |
| `--undo` | Undo previous cleanup using the transaction log |

## How It Works

### Duplicate Detection

```
Image files (.jpg .jpeg .png .heic .webp .dng)
  → Decode with Pillow → Convert to RGB → MD5 of pixel bytes
  → Ignores EXIF, ICC profiles, thumbnails, compression differences
  → Images > 100MP auto-fallback to file MD5 (memory safety)

Other files (.mp4 .mov .gif .3gp etc.)
  → Pre-filter by file size (different size = not duplicate)
  → MD5 of entire file contents
```

### Retention Rule

For each duplicate group: **keep the largest file** (most likely has complete metadata).

### Filename Readability + Extension Priority

After keeping the best file, rename it using the most readable name AND the most optimal extension:

| Score | Filename Type | Example |
|---|---|---|
| +15 | Date + time | `20210103_081230.jpg` |
| +3 | Camera prefix | `IMG_20210103.jpg` |
| -10 | Unix timestamp | `1609753382985.jpeg` |
| -20 | Copy suffix | `photo (2).jpg` |

Extension priority: `.jpg` > `.jpeg` > `.png` > `.heic` > `.webp` > `.dng`

### Safety Features

| Feature | Details |
|---|---|
| **Backup** | Duplicates moved to backup folder, preserving original directory structure |
| **Transaction log** | All operations recorded in `_cleanup_log.json` |
| **Undo** | `--undo` reverses all moves and renames |
| **Dry run** | `--dry-run` previews without changes |
| **Validation** | Checks directory existence, permissions before starting |

## Requirements

- Python 3.10+
- [Pillow](https://python-pillow.org/) — Image processing
- [pillow-heif](https://github.com/bigcat88/pillow_heif) — HEIC/HEIF support (optional but recommended)

## License

MIT
