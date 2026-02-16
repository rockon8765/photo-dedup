# photo-dedup

Find and remove duplicate photos in your Google Photos backup (or any photo directory).

找出並移除 Google 相簿備份（或任何資料夾）中的重複照片。

## Features

- **Pixel-level comparison** — Compares decoded pixel data for images, ignoring EXIF/metadata differences
- **Recursive scanning** — Scans all subdirectories by default
- **Smart file retention** — Keeps the largest file in each duplicate group (preserves the most complete metadata)
- **Readable rename** — Renames kept files to the most human-readable name (preserves original extension)
- **Safe deletion** — Moves duplicates to a backup folder (preserving directory structure)
- **Undo support** — Transaction log (with fsync) enables full rollback with `--undo`
- **Path safety** — Validates all paths to prevent directory traversal attacks
- **JSON output** — Structured `duplicates_data.json` for machine processing
- **HEIC support** — Optional support for Apple HEIC photos via `pillow-heif`
- **Memory safety** — Limits max image pixels (60MP, ~180MB) to prevent decompression bombs

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# Optional: HEIC support
pip install pillow-heif

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

### `clean.py` — Safe Deletion + Rename

```
python clean.py --dir <DIR> [options]
```

| Option | Description |
|---|---|
| `--dir`, `-d` | **(Required)** Photo directory |
| `--report`, `-r` | Path to `duplicates_data.json` |
| `--backup`, `-b` | Backup directory (default: `<dir>/_duplicates_backup`) |
| `--no-rename` | Skip renaming kept files |
| `--dry-run` | Preview mode, no file system changes |
| `--yes`, `-y` | Skip interactive confirmation (for automation) |
| `--undo` | Undo previous cleanup using the transaction log |
| `--force` | Allow directory mismatch between report and `--dir` |

## How It Works

### Duplicate Detection

```
Image files (.jpg .jpeg .png .heic .webp .dng)
  → Decode with Pillow → Convert to RGB → MD5 of pixel bytes
  → Ignores EXIF, ICC profiles, thumbnails, compression differences
  → Images > 60MP auto-fallback to file MD5 (memory safety)

Other files (.mp4 .mov .gif .3gp etc.)
  → Pre-filter by file size (different size = not duplicate)
  → MD5 of entire file contents
```

### Safety Features

| Feature | Details |
|---|---|
| **Path validation** | Rejects absolute paths, `..` traversal, and paths escaping target dir |
| **Dir mismatch check** | Verifies report's target\_dir matches `--dir` (override with `--force`) |
| **Backup structure** | Preserves original directory structure in backup folder |
| **Transaction log** | Every move/rename recorded with fsync; supports `--undo` |
| **Dry run** | `--dry-run` makes zero file system changes (no dirs created) |
| **Input validation** | Checks directory existence and permissions upfront |
| **Memory limit** | MAX\_IMAGE\_PIXELS = 60MP (~180MB max per image) |

### Filename Readability

| Score | Filename Type | Example |
|---|---|---|
| +15 | Date + time | `20210103_081230.jpg` |
| +3 | Camera prefix | `IMG_20210103.jpg` |
| -10 | Unix timestamp | `1609753382985.jpeg` |
| -20 | Copy suffix | `photo (2).jpg` |

> Note: Renaming only changes the stem (basename), never the extension. This prevents creating files where the extension doesn't match the actual content.

## Testing

```bash
python tests/test_core.py -v
```

17 tests covering path safety, naming strategy, and end-to-end flow.

## Requirements

- Python 3.10+
- [Pillow](https://python-pillow.org/) — Image processing
- [pillow-heif](https://github.com/bigcat88/pillow_heif) — HEIC/HEIF support *(optional)*

## License

MIT
