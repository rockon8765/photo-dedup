"""
掃描模組 — 找出資料夾中的重複檔案

流程：
  1. 驗證輸入參數
  2. 用 os.walk (遞迴) 或 os.scandir (平面) 收集所有檔案
  3. 非圖片檔按大小分組預篩（大小不同不可能重複）
  4. 非圖片先做 partial hash，再對候選做全檔 MD5
  5. 圖片依模式比對（exact/similar/hybrid），其他檔案做全檔 MD5
  6. 產出 JSON 結構化報告 + 可讀文字報告
"""

import json
import logging
import os
import time
from collections import defaultdict, deque
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import datetime, timezone
from typing import NamedTuple

from .exceptions import AccessDeniedError, DirectoryNotFoundError, InvalidParameterError
from .hasher import (
    HAMMING_THRESHOLD,
    IMAGE_EXTENSIONS,
    RMS_THRESHOLD,
    compute_hash,
    compute_rms_difference,
    get_dhash,
    get_file_partial_md5,
    hamming_distance,
    init_heic_support,
)
from .utils import SCAN_SKIP_DIR_NAMES, VERSION, format_size

logger = logging.getLogger(__name__)

HASH_PROGRESS_INTERVAL = 1000


class FileEntry(NamedTuple):
    """Represents a file found during scanning."""
    path: str
    size: int
    ext: str


def validate_scan_args(target_dir: str, output_dir: str):
    """
    驗證掃描參數。

    Raises:
        DirectoryNotFoundError: 目標資料夾不存在
        AccessDeniedError: 權限不足
    """
    if not os.path.exists(target_dir):
        raise DirectoryNotFoundError(f"Directory not found: {target_dir}")

    if not os.path.isdir(target_dir):
        raise DirectoryNotFoundError(f"Not a directory: {target_dir}")

    if not os.access(target_dir, os.R_OK):
        raise AccessDeniedError(f"No read permission: {target_dir}")

    # 確保 output_dir 可寫
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        raise AccessDeniedError(
            f"Cannot create output directory: {output_dir} ({e})"
        )

    if not os.access(output_dir, os.W_OK):
        raise AccessDeniedError(f"No write permission: {output_dir}")


def collect_files(
    target_dir: str,
    recursive: bool = True,
) -> tuple[list[FileEntry], list[str]]:
    """
    收集目標資料夾中的所有檔案。

    Args:
        target_dir: 目標資料夾
        recursive: 是否遞迴掃描子資料夾

    Returns:
        (files, errors):
            files: list of FileEntry(path, size, ext)
            errors: list of error messages for skipped files
    """
    skip_dirs = SCAN_SKIP_DIR_NAMES
    all_files: list[FileEntry] = []
    errors: list[str] = []

    if recursive:
        def _walk_onerror(e: OSError) -> None:
            location = e.filename or target_dir
            errors.append(f"{location}: {e}")

        # followlinks=False: 防止符號連結逃逸目標目錄
        for dirpath, dirnames, filenames in os.walk(
            target_dir, followlinks=False, onerror=_walk_onerror,
        ):
            # 跳過特定目錄
            dirnames[:] = [
                d for d in dirnames
                if d not in skip_dirs and not d.startswith('.')
            ]
            for name in filenames:
                if name.startswith('.'):
                    continue
                filepath = os.path.join(dirpath, name)
                try:
                    size = os.path.getsize(filepath)
                    ext = os.path.splitext(name)[1].lower()
                    all_files.append(FileEntry(filepath, size, ext))
                except OSError as e:
                    errors.append(f"{filepath}: {e}")
    else:
        for entry in os.scandir(target_dir):
            if entry.is_file(follow_symlinks=False) and not entry.name.startswith('.'):
                try:
                    stat = entry.stat()
                    ext = os.path.splitext(entry.name)[1].lower()
                    all_files.append(FileEntry(entry.path, stat.st_size, ext))
                except OSError as e:
                    errors.append(f"{entry.path}: {e}")

    return all_files, errors


def categorize_files(
    all_files: list[FileEntry],
    use_pixel: bool,
) -> tuple[list[FileEntry], list[FileEntry]]:
    """
    分類檔案：決定哪些需要計算 hash。

    非圖片檔只有大小相同時才需要比對。
    圖片檔因為 metadata 差異會導致大小不同，全部都需要比對。

    Returns:
        (image_candidates, non_image_candidates)
    """
    image_files: list[FileEntry] = []
    non_image_by_size: dict[int, list[FileEntry]] = defaultdict(list)

    for entry in all_files:
        if use_pixel and entry.ext in IMAGE_EXTENSIONS:
            image_files.append(entry)
        else:
            non_image_by_size[entry.size].append(entry)

    non_image_candidates: list[FileEntry] = []
    for size, files in non_image_by_size.items():
        if len(files) > 1:
            non_image_candidates.extend(files)

    return image_files, non_image_candidates


def _hash_one(args: tuple[str, str, bool]) -> tuple[str, str] | None:
    """Worker function for parallel hashing. Returns (path, hash) or None."""
    path, ext, use_pixel = args
    try:
        return (path, compute_hash(path, ext, use_pixel))
    except Exception as e:
        logger.error("Hash failed: %s: %s", os.path.basename(path), e)
        return None


def _partial_hash_one(path: str) -> tuple[str, str] | None:
    """Worker for non-image partial hash stage."""
    try:
        return (path, get_file_partial_md5(path))
    except Exception as e:
        logger.error("Partial hash failed: %s: %s", os.path.basename(path), e)
        return None


def _files_identical(path_a: str, path_b: str, chunk_size: int = 65536) -> bool:
    """
    Byte-by-byte comparison for strict verification.

    Any I/O error is treated as non-identical (safe default: don't dedup).
    """
    if path_a == path_b:
        return True

    try:
        if os.path.getsize(path_a) != os.path.getsize(path_b):
            return False
    except OSError as e:
        logger.warning(
            "Strict verify size check failed: %s vs %s (%s)",
            os.path.basename(path_a),
            os.path.basename(path_b),
            e,
        )
        return False

    try:
        with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
            while True:
                chunk_a = fa.read(chunk_size)
                chunk_b = fb.read(chunk_size)
                if chunk_a != chunk_b:
                    return False
                if not chunk_a:
                    return True
    except OSError as e:
        logger.warning(
            "Strict verify read failed: %s vs %s (%s)",
            os.path.basename(path_a),
            os.path.basename(path_b),
            e,
        )
        return False


def _dhash_one(path: str) -> tuple[str, bytes] | None:
    """Worker for perceptual hash (dHash) computation."""
    try:
        return (path, get_dhash(path))
    except Exception as e:
        logger.error("dHash failed: %s: %s", os.path.basename(path), e)
        return None


class _BKTree:
    """
    BK-tree for Hamming distance search on fixed-length byte hashes.

    This avoids O(n²) pairwise comparisons for large image sets.
    """

    def __init__(self, hashes: list[bytes]):
        self.hashes = hashes
        self.root: int | None = None
        self.children: dict[int, dict[int, int]] = defaultdict(dict)

    def insert(self, idx: int) -> None:
        if self.root is None:
            self.root = idx
            return

        node = self.root
        while node is not None:
            dist = hamming_distance(self.hashes[idx], self.hashes[node])
            next_node = self.children[node].get(dist)
            if next_node is None:
                self.children[node][dist] = idx
                return
            node = next_node

    def search(self, idx: int, radius: int) -> list[int]:
        """
        Find neighbor node indices whose Hamming distance <= radius.

        Note: if the query index has already been inserted into the tree,
        this result may include `idx` itself. Callers should filter self-hits.
        """
        if self.root is None:
            return []

        query = self.hashes[idx]
        found: list[int] = []
        stack = [self.root]
        while stack:
            node = stack.pop()
            dist = hamming_distance(query, self.hashes[node])
            if dist <= radius:
                found.append(node)

            lower = dist - radius
            upper = dist + radius
            for edge_dist, child in self.children.get(node, {}).items():
                if lower <= edge_dist <= upper:
                    stack.append(child)

        return found


def _find_connected_components(
    adjacency: dict[int, set[int]],
    n: int,
) -> list[list[int]]:
    """BFS 取 connected components。"""
    visited = [False] * n
    components: list[list[int]] = []

    for start in range(n):
        if visited[start]:
            continue

        component = []
        queue = deque([start])
        visited[start] = True
        while queue:
            node = queue.popleft()
            component.append(node)
            for neighbor in adjacency.get(node, set()):
                if not visited[neighbor]:
                    visited[neighbor] = True
                    queue.append(neighbor)
        components.append(component)

    return components


def find_similar_image_groups(
    image_candidates: list[FileEntry],
    hamming_threshold: int = HAMMING_THRESHOLD,
    rms_threshold: float = RMS_THRESHOLD,
) -> tuple[dict[str, list[str]], dict[str, int]]:
    """
    用感知雜湊 (dHash) 找出跨解析度的相似圖片。

    Stage 1: 計算 dHash → BK-tree 半徑搜尋建圖 → connected components
    Stage 2: component 內 pairwise RMS 驗證 → 代表者模式分子群

    Args:
        image_candidates: 要比對的圖片清單
        hamming_threshold: Hamming distance 門檻
        rms_threshold: RMS 像素差門檻 (0-255 scale)

    Returns:
        (hash_groups, size_map)
        hash_groups key 格式: "SIMILAR:group_N"
    """
    if not image_candidates:
        return {}, {}

    # Stage 1: 計算 dHash
    logger.info(
        "  Similar image detection: computing dHash for %d images...",
        len(image_candidates),
    )
    dhashes: list[tuple[str, bytes, int]] = []  # (path, dhash, original_size)

    with ThreadPoolExecutor() as pool:
        results = pool.map(
            _dhash_one,
            [e.path for e in image_candidates],
        )
        for entry, result in zip(image_candidates, results):
            if result is not None:
                path, dh = result
                dhashes.append((path, dh, entry.size))
            # dHash 失敗的圖片直接跳過（不參與相似比對）

    n = len(dhashes)
    if n < 2:
        return {}, {}

    # BK-tree radius search → adjacency list
    adjacency: dict[int, set[int]] = defaultdict(set)
    hash_values = [item[1] for item in dhashes]
    tree = _BKTree(hash_values)
    for i in range(n):
        for j in tree.search(i, hamming_threshold):
            if j == i:
                continue
            adjacency[i].add(j)
            adjacency[j].add(i)
        tree.insert(i)

    # BFS connected components
    components = _find_connected_components(adjacency, n)

    # Stage 2: component 內 RMS 驗證
    hash_groups: dict[str, list[str]] = {}
    size_map: dict[str, int] = {}
    group_counter = 0

    for component in components:
        if len(component) < 2:
            continue

        # 代表者模式分子群（同 strict_verify 邏輯）
        subgroups: list[list[int]] = []
        for idx in component:
            assigned = False
            for subgroup in subgroups:
                rep_idx = subgroup[0]
                rms = compute_rms_difference(
                    dhashes[idx][0], dhashes[rep_idx][0],
                )
                if rms <= rms_threshold:
                    subgroup.append(idx)
                    assigned = True
                    break
            if not assigned:
                subgroups.append([idx])

        # 只保留 >= 2 張的子群
        for subgroup in subgroups:
            if len(subgroup) < 2:
                continue
            group_counter += 1
            key = f"SIMILAR:group_{group_counter}"
            paths = [dhashes[idx][0] for idx in subgroup]
            hash_groups[key] = paths
            for idx in subgroup:
                size_map[dhashes[idx][0]] = dhashes[idx][2]

    if group_counter > 0:
        logger.info(
            "  Found %d similar image group(s)",
            group_counter,
        )

    return hash_groups, size_map


def compute_hashes(
    image_candidates: list[FileEntry],
    non_image_candidates: list[FileEntry],
    use_pixel: bool,
    image_match: str = "hybrid",
    hamming_threshold: int = HAMMING_THRESHOLD,
    rms_threshold: float = RMS_THRESHOLD,
) -> tuple[dict[str, list[str]], dict[str, int]]:
    """
    計算所有候選檔案的 hash。

    圖片比對模式 (image_match):
      - "exact":   像素 MD5（現有行為，不跨解析度）
      - "similar": 感知雜湊 dHash + RMS 驗證（跨解析度）
      - "hybrid":  先 exact，未命中的殘餘圖片再走 similar

    非圖片檔採兩階段：
      1) partial hash 預篩（ThreadPool）
      2) 只有 size+partial 命中的檔案才做 full MD5（ThreadPool）

    Returns:
        (hash_groups, size_map)
    """
    hash_groups: dict[str, list[str]] = defaultdict(list)
    size_map: dict[str, int] = {}
    processed = 0
    errors = 0
    start_time = time.time()
    total_ops = len(image_candidates) + len(non_image_candidates)

    def _log_progress(force: bool = False) -> None:
        nonlocal processed
        if processed == 0:
            return
        if not force and processed % HASH_PROGRESS_INTERVAL != 0:
            return

        elapsed = time.time() - start_time
        speed = processed / elapsed if elapsed > 0 else 0
        safe_total = max(total_ops, processed)
        remaining = (safe_total - processed) / speed if speed > 0 else 0
        logger.info(
            "Progress: %d/%d (%d%%) ETA: %.0fs",
            processed,
            safe_total,
            processed * 100 // safe_total,
            remaining,
        )

    def _process_results(
        results,
        entries: list[FileEntry],
    ) -> None:
        nonlocal processed, errors
        for entry, result in zip(entries, results):
            if result is not None:
                path, h = result
                hash_groups[h].append(path)
                size_map[path] = entry.size
            else:
                errors += 1
            processed += 1
            _log_progress()

    # 非圖片: 先 partial hash，再只對 size+partial 命中的檔案做 full hash
    if non_image_candidates:
        logger.info(
            "  Non-image partial hash prefilter: %d files",
            len(non_image_candidates),
        )
        partial_groups: dict[tuple[int, str], list[FileEntry]] = defaultdict(list)
        with ThreadPoolExecutor() as pool:
            partial_results = pool.map(
                _partial_hash_one,
                [e.path for e in non_image_candidates],
            )
            for entry, result in zip(non_image_candidates, partial_results):
                if result is None:
                    errors += 1
                else:
                    _, partial_hash = result
                    partial_groups[(entry.size, partial_hash)].append(entry)
                processed += 1
                _log_progress()

        full_hash_candidates: list[FileEntry] = []
        for files in partial_groups.values():
            if len(files) > 1:
                full_hash_candidates.extend(files)

        total_ops += len(full_hash_candidates)

        logger.info(
            "  Non-image full MD5 after prefilter: %d files",
            len(full_hash_candidates),
        )

        if full_hash_candidates:
            args_list = [
                (e.path, e.ext, use_pixel) for e in full_hash_candidates
            ]
            with ThreadPoolExecutor() as pool:
                results = pool.map(_hash_one, args_list)
            _process_results(results, full_hash_candidates)

    # 圖片處理：依 image_match 模式分流
    if image_candidates:
        if image_match == "similar":
            # 全部走感知雜湊
            similar_groups, similar_sizes = find_similar_image_groups(
                image_candidates, hamming_threshold, rms_threshold,
            )
            hash_groups.update(similar_groups)
            size_map.update(similar_sizes)
            processed += len(image_candidates)

        elif image_match == "hybrid":
            # Step 1: 先做 exact pixel hash
            args_list = [(e.path, e.ext, use_pixel) for e in image_candidates]
            try:
                with ProcessPoolExecutor() as pool:
                    results = pool.map(_hash_one, args_list, chunksize=8)
                _process_results(results, image_candidates)
            except Exception:
                logger.warning(
                    "ProcessPool failed, falling back to sequential",
                    exc_info=True,
                )
                results = (_hash_one(a) for a in args_list)
                _process_results(results, image_candidates)

            # Step 2: 收集未命中的殘餘圖片 + exact 組代表者
            matched_paths: set[str] = set()
            exact_group_reps: dict[str, str] = {}  # rep_path → hash_key
            for h, files in hash_groups.items():
                if not h.startswith("FILE:") and len(files) >= 2:
                    matched_paths.update(files)
                    exact_group_reps[files[0]] = h

            remaining = [
                e for e in image_candidates
                if e.path not in matched_paths
            ]

            # 加入 exact 組代表者，讓 similar 階段能跨解析度配對
            rep_entries = [
                e for e in image_candidates
                if e.path in exact_group_reps
            ]
            similar_candidates = remaining + rep_entries

            if len(similar_candidates) >= 2:
                logger.info(
                    "  Hybrid: %d images unmatched by exact "
                    "(+ %d exact-group reps), running similar detection...",
                    len(remaining),
                    len(rep_entries),
                )
                similar_groups, similar_sizes = find_similar_image_groups(
                    similar_candidates, hamming_threshold, rms_threshold,
                )

                # 合併規則：
                # 1) similar 組含 exact reps → 合併 reps 所在 exact 組，再加入新成員
                # 2) pure similar 組（無 exact rep）→ 新增為 SIMILAR 群組
                for sim_key, sim_paths in similar_groups.items():
                    reps_in_group = [
                        p for p in sim_paths if p in exact_group_reps
                    ]
                    new_members = [
                        p for p in sim_paths if p not in exact_group_reps
                    ]

                    if reps_in_group:
                        base_key = exact_group_reps[reps_in_group[0]]
                        base_members = hash_groups[base_key]

                        # 先把其他 reps 的 exact 組併到 base
                        for rep_path in reps_in_group[1:]:
                            other_key = exact_group_reps[rep_path]
                            if other_key == base_key:
                                continue
                            for member_path in hash_groups.get(other_key, []):
                                if member_path not in base_members:
                                    base_members.append(member_path)

                            for rep, key in list(exact_group_reps.items()):
                                if key == other_key:
                                    exact_group_reps[rep] = base_key
                            hash_groups.pop(other_key, None)

                        # 再把 similar 新成員併入 base
                        for p in new_members:
                            if p not in base_members:
                                base_members.append(p)
                            size_map[p] = similar_sizes.get(p, size_map.get(p, 0))
                    else:
                        # 純新 similar 組，直接加入
                        unique_paths: list[str] = []
                        for p in sim_paths:
                            if p not in unique_paths:
                                unique_paths.append(p)
                        hash_groups[sim_key] = unique_paths
                        for p in unique_paths:
                            size_map[p] = similar_sizes[p]

        else:
            # "exact": 現有 pixel hash 行為
            args_list = [(e.path, e.ext, use_pixel) for e in image_candidates]
            try:
                with ProcessPoolExecutor() as pool:
                    results = pool.map(_hash_one, args_list, chunksize=8)
                _process_results(results, image_candidates)
            except Exception:
                logger.warning(
                    "ProcessPool failed, falling back to sequential",
                    exc_info=True,
                )
                results = (_hash_one(a) for a in args_list)
                _process_results(results, image_candidates)

    _log_progress(force=True)
    elapsed = time.time() - start_time
    logger.info("Done! %.1fs, %d errors", elapsed, errors)
    return hash_groups, size_map


def strict_verify_file_hash_groups(
    hash_groups: dict[str, list[str]],
    size_map: dict[str, int],
) -> dict[str, list[str]]:
    """
    對 FILE hash 群組做 byte-by-byte 最終確認，避免 hash collision 誤判。

    若同一 FILE hash 中出現內容不一致，會拆成多個子群組。
    """
    verified: dict[str, list[str]] = {}
    split_group_count = 0

    for h, files in hash_groups.items():
        if not h.startswith("FILE:") or len(files) <= 1:
            verified[h] = files
            continue

        subgroups: list[list[str]] = []
        for path in files:
            assigned = False
            for subgroup in subgroups:
                rep = subgroup[0]
                if size_map.get(path) != size_map.get(rep):
                    continue
                if _files_identical(path, rep):
                    subgroup.append(path)
                    assigned = True
                    break

            if not assigned:
                subgroups.append([path])

        if len(subgroups) == 1:
            verified[h] = subgroups[0]
            continue

        split_group_count += 1
        for idx, subgroup in enumerate(subgroups, 1):
            key = h if idx == 1 else f"{h}::verify{idx}"
            while key in verified:
                idx += 1
                key = f"{h}::verify{idx}"
            verified[key] = subgroup

    if split_group_count > 0:
        logger.warning(
            "Strict verify split %d FILE hash group(s) due to byte mismatch",
            split_group_count,
        )

    return verified


def build_groups(
    dup_groups: dict[str, list[str]],
    size_map: dict[str, int],
    target_dir: str,
) -> list[dict]:
    """
    建構重複組的結構化資料。

    Returns:
        list of group dicts, 每個包含 keep 和 delete 資訊
    """
    groups = []

    for h, files in sorted(dup_groups.items(), key=lambda x: -len(x[1])):
        files_with_size = [(f, size_map.get(f, 0)) for f in files]
        # 先按大小遞減，再按路徑字典序，確保同大小時結果穩定可重現
        files_with_size.sort(key=lambda x: (-x[1], os.path.normcase(x[0])))

        keep_path, keep_size = files_with_size[0]
        delete_files = files_with_size[1:]

        group = {
            "hash": h,
            "keep": {
                "path": os.path.relpath(keep_path, target_dir),
                "size": keep_size,
            },
            "delete": [
                {
                    "path": os.path.relpath(dp, target_dir),
                    "size": ds,
                }
                for dp, ds in delete_files
            ],
        }
        groups.append(group)

    return groups


def write_json_report(
    groups: list[dict],
    total_files: int,
    target_dir: str,
    output_dir: str,
    settings: dict,
):
    """寫入 JSON 結構化報告"""
    total_dup = sum(len(g["delete"]) for g in groups)
    total_save = sum(
        sum(d["size"] for d in g["delete"])
        for g in groups
    )

    report = {
        "version": VERSION,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "target_dir": target_dir,
        "settings": settings,
        "summary": {
            "total_files": total_files,
            "duplicate_groups": len(groups),
            "deletable_files": total_dup,
            "space_saveable_bytes": total_save,
            "space_saveable": format_size(total_save),
            "files_remaining": total_files - total_dup,
        },
        "groups": groups,
    }

    json_path = os.path.join(output_dir, "duplicates_data.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    return report


def write_text_report(
    report_data: dict,
    output_dir: str,
):
    """從 JSON 資料生成可讀文字報告"""
    report_path = os.path.join(output_dir, "duplicates_report.txt")
    summary = report_data["summary"]

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("Duplicate File Report / 重複檔案掃描報告\n")
        f.write(f"Time: {report_data['scan_time']}\n")
        f.write(f"Directory: {report_data['target_dir']}\n")
        f.write("=" * 70 + "\n\n")

        for i, group in enumerate(report_data["groups"], 1):
            total_in_group = 1 + len(group["delete"])
            f.write(f"--- Group #{i} ({total_in_group} files) ---\n")
            f.write(
                f"  KEEP: {group['keep']['path']} "
                f"({format_size(group['keep']['size'])})\n"
            )
            for d in group["delete"]:
                f.write(
                    f"  DEL:  {d['path']} "
                    f"({format_size(d['size'])})\n"
                )
            group_save = sum(d["size"] for d in group["delete"])
            f.write(f"  Save: {format_size(group_save)}\n\n")

        f.write("=" * 70 + "\n")
        f.write("Summary\n")
        f.write("=" * 70 + "\n")
        f.write(f"Total files: {summary['total_files']}\n")
        f.write(f"Duplicate groups: {summary['duplicate_groups']}\n")
        f.write(f"Duplicate files (deletable): {summary['deletable_files']}\n")
        f.write(f"Space saveable: {summary['space_saveable']}\n")
        f.write(f"Files remaining: {summary['files_remaining']}\n")


def scan(
    target_dir: str,
    output_dir: str | None = None,
    use_pixel: bool = True,
    recursive: bool = True,
    strict_verify: bool = False,
    image_match: str = "hybrid",
    hamming_threshold: int = HAMMING_THRESHOLD,
    rms_threshold: float = RMS_THRESHOLD,
):
    """
    主掃描流程。

    Args:
        target_dir: 要掃描的資料夾路徑
        output_dir: 報告輸出路徑 (預設 = target_dir)
        use_pixel: 是否使用像素比對 (預設 True)
        recursive: 是否遞迴掃描子資料夾 (預設 True)
        strict_verify: 是否對 FILE hash 命中做 byte-by-byte 最終確認
        image_match: 圖片比對模式 ("exact", "similar", "hybrid")
        hamming_threshold: dHash Hamming distance 門檻
        rms_threshold: RMS 像素差門檻 (0-255)

    Raises:
        DirectoryNotFoundError: 目標資料夾不存在
        AccessDeniedError: 權限不足
    """

    if output_dir is None:
        output_dir = target_dir

    target_dir = os.path.abspath(target_dir)
    output_dir = os.path.abspath(output_dir)

    # 驗證參數（會拋出自訂例外）
    validate_scan_args(target_dir, output_dir)
    if image_match not in {"exact", "similar", "hybrid"}:
        raise InvalidParameterError(
            f"Invalid image_match: {image_match}. "
            "Must be one of: exact, similar, hybrid"
        )
    if hamming_threshold < 0:
        raise InvalidParameterError("hamming_threshold must be >= 0")
    if rms_threshold < 0:
        raise InvalidParameterError("rms_threshold must be >= 0")

    # --no-pixel 時圖片不走專屬流程，統一當檔案 MD5 比對。
    if not use_pixel and image_match != "exact":
        logger.warning(
            "use_pixel=False overrides image_match=%s to exact (file MD5 mode)",
            image_match,
        )
        image_match = "exact"

    settings = {
        "use_pixel": use_pixel,
        "recursive": recursive,
        "strict_verify": strict_verify,
        "image_match": image_match,
        "hamming_threshold": hamming_threshold,
        "rms_threshold": rms_threshold,
    }

    logger.info("=" * 50)
    logger.info("Photo Dedup -- Duplicate Scanner")
    logger.info("=" * 50)
    logger.info("Target:    %s", target_dir)
    logger.info("Output:    %s", output_dir)
    logger.info("Mode:      %s", 'Pixel comparison' if use_pixel else 'File MD5 only')
    logger.info("Image match: %s", image_match)
    logger.info("Recursive: %s", 'Yes' if recursive else 'No')
    logger.info("Strict verify FILE hash: %s", 'Yes' if strict_verify else 'No')

    # Step 1
    logger.info("[1/4] Collecting files...")
    all_files, collect_errors = collect_files(target_dir, recursive=recursive)
    logger.info("  Found %d files", len(all_files))

    if collect_errors:
        logger.warning("Skipped %d files due to errors:", len(collect_errors))
        for err in collect_errors[:5]:
            logger.warning("  %s", err)
        if len(collect_errors) > 5:
            logger.warning("  ... and %d more", len(collect_errors) - 5)

    if not all_files:
        logger.info("  No files to scan. Writing empty reports...")
        report_data = write_json_report(
            groups=[],
            total_files=0,
            target_dir=target_dir,
            output_dir=output_dir,
            settings=settings,
        )
        write_text_report(report_data, output_dir)
        logger.info("  JSON:   %s", os.path.join(output_dir, 'duplicates_data.json'))
        logger.info("  Report: %s", os.path.join(output_dir, 'duplicates_report.txt'))
        return

    # Step 2
    logger.info("[2/4] Categorizing...")
    image_candidates, non_image_candidates = categorize_files(all_files, use_pixel)

    total_to_hash = len(image_candidates) + (len(non_image_candidates) * 2)
    if image_match == "similar":
        image_mode_label = "similar matching"
    elif image_match == "hybrid":
        image_mode_label = "hybrid matching"
    else:
        image_mode_label = "exact pixel hash"
    logger.info("  Images (%s): %d", image_mode_label, len(image_candidates))
    logger.info(
        "  Non-images (size-matched candidates): %d",
        len(non_image_candidates),
    )
    logger.info("  Estimated upper-bound hash operations: %d", total_to_hash)

    # HEIC support
    if use_pixel:
        heic_ok = init_heic_support()
        logger.info(
            "  HEIC support: %s",
            'OK' if heic_ok else 'NOT AVAILABLE (will use file MD5)',
        )

    # Step 3
    logger.info("[3/4] Computing hashes...")
    hash_groups, size_map = compute_hashes(
        image_candidates, non_image_candidates, use_pixel,
        image_match=image_match,
        hamming_threshold=hamming_threshold,
        rms_threshold=rms_threshold,
    )

    if strict_verify:
        logger.info("[3.5/4] Strict verifying FILE hash groups...")
        hash_groups = strict_verify_file_hash_groups(hash_groups, size_map)

    # Step 4
    logger.info("[4/4] Generating reports...")
    dup_groups = {
        h: files for h, files in hash_groups.items() if len(files) > 1
    }

    groups = build_groups(dup_groups, size_map, target_dir)
    report_data = write_json_report(
        groups, len(all_files), target_dir, output_dir, settings
    )
    write_text_report(report_data, output_dir)

    summary = report_data["summary"]
    logger.info("")
    logger.info("=" * 50)
    logger.info("DONE!")
    logger.info("  Total files:         %d", summary['total_files'])
    logger.info("  Duplicate groups:    %d", summary['duplicate_groups'])
    logger.info("  Deletable:           %d", summary['deletable_files'])
    logger.info("  Space saveable:      %s", summary['space_saveable'])
    logger.info("  Remaining:           %d", summary['files_remaining'])
    logger.info("")
    logger.info("  JSON:   %s", os.path.join(output_dir, 'duplicates_data.json'))
    logger.info("  Report: %s", os.path.join(output_dir, 'duplicates_report.txt'))
    logger.info("")
    logger.info("Review the report, then run: python clean.py --dir <DIR>")
