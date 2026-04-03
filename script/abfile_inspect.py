#!/usr/bin/env python3
import argparse
import base64
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterator, List, Optional, Tuple


def base64url_decode_to_bytes(b64url_string: str) -> bytes:
    padding = "=" * (-len(b64url_string) % 4)
    return base64.urlsafe_b64decode(b64url_string + padding)


def base64url_decode_str(b64url_string: str) -> str:
    return base64url_decode_to_bytes(b64url_string).decode("utf-8")


def _decoded_len_b64url(seg: str) -> int:
    padding = "=" * (-len(seg) % 4)
    return len(base64.urlsafe_b64decode(seg + padding))


def try_decode_filename(name: str) -> Optional[str]:
    try:
        return base64url_decode_str(name)
    except Exception:
        return None


_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")  # empty allowed (for detached JWS payload)


def _is_b64url(s: str) -> bool:
    return bool(_B64URL_RE.fullmatch(s))


def _decode_json_segment(segment: str) -> Optional[dict]:
    try:
        return json.loads(base64url_decode_to_bytes(segment).decode("utf-8"))
    except Exception:
        return None


def _classify_compact_jwt(compact: str) -> Tuple[Optional[dict], Optional[str]]:
    """
    Returns (parsed_obj, type_label) for compact JOSE forms:
      - JWS (3 parts): {"jws": {"header": {...}, "payload": <obj|str>, "sig_len": int, "detached": bool}}
      - JWE (5 parts): {"jwe": {"protected": {...}, "parts": 5, "note": "..."}}
    If not JWT-like, returns (None, None).
    """
    s = compact.strip()
    if not s:
        return None, None

    parts = s.split(".")
    if len(parts) not in (3, 5):
        return None, None

    # All parts must be base64url (payload may be empty for detached JWS)
    if not all(_is_b64url(p) for p in parts):
        return None, None

    # Decode protected header
    header = _decode_json_segment(parts[0])
    if header is None:
        return None, None

    typ = header.get("typ")

    if len(parts) == 3:
        # JWS: header SHOULD have "alg"
        if "alg" not in header:
            return None, None

        detached = parts[1] == ""
        payload_obj = None if detached else _decode_json_segment(parts[1])
        payload_repr = (
            payload_obj
            if payload_obj is not None
            else ("[detached]" if detached else "[non-JSON payload]")
        )

        try:
            sig_len = _decoded_len_b64url(parts[2])
        except Exception:
            return None, None

        label = (
            f"JWT (JWS{', typ='+typ if typ else ''}{', detached' if detached else ''})"
        )
        return {
            "jws": {
                "header": header,
                "payload": payload_repr,
                "sig_len": sig_len,
                "detached": detached,
            }
        }, label

    # len(parts) == 5 -> JWE: header SHOULD have "enc"
    if "enc" not in header:
        return None, None

    label = f"JWT (JWE{', typ='+typ if typ else ''})"
    return {
        "jwe": {
            "protected": header,
            "parts": 5,
            "note": "Compact JWE; content not decrypted or verified.",
        }
    }, label


def parse_content_text(text: str) -> Tuple[dict, str]:
    """
    Decide between JSON vs Compact JWT vs Other. No signature verification.
    JSON is attempted first. If the JSON is a string that looks like compact JOSE,
    classify that token instead.
    Returns (parsed_object, label).
    """
    s = text.strip()
    # Try full JSON first
    try:
        obj = json.loads(s)
    except json.JSONDecodeError:
        obj = None

    if obj is not None:
        # If content is a JSON *string* holding a compact JOSE value, decode it.
        if isinstance(obj, str):
            parsed, label = _classify_compact_jwt(obj)
            if parsed is not None:
                return parsed, f"{label} (wrapped in JSON string)"
        return obj, "JSON"

    # Not JSON. Try compact JOSE next.
    parsed, label = _classify_compact_jwt(s)
    if parsed is not None:
        return parsed, label

    # 3) Fallback
    return {"error": "Unrecognized content (not JSON and not compact JWT)."}, "Other"


def iter_entity_files(root: Path) -> Iterator[Tuple[Path, str]]:
    """
    Yield (file_path, decoded_label) for files whose basename is base64url-decodable.
    Skips files ending in '.lock'.
    """
    if root.is_file():
        name = root.name
        if name.endswith(".lock"):
            return
        decoded = try_decode_filename(name)
        if decoded is not None:
            yield root, decoded
        return

    if root.is_dir():
        for dirpath, _, filenames in os.walk(root, followlinks=False):
            for fname in filenames:
                if fname.endswith(".lock"):
                    continue
                decoded = try_decode_filename(fname)
                if decoded is None:
                    continue
                p = Path(dirpath) / fname
                if p.is_file():
                    yield p, decoded


def list_files_only(files: List[Tuple[Path, str]]) -> None:
    for p, decoded in sorted(files, key=lambda x: str(x[0])):
        print(f"{str(p)} -> {decoded}")


def describe_file(path: Path, decoded_label: str, max_bytes: int) -> None:
    print(f"Path: {path}")
    print(f"  Decoded label: {decoded_label}")

    try:
        size = path.stat().st_size
    except Exception:
        size = None
    print(f"  Size: {size} bytes" if size is not None else "  Size: [unknown]")

    # Read up to max_bytes for safety
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        truncated = size is not None and size > max_bytes
        text = data.decode("utf-8", errors="replace")
        parsed, fmt = parse_content_text(text)
        print(f"  Parsed as: {fmt}")
        if truncated:
            print(f"  [NOTE] Content truncated to --max-bytes={max_bytes} for safety.")
        print(json.dumps(parsed, indent=2, ensure_ascii=False))
    except Exception as e:
        print("  Parsed as: Other")
        print(json.dumps({"error": str(e)}, indent=2))
    print("-" * 80)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "List and inspect AbstractFileSystem files stored on the local filesystem."
            "A file is included if its basename is base64url-decodable to UTF-8."
            "False positives are expected.To reduce noise, scope the input directory "
            "at the shell level or use --list and post-filter with standard tools like grep, awk, or jq."
        )
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to scan or inspect (file or directory)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Only list base64url-decodable filenames with their decoded labels",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=1_000_000,
        help="Max bytes to read from a file for inspection (default: 1MB)",
    )
    args = parser.parse_args()

    root = Path(args.path)

    if not (root.exists() or root.is_file()):
        print(f"Path does not exist or is not accessible: {args.path}", file=sys.stderr)
        sys.exit(1)

    if root.is_file():
        name = root.name
        if name.endswith(".lock"):
            print(f"Skipping lock file: {str(root)}", file=sys.stderr)
            sys.exit(1)
        decoded = try_decode_filename(name)
        if decoded is None:
            print(f"Not a base64url-decodable filename: {str(root)}", file=sys.stderr)
            sys.exit(1)
        if args.list:
            list_files_only([(root, decoded)])
        else:
            describe_file(root, decoded, args.max_bytes)
        return

    entries = list(iter_entity_files(root))
    if args.list:
        list_files_only(entries)
    else:
        print(f"Scanning for base64url-decodable filenames under: {args.path}\n")
        for p, decoded in sorted(entries, key=lambda x: str(x[0])):
            describe_file(p, decoded, args.max_bytes)


if __name__ == "__main__":
    main()
