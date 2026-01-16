"""
Common utility functions for the Malware Analysis Platform.
"""

import os
import hashlib
from pathlib import Path
from typing import Any, Iterator, List, Optional, Union
from datetime import datetime

# Optional dependency
try:
    import humanize
    HUMANIZE_AVAILABLE = True
except ImportError:
    HUMANIZE_AVAILABLE = False


def format_bytes(size: int) -> str:
    """
    Format byte size to human readable string.

    Args:
        size: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    if HUMANIZE_AVAILABLE:
        return humanize.naturalsize(size, binary=True)

    # Fallback implementation
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    size_float = float(size)

    while size_float >= 1024 and unit_index < len(units) - 1:
        size_float /= 1024
        unit_index += 1

    if unit_index == 0:
        return f"{int(size_float)} {units[unit_index]}"
    return f"{size_float:.2f} {units[unit_index]}"


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """
    Format datetime to ISO format.

    Args:
        dt: Datetime object (default: now)

    Returns:
        ISO formatted string
    """
    if dt is None:
        dt = datetime.now()
    return dt.isoformat()


def format_hex(value: int, width: int = 8) -> str:
    """
    Format integer as hexadecimal string.

    Args:
        value: Integer value
        width: Minimum width with zero padding

    Returns:
        Hex string (e.g., "0x00401000")
    """
    return f"0x{value:0{width}X}"


def chunk_iterator(
    data: bytes,
    chunk_size: int = 4096,
) -> Iterator[tuple]:
    """
    Iterate over data in chunks.

    Args:
        data: Byte data to iterate
        chunk_size: Size of each chunk

    Yields:
        Tuple of (offset, chunk_data)
    """
    for offset in range(0, len(data), chunk_size):
        yield offset, data[offset:offset + chunk_size]


def calculate_hash(data: bytes, algorithm: str = "sha256") -> str:
    """
    Calculate hash of data.

    Args:
        data: Byte data to hash
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)

    Returns:
        Hex digest string
    """
    hasher = hashlib.new(algorithm)
    hasher.update(data)
    return hasher.hexdigest()


def is_printable_string(data: bytes, min_length: int = 4) -> bool:
    """
    Check if byte data represents a printable ASCII string.

    Args:
        data: Byte data to check
        min_length: Minimum length requirement

    Returns:
        True if printable ASCII string
    """
    if len(data) < min_length:
        return False
    return all(32 <= b < 127 for b in data)


def extract_strings(
    data: bytes,
    min_length: int = 4,
    include_unicode: bool = True,
) -> List[tuple]:
    """
    Extract ASCII and Unicode strings from binary data.

    Args:
        data: Binary data
        min_length: Minimum string length
        include_unicode: Include Unicode strings

    Returns:
        List of (offset, string, encoding) tuples
    """
    strings = []

    # ASCII strings
    current_string = b""
    start_offset = 0

    for i, byte in enumerate(data):
        if 32 <= byte < 127:
            if not current_string:
                start_offset = i
            current_string += bytes([byte])
        else:
            if len(current_string) >= min_length:
                strings.append((
                    start_offset,
                    current_string.decode("ascii"),
                    "ascii",
                ))
            current_string = b""

    # Handle string at end of data
    if len(current_string) >= min_length:
        strings.append((
            start_offset,
            current_string.decode("ascii"),
            "ascii",
        ))

    # Unicode strings (UTF-16LE)
    if include_unicode:
        current_string = b""
        start_offset = 0

        for i in range(0, len(data) - 1, 2):
            char = data[i:i + 2]
            if char[1] == 0 and 32 <= char[0] < 127:
                if not current_string:
                    start_offset = i
                current_string += char
            else:
                if len(current_string) >= min_length * 2:
                    try:
                        decoded = current_string.decode("utf-16-le")
                        strings.append((start_offset, decoded, "utf-16-le"))
                    except UnicodeDecodeError:
                        pass
                current_string = b""

        if len(current_string) >= min_length * 2:
            try:
                decoded = current_string.decode("utf-16-le")
                strings.append((start_offset, decoded, "utf-16-le"))
            except UnicodeDecodeError:
                pass

    return sorted(strings, key=lambda x: x[0])


def safe_path(path: Union[str, Path]) -> Path:
    """
    Safely resolve path, expanding user directory and normalizing.

    Args:
        path: Path string or Path object

    Returns:
        Resolved Path object
    """
    return Path(path).expanduser().resolve()


def ensure_directory(path: Union[str, Path]) -> Path:
    """
    Ensure directory exists, creating if necessary.

    Args:
        path: Directory path

    Returns:
        Path object
    """
    dir_path = safe_path(path)
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path


def get_file_type_icon(file_type: str) -> str:
    """
    Get icon character for file type.

    Args:
        file_type: File type string

    Returns:
        Unicode icon character
    """
    icons = {
        "pe": "🪟",
        "elf": "🐧",
        "macho": "🍎",
        "pdf": "📄",
        "office": "📊",
        "archive": "📦",
        "script": "📜",
        "unknown": "❓",
    }

    file_type_lower = file_type.lower()

    if "pe" in file_type_lower or "exe" in file_type_lower or "dll" in file_type_lower:
        return icons["pe"]
    elif "elf" in file_type_lower:
        return icons["elf"]
    elif "mach" in file_type_lower:
        return icons["macho"]
    elif "pdf" in file_type_lower:
        return icons["pdf"]
    elif any(x in file_type_lower for x in ["zip", "rar", "tar", "gz"]):
        return icons["archive"]
    elif any(x in file_type_lower for x in ["script", "python", "javascript", "batch"]):
        return icons["script"]

    return icons["unknown"]


def truncate_string(s: str, max_length: int = 50, suffix: str = "...") -> str:
    """
    Truncate string to maximum length.

    Args:
        s: String to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated

    Returns:
        Truncated string
    """
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


def bytes_to_hex_string(data: bytes, separator: str = " ") -> str:
    """
    Convert bytes to hex string.

    Args:
        data: Byte data
        separator: Separator between bytes

    Returns:
        Hex string (e.g., "4D 5A 90 00")
    """
    return separator.join(f"{b:02X}" for b in data)


def hex_string_to_bytes(hex_str: str) -> bytes:
    """
    Convert hex string to bytes.

    Args:
        hex_str: Hex string (with or without separators)

    Returns:
        Byte data
    """
    # Remove common separators
    cleaned = hex_str.replace(" ", "").replace("-", "").replace(":", "")
    return bytes.fromhex(cleaned)
