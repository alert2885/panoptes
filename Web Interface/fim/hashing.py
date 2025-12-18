"""SHA256 hashing utilities"""
import hashlib
import os
from typing import Optional


def compute_hash(file_path: str) -> Optional[str]:
    """Compute SHA256 hash of a file
    
    Args:
        file_path: Path to the file
    
    Returns:
        Hex digest of SHA256 hash, or None if file cannot be read
    """
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return None
    
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (IOError, OSError, PermissionError):
        return None






