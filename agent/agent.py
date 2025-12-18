"""
agent.py — Panoptes FIM Agent (Windows)

Features:
- Multi watch roots: watch_dirs (fallback watch_dir)
- Exclusions: exclude_dirs (absolute paths), exclude_globs (glob patterns), ignore_patterns (glob patterns)
- Local state: hashes.json + hash_history.json
- Central reporting: /fim/event over HTTPS mTLS + API key
- Remote management: /fim/agent/heartbeat over HTTPS mTLS + API key
- Runtime config:
    - Stored in runtime_config.json (server snapshot + version)
    - Also merged into config.json (effective config persisted)  <-- requested
"""

import os
import json
import time
import socket
import getpass
import hashlib
import uuid
from bdb import effective
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple

import fnmatch
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import win32security
import win32con
from PIL import Image
from PIL.ExifTags import TAGS

try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

try:
    import docx
except ImportError:
    docx = None


# ============================
# Config (bootstrap)
# ============================

CONFIG_PATH = r"config.json"

# Keys that MUST NOT be overridden by runtime config coming from server
PROTECTED_KEYS = {
    "api_key",
    "ca_cert",
    "client_cert",
    "client_key",
    "central_api_url",
    "agent_id",
}


def load_config(path: str = CONFIG_PATH) -> dict:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(cfg: dict, path: str = CONFIG_PATH):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


config = load_config()

ENDPOINT = config.get("endpoint", "local")
AGENT_ID = config.get("agent_id", socket.gethostname())

# Multi-root (preferred)
WATCH_DIRS = config.get("watch_dirs")
# Backward compatibility
if not WATCH_DIRS:
    WATCH_DIRS = [config.get("watch_dir", r"C:\Users\Public")]

CENTRAL_API_URL = config.get("central_api_url")
API_KEY = config.get("api_key")

CA_CERT = config.get("ca_cert")
CLIENT_CERT = config.get("client_cert")
CLIENT_KEY = config.get("client_key")

DEBUG_HTTP = bool(config.get("debug_http", False))

CHUNK_SIZE = int(config.get("chunk_size", 4096))
CHUNK_MAX_BYTES = int(config.get("chunk_max_bytes", 10 * 1024 * 1024))

HEARTBEAT_INTERVAL = int(config.get("heartbeat_interval", 60))
HEARTBEAT_URL = config.get("heartbeat_url")

# Bootstrap exclusions
EXCLUDE_DIRS = config.get("exclude_dirs", [])
EXCLUDE_GLOBS = config.get("exclude_globs", [])
# Bootstrap ignore patterns
BOOTSTRAP_IGNORE_PATTERNS = config.get("ignore_patterns", [])

HOSTNAME = socket.gethostname()
USERNAME = getpass.getuser()


# ============================
# Timezone handling
# ============================

AGENT_TZ_STR = config.get("timezone", "+00:00")


def parse_tz_offset(tz_str: str) -> timezone:
    s = (tz_str or "").strip().upper()
    if s in ("UTC", "Z"):
        return timezone.utc
    try:
        sign = 1
        if s[0] == "-":
            sign = -1
            s = s[1:]
        elif s[0] == "+":
            s = s[1:]
        hours_str, minutes_str = s.split(":")
        offset = timedelta(hours=int(hours_str), minutes=int(minutes_str)) * sign
        return timezone(offset)
    except Exception:
        return timezone.utc


AGENT_TZ = parse_tz_offset(AGENT_TZ_STR)


def now_agent_iso() -> str:
    return datetime.now(AGENT_TZ).isoformat()


# ============================
# Local DB files (JSON)
# ============================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HASH_DB_FILE = os.path.join(BASE_DIR, "hashes.json")
HISTORY_DB_FILE = os.path.join(BASE_DIR, "hash_history.json")

# Runtime config (from central server)
RUNTIME_CONFIG_PATH = os.path.join(BASE_DIR, "runtime_config.json")
CURRENT_CONFIG_VERSION = 0

# Runtime ignore/exclusions (from server)
RUNTIME_IGNORE_PATTERNS: List[str] = []
RUNTIME_EXCLUDE_DIRS: List[str] = []
RUNTIME_EXCLUDE_GLOBS: List[str] = []


def load_json(path: str):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


def save_json(obj: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


# ============================
# Runtime config helpers
# ============================

def load_runtime_state() -> Tuple[Dict[str, Any], int]:
    """
    runtime_config.json structure:
    {
      "config_version": int,
      "config": { ...server-controlled keys... }
    }
    """
    if not os.path.exists(RUNTIME_CONFIG_PATH):
        return {}, 0
    try:
        with open(RUNTIME_CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return {}, 0
    cfg = data.get("config", {}) or {}
    ver = int(data.get("config_version", 0) or 0)
    return cfg, ver


def save_runtime_state(cfg: Dict[str, Any], version: int):
    save_json({"config_version": int(version), "config": cfg}, RUNTIME_CONFIG_PATH)


def normalize_paths_list(items: Any) -> List[str]:
    if not items:
        return []
    if isinstance(items, str):
        return [os.path.abspath(items)]
    if isinstance(items, list):
        out = []
        for x in items:
            if isinstance(x, str) and x.strip():
                out.append(os.path.abspath(x))
        return out
    return []


def merge_runtime_into_config_json(runtime_cfg: Dict[str, Any]):
    """
    Merge server runtime config into local config.json (effective config),
    while respecting PROTECTED_KEYS.
    """
    global config
    if not isinstance(runtime_cfg, dict):
        return

    merged = dict(config)
    for k, v in runtime_cfg.items():
        if k in PROTECTED_KEYS:
            continue
        merged[k] = v

    # Backward-compat: if server sends watch_dirs, remove watch_dir to avoid confusion
    if "watch_dirs" in merged and "watch_dir" in merged:
        try:
            merged.pop("watch_dir", None)
        except Exception:
            pass

    config = merged
    save_config(config, CONFIG_PATH)


def apply_runtime_config(cfg: Dict[str, Any], version: Optional[int] = None, allow_watch_dir_update: bool = True):
    """
    Apply runtime config values on top of bootstrap config.
    watch_dirs changes can be applied on startup; during periodic heartbeat we store but require restart.
    """
    global WATCH_DIRS, AGENT_TZ_STR, AGENT_TZ, CHUNK_SIZE, CHUNK_MAX_BYTES
    global CURRENT_CONFIG_VERSION, RUNTIME_IGNORE_PATTERNS, RUNTIME_EXCLUDE_DIRS, RUNTIME_EXCLUDE_GLOBS
    global EXCLUDE_DIRS, EXCLUDE_GLOBS, BOOTSTRAP_IGNORE_PATTERNS

    if not isinstance(cfg, dict):
        return

    # Persist as effective config too (requested)
    merge_runtime_into_config_json(cfg)

    if "timezone" in cfg:
        AGENT_TZ_STR = str(cfg["timezone"])
        AGENT_TZ = parse_tz_offset(AGENT_TZ_STR)
        print(f"[*] Runtime config: timezone -> {AGENT_TZ_STR} ({AGENT_TZ})")

    if "chunk_size" in cfg:
        try:
            CHUNK_SIZE = int(cfg["chunk_size"])
            print(f"[*] Runtime config: chunk_size -> {CHUNK_SIZE}")
        except Exception:
            print("[!] Runtime config: invalid chunk_size, ignoring")

    if "chunk_max_bytes" in cfg:
        try:
            CHUNK_MAX_BYTES = int(cfg["chunk_max_bytes"])
            print(f"[*] Runtime config: chunk_max_bytes -> {CHUNK_MAX_BYTES}")
        except Exception:
            print("[!] Runtime config: invalid chunk_max_bytes, ignoring")

    # ignore_patterns can exist in bootstrap and runtime; runtime appends/overrides via RUNTIME_IGNORE_PATTERNS
    if "ignore_patterns" in cfg and isinstance(cfg["ignore_patterns"], list):
        RUNTIME_IGNORE_PATTERNS = [str(x) for x in cfg["ignore_patterns"] if isinstance(x, str)]
        print(f"[*] Runtime config: ignore_patterns -> {RUNTIME_IGNORE_PATTERNS}")

    if "exclude_dirs" in cfg and isinstance(cfg["exclude_dirs"], list):
        RUNTIME_EXCLUDE_DIRS = [str(x) for x in cfg["exclude_dirs"] if isinstance(x, str)]
        print(f"[*] Runtime config: exclude_dirs -> {RUNTIME_EXCLUDE_DIRS}")

    if "exclude_globs" in cfg and isinstance(cfg["exclude_globs"], list):
        RUNTIME_EXCLUDE_GLOBS = [str(x) for x in cfg["exclude_globs"] if isinstance(x, str)]
        print(f"[*] Runtime config: exclude_globs -> {RUNTIME_EXCLUDE_GLOBS}")

    # Preferred: watch_dirs
    if "watch_dirs" in cfg:
        if allow_watch_dir_update:
            if isinstance(cfg["watch_dirs"], list):
                WATCH_DIRS = cfg["watch_dirs"]
            else:
                WATCH_DIRS = [cfg["watch_dirs"]]
            print(f"[*] Runtime config: watch_dirs -> {WATCH_DIRS}")
        else:
            print("[*] Runtime config: received new watch_dirs, will apply on next restart")

    # Backward compatibility: watch_dir
    elif "watch_dir" in cfg:
        if allow_watch_dir_update:
            WATCH_DIRS = [cfg["watch_dir"]]
            print(f"[*] Runtime config: watch_dir -> {WATCH_DIRS[0]}")
        else:
            print("[*] Runtime config: received new watch_dir, will apply on next restart")

    if version is not None:
        CURRENT_CONFIG_VERSION = int(version)
        print(f"[*] Runtime config: version -> {CURRENT_CONFIG_VERSION}")


# ============================
# Ignore / exclusion logic
# ============================

def is_temp_file(path: str) -> bool:
    filename = os.path.basename(path)
    return filename.endswith("~")


def is_excluded_dir(path: str) -> bool:
    p = os.path.abspath(path)

    ex_dirs = normalize_paths_list(EXCLUDE_DIRS) + normalize_paths_list(RUNTIME_EXCLUDE_DIRS)
    for ex in ex_dirs:
        if p == ex or p.startswith(ex + os.sep):
            return True
    return False


def is_excluded_glob(path: str) -> bool:
    name = os.path.basename(path)

    patterns: List[str] = []
    if isinstance(EXCLUDE_GLOBS, list):
        patterns += [str(x) for x in EXCLUDE_GLOBS if isinstance(x, str)]
    # ignore patterns: bootstrap + runtime + runtime exclude globs
    if isinstance(BOOTSTRAP_IGNORE_PATTERNS, list):
        patterns += [str(x) for x in BOOTSTRAP_IGNORE_PATTERNS if isinstance(x, str)]
    patterns += RUNTIME_IGNORE_PATTERNS
    patterns += RUNTIME_EXCLUDE_GLOBS

    for pat in patterns:
        if pat and fnmatch.fnmatch(name, pat):
            return True
    return False


def should_ignore_path(path: str) -> bool:
    if is_temp_file(path):
        return True
    if is_excluded_dir(path):
        return True
    if is_excluded_glob(path):
        return True
    return False


# ============================
# Central server sender (events)
# ============================

def send_event_to_central(event: dict):
    if not CENTRAL_API_URL or not API_KEY:
        print("[!] CENTRAL_API_URL or API_KEY not set, skipping send.")
        return
    if not CA_CERT or not CLIENT_CERT or not CLIENT_KEY:
        print("[!] mTLS cert paths not configured, not sending event")
        return

    headers = {"X-API-Key": API_KEY}

    try:
        resp = requests.post(
            CENTRAL_API_URL,
            json=event,
            headers=headers,
            timeout=10,
            cert=(CLIENT_CERT, CLIENT_KEY),
            verify=CA_CERT,
        )

        print(f"[>] Sent event to central ({resp.status_code})")

        if DEBUG_HTTP or not resp.ok:
            try:
                body = resp.json()
            except ValueError:
                body = resp.text
            print("    [HTTP DEBUG] URL:   ", CENTRAL_API_URL)
            print("    [HTTP DEBUG] Status:", resp.status_code)
            print("    [HTTP DEBUG] Body:  ", body)

    except Exception as e:
        print(f"[!] Failed to send event to central: {e}")


# ============================
# Heartbeat / remote management
# ============================

def get_heartbeat_url() -> Optional[str]:
    global HEARTBEAT_URL
    if HEARTBEAT_URL:
        return HEARTBEAT_URL
    if not CENTRAL_API_URL:
        return None
    if "/fim/event" in CENTRAL_API_URL:
        HEARTBEAT_URL = CENTRAL_API_URL.replace("/fim/event", "/fim/agent/heartbeat")
    else:
        HEARTBEAT_URL = CENTRAL_API_URL.rstrip("/") + "/fim/agent/heartbeat"
    return HEARTBEAT_URL


def agent_heartbeat(periodic: bool = False):
    hb_url = get_heartbeat_url()
    if not hb_url:
        print("[HB] No heartbeat URL available; skipping.")
        return
    if not API_KEY:
        print("[HB] API_KEY not set; skipping.")
        return
    if not CA_CERT or not CLIENT_CERT or not CLIENT_KEY:
        print("[HB] mTLS cert paths not configured; skipping.")
        return

    payload = {
        "agent_id": AGENT_ID,
        "hostname": HOSTNAME,
        "endpoint": ENDPOINT,
        "agent_version": "1.0.0",
        "current_config_version": CURRENT_CONFIG_VERSION or 0,
    }
    headers = {"X-API-Key": API_KEY}

    try:
        resp = requests.post(
            hb_url,
            json=payload,
            headers=headers,
            timeout=10,
            cert=(CLIENT_CERT, CLIENT_KEY),
            verify=CA_CERT,
        )

        if DEBUG_HTTP or not resp.ok:
            try:
                body = resp.json()
            except ValueError:
                body = resp.text
            print("[HB] Status:", resp.status_code)
            print("[HB] Body:", body)

        resp.raise_for_status()
        data = resp.json() if resp.content else {}

        # New config?
        new_cfg_ver = data.get("config_version")
        new_cfg = data.get("config")

        if new_cfg_ver is not None and new_cfg is not None:
            print(f"[HB] Received new config version {new_cfg_ver}")

            # Save server snapshot
            save_runtime_state(new_cfg, int(new_cfg_ver))

            # Apply + persist effective config.json
            allow_watch_dir = not periodic
            apply_runtime_config(new_cfg, int(new_cfg_ver), allow_watch_dir_update=allow_watch_dir)

            if periodic and ("watch_dir" in new_cfg or "watch_dirs" in new_cfg):
                print("[HB] NOTE: watch_dir(s) change received; will apply on next agent restart")

        # Commands (optional)
        commands = data.get("commands", []) or []
        for cmd in commands:
            cmd_id = cmd.get("id")
            cmd_type = cmd.get("command_type")
            cmd_payload = cmd.get("payload", {}) or {}

            print(f"[HB] Received command id={cmd_id}, type={cmd_type}, payload={cmd_payload}")

            if cmd_type == "baseline_scan":
                try:
                    for d in normalize_paths_list(WATCH_DIRS):
                        print(f"[HB] Executing baseline_scan via command on: {d}")
                        baseline_scan(d)
                except Exception as e:
                    print(f"[HB] baseline_scan command failed: {e}")
            elif cmd_type == "noop":
                pass
            else:
                print(f"[HB] Unknown command_type={cmd_type}, ignoring")

    except Exception as e:
        print(f"[HB] Heartbeat failed: {e}")


# ============================
# Hashing & metadata
# ============================

def sha256_string(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def get_file_content_hash(path: str) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


def get_owner(path: str) -> str:
    sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)
    owner_sid = sd.GetSecurityDescriptorOwner()
    name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
    return f"{domain}\\{name}"


def get_filesystem_metadata(path: str) -> Dict[str, Any]:
    stats = os.stat(path)
    return {
        "size": stats.st_size,
        "created": stats.st_ctime,
        "modified": stats.st_mtime,
        "accessed": stats.st_atime,  # kept in metadata but excluded from combined_hash
        "owner": get_owner(path),
        "attributes": {
            "read_only": bool(stats.st_file_attributes & win32con.FILE_ATTRIBUTE_READONLY),
            "hidden": bool(stats.st_file_attributes & win32con.FILE_ATTRIBUTE_HIDDEN),
            "system": bool(stats.st_file_attributes & win32con.FILE_ATTRIBUTE_SYSTEM),
        },
    }


def get_exif_metadata(path: str) -> Optional[Dict[str, Any]]:
    try:
        img = Image.open(path)
        exif_data = img._getexif()
        if not exif_data:
            return None
        readable = {}
        for tag, value in exif_data.items():
            key = TAGS.get(tag, tag)
            readable[key] = str(value)
        return readable
    except Exception:
        return None


def get_pdf_metadata(path: str) -> Optional[Dict[str, Any]]:
    if not PyPDF2:
        return None
    try:
        with open(path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            meta = reader.metadata
            if not meta:
                return None
            return {k: str(v) for k, v in meta.items()}
    except Exception:
        return None


def get_docx_metadata(path: str) -> Optional[Dict[str, Any]]:
    if not docx:
        return None
    try:
        d = docx.Document(path)
        props = d.core_properties
        metadata = {attr: str(getattr(props, attr)) for attr in dir(props) if not attr.startswith("_")}
        return metadata if metadata else None
    except Exception:
        return None


def get_embedded_metadata(path: str) -> Optional[Dict[str, Any]]:
    ext = os.path.splitext(path)[1].lower()
    if ext in [".jpg", ".jpeg", ".png", ".tiff"]:
        return get_exif_metadata(path)
    if ext == ".pdf":
        return get_pdf_metadata(path)
    if ext == ".docx":
        return get_docx_metadata(path)
    return None


def get_embedded_metadata_hash(metadata: Optional[Dict[str, Any]]) -> Optional[str]:
    if not metadata:
        return None
    return sha256_string(json.dumps(metadata, sort_keys=True))


def get_combined_hash(content_hash: str, fs_metadata: Dict[str, Any], embedded_metadata: Optional[Dict[str, Any]]) -> str:
    fs_meta_for_hash = dict(fs_metadata)
    fs_meta_for_hash.pop("accessed", None)  # exclude atime from integrity
    combined = {
        "content_hash": content_hash,
        "filesystem_metadata": fs_meta_for_hash,
        "embedded_metadata": embedded_metadata,
    }
    return sha256_string(json.dumps(combined, sort_keys=True))


def get_all_hashes(path: str) -> Dict[str, Any]:
    ts = now_agent_iso()
    content_hash = get_file_content_hash(path)
    fs_metadata = get_filesystem_metadata(path)
    embedded_metadata = get_embedded_metadata(path)

    embedded_hash = get_embedded_metadata_hash(embedded_metadata)
    fs_hash = sha256_string(json.dumps(fs_metadata, sort_keys=True))
    combined_hash = get_combined_hash(content_hash, fs_metadata, embedded_metadata)

    return {
        "path": os.path.abspath(path),
        "timestamp": ts,
        "current_user": getpass.getuser(),
        "machine": socket.gethostname(),
        "content_hash": content_hash,
        "filesystem_hash": fs_hash,
        "embedded_metadata_hash": embedded_hash,
        "combined_hash": combined_hash,
        "filesystem_metadata": fs_metadata,
        "embedded_metadata": embedded_metadata,
    }


# ============================
# Chunk hashing & diff
# ============================

def compute_chunk_hashes(path: str, chunk_size: int = None, max_bytes: int = None) -> Optional[Dict[str, Any]]:
    chunk_size = int(chunk_size or CHUNK_SIZE)
    max_bytes = int(max_bytes or CHUNK_MAX_BYTES)

    file_size = os.path.getsize(path)
    if file_size == 0:
        return {"chunk_size": chunk_size, "total_chunks": 0, "hashes": []}

    if file_size > max_bytes:
        return None

    hashes: List[str] = []
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hashes.append(hashlib.sha256(chunk).hexdigest())

    return {"chunk_size": chunk_size, "total_chunks": len(hashes), "hashes": hashes}


def compute_chunk_diff(old_chunks: Optional[Dict[str, Any]], new_chunks: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not new_chunks:
        return None

    new_hashes = new_chunks.get("hashes", [])
    new_size = new_chunks.get("chunk_size")

    if not old_chunks:
        return {
            "chunk_size": new_size,
            "total_old": 0,
            "total_new": len(new_hashes),
            "changed": [],
            "added": list(range(len(new_hashes))),
            "removed": [],
        }

    old_hashes = old_chunks.get("hashes", [])
    old_size = old_chunks.get("chunk_size")

    if old_size != new_size:
        return {
            "chunk_size": new_size,
            "total_old": len(old_hashes),
            "total_new": len(new_hashes),
            "changed": list(range(0, max(len(old_hashes), len(new_hashes)))),
            "added": [],
            "removed": [],
        }

    min_len = min(len(old_hashes), len(new_hashes))
    changed = [i for i in range(min_len) if old_hashes[i] != new_hashes[i]]

    added, removed = [], []
    if len(new_hashes) > len(old_hashes):
        added = list(range(len(old_hashes), len(new_hashes)))
    elif len(old_hashes) > len(new_hashes):
        removed = list(range(len(new_hashes), len(old_hashes)))

    if not changed and not added and not removed:
        return None

    return {
        "chunk_size": new_size,
        "total_old": len(old_hashes),
        "total_new": len(new_hashes),
        "changed": changed,
        "added": added,
        "removed": removed,
    }


def compute_snapshot(path: str, file_uid: str) -> Dict[str, Any]:
    snap = get_all_hashes(path)
    snap["file_uid"] = file_uid
    snap["file_size"] = snap["filesystem_metadata"]["size"]

    chunks = compute_chunk_hashes(path, CHUNK_SIZE, CHUNK_MAX_BYTES)
    if chunks is not None:
        snap["chunks"] = chunks

    return snap


# ============================
# Local history helpers
# ============================

def append_history_entry(state: Dict[str, Any], history_db: Dict[str, Any], timestamp: int, event_type: str):
    path = state["path"]
    new_hash = state["combined_hash"]

    entry = {
        "timestamp": timestamp,
        "event": event_type,
        "file_uid": state.get("file_uid"),
        "combined_hash": new_hash,
        "content_hash": state.get("content_hash"),
        "filesystem_hash": state.get("filesystem_hash"),
        "embedded_metadata_hash": state.get("embedded_metadata_hash"),
        "filesystem_metadata": state.get("filesystem_metadata"),
        "embedded_metadata": state.get("embedded_metadata"),
        "current_user": state.get("current_user"),
        "machine": state.get("machine"),
    }

    if path not in history_db:
        history_db[path] = [entry]
        return

    last = history_db[path][-1]
    if last.get("combined_hash") == new_hash:
        return

    history_db[path].append(entry)


def append_deletion_history(path: str, history_db: Dict[str, Any], timestamp: int, file_uid: Optional[str]):
    if path not in history_db:
        history_db[path] = []
    if history_db[path] and history_db[path][-1].get("event") == "DELETED":
        return

    history_db[path].append({
        "timestamp": timestamp,
        "event": "DELETED",
        "file_uid": file_uid,
        "combined_hash": None,
        "content_hash": None,
        "filesystem_hash": None,
        "embedded_metadata_hash": None,
        "filesystem_metadata": None,
        "embedded_metadata": None,
        "current_user": None,
        "machine": None,
    })


# ============================
# Baseline / reconciliation
# ============================

def baseline_scan(watch_dir: str):
    watch_dir = os.path.abspath(watch_dir)

    if is_excluded_dir(watch_dir):
        print(f"[*] Baseline: root excluded, skipping: {watch_dir}")
        return

    print(f"[*] Performing baseline reconciliation on: {watch_dir}")

    db = load_json(HASH_DB_FILE)
    history_db = load_json(HISTORY_DB_FILE)

    now_ts = int(time.time())
    now_iso = datetime.fromtimestamp(now_ts, tz=AGENT_TZ).isoformat()

    seen_paths = set()
    events = []

    for root, dirs, files in os.walk(watch_dir):
        # prune excluded dirs from recursion
        pruned = []
        for d in dirs:
            full = os.path.join(root, d)
            if is_excluded_dir(full):
                pruned.append(d)
        for d in pruned:
            dirs.remove(d)

        for name in files:
            path = os.path.join(root, name)
            if should_ignore_path(path):
                continue
            if not os.path.exists(path):
                continue

            abs_path = os.path.abspath(path)
            old_state = db.get(abs_path)

            file_uid = old_state.get("file_uid") if old_state and old_state.get("file_uid") else str(uuid.uuid4())

            try:
                current_state = compute_snapshot(abs_path, file_uid)
            except Exception:
                continue

            seen_paths.add(abs_path)

            if old_state is None:
                status = "CREATED"
                chunk_diff = None
            else:
                if current_state["combined_hash"] == old_state.get("combined_hash"):
                    continue
                status = "MODIFIED"
                chunk_diff = compute_chunk_diff(old_state.get("chunks"), current_state.get("chunks"))

            db[abs_path] = current_state
            append_history_entry(current_state, history_db, now_ts, status)

            events.append({"path": abs_path, "status": status})

            send_event_to_central({
                "agent_id": AGENT_ID,
                "endpoint": ENDPOINT,
                "hostname": HOSTNAME,
                "username": USERNAME,
                "event_type": status,
                "source": "baseline",
                "path": abs_path,
                "timestamp": now_iso,
                "snapshot": current_state,
                "chunk_diff": chunk_diff,
            })

    # Deletions within this root
    for stored_path in list(db.keys()):
        if should_ignore_path(stored_path):
            continue

        if stored_path.startswith(watch_dir + os.sep) and stored_path not in seen_paths:
            if not os.path.exists(stored_path):
                old_state = db.get(stored_path)
                file_uid = old_state.get("file_uid") if old_state else None

                append_deletion_history(stored_path, history_db, now_ts, file_uid)

                del db[stored_path]
                events.append({"path": stored_path, "status": "DELETED"})

                send_event_to_central({
                    "agent_id": AGENT_ID,
                    "endpoint": ENDPOINT,
                    "hostname": HOSTNAME,
                    "username": USERNAME,
                    "event_type": "DELETED",
                    "source": "baseline",
                    "path": stored_path,
                    "timestamp": now_iso,
                    "snapshot": old_state,
                    "chunk_diff": None,
                })

    save_json(db, HASH_DB_FILE)
    save_json(history_db, HISTORY_DB_FILE)

    if events:
        print("[*] Baseline differences detected:")
        for e in events:
            print(f"    {e['status']:8} {e['path']}")
    else:
        print("[*] Baseline is up to date (no differences).")


# ============================
# File system event handler
# ============================

class FIMEventHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()

    def _handle_file_change(self, path: str, event_type: str):
        if not path:
            return
        if os.path.isdir(path):
            return
        if should_ignore_path(path):
            return

        abs_path = os.path.abspath(path)
        now_ts = int(time.time())
        now_iso = datetime.fromtimestamp(now_ts, tz=AGENT_TZ).isoformat()

        db = load_json(HASH_DB_FILE)
        history_db = load_json(HISTORY_DB_FILE)

        if event_type == "DELETED":
            old_state = db.get(abs_path)
            file_uid = old_state.get("file_uid") if old_state else None

            print(f"[DELETED] {abs_path}")

            append_deletion_history(abs_path, history_db, now_ts, file_uid)

            if abs_path in db:
                del db[abs_path]

            save_json(db, HASH_DB_FILE)
            save_json(history_db, HISTORY_DB_FILE)

            send_event_to_central({
                "agent_id": AGENT_ID,
                "endpoint": ENDPOINT,
                "hostname": HOSTNAME,
                "username": USERNAME,
                "event_type": "DELETED",
                "source": "realtime",
                "path": abs_path,
                "timestamp": now_iso,
                "snapshot": old_state,
                "chunk_diff": None,
            })
            return

        if not os.path.exists(abs_path):
            return

        old_state = db.get(abs_path)
        file_uid = old_state.get("file_uid") if old_state and old_state.get("file_uid") else str(uuid.uuid4())

        try:
            current_state = compute_snapshot(abs_path, file_uid)
        except (PermissionError, FileNotFoundError):
            return

        if old_state is None:
            status = "CREATED"
            chunk_diff = None
        else:
            if current_state["combined_hash"] == old_state.get("combined_hash"):
                return
            status = "MODIFIED"
            chunk_diff = compute_chunk_diff(old_state.get("chunks"), current_state.get("chunks"))

        db[abs_path] = current_state
        append_history_entry(current_state, history_db, now_ts, status)

        save_json(db, HASH_DB_FILE)
        save_json(history_db, HISTORY_DB_FILE)

        print(f"[{status}] {abs_path}")

        send_event_to_central({
            "agent_id": AGENT_ID,
            "endpoint": ENDPOINT,
            "hostname": HOSTNAME,
            "username": USERNAME,
            "event_type": status,
            "source": "realtime",
            "path": abs_path,
            "timestamp": now_iso,
            "snapshot": current_state,
            "chunk_diff": chunk_diff,
        })

    def on_created(self, event):
        if not event.is_directory and not should_ignore_path(event.src_path):
            self._handle_file_change(event.src_path, "CREATED")

    def on_modified(self, event):
        if not event.is_directory and not should_ignore_path(event.src_path):
            self._handle_file_change(event.src_path, "MODIFIED")

    def on_deleted(self, event):
        if not event.is_directory and not should_ignore_path(event.src_path):
            self._handle_file_change(event.src_path, "DELETED")

    def on_moved(self, event):
        if event.is_directory:
            return

        old_path = os.path.abspath(event.src_path)
        new_path = os.path.abspath(event.dest_path)

        if should_ignore_path(old_path) or should_ignore_path(new_path):
            return

        now_ts = int(time.time())
        now_iso = datetime.fromtimestamp(now_ts, tz=AGENT_TZ).isoformat()

        db = load_json(HASH_DB_FILE)
        history_db = load_json(HISTORY_DB_FILE)

        if not os.path.exists(new_path):
            return

        old_state = db.get(old_path)
        file_uid = old_state.get("file_uid") if old_state and old_state.get("file_uid") else str(uuid.uuid4())

        try:
            new_state = compute_snapshot(new_path, file_uid)
        except Exception:
            return

        if old_path in db:
            del db[old_path]

        db[new_path] = new_state

        history_db.setdefault(new_path, []).append({
            "timestamp": now_ts,
            "event": "MOVED",
            "old_path": old_path,
            "new_path": new_path,
            "file_uid": file_uid,
            "combined_hash": new_state.get("combined_hash"),
            "content_hash": new_state.get("content_hash"),
            "filesystem_hash": new_state.get("filesystem_hash"),
            "embedded_metadata_hash": new_state.get("embedded_metadata_hash"),
            "filesystem_metadata": new_state.get("filesystem_metadata"),
            "embedded_metadata": new_state.get("embedded_metadata"),
            "current_user": new_state.get("current_user"),
            "machine": new_state.get("machine"),
        })

        save_json(db, HASH_DB_FILE)
        save_json(history_db, HISTORY_DB_FILE)

        print(f"[MOVED] {old_path}  →  {new_path}")

        chunk_diff = compute_chunk_diff(old_state.get("chunks") if old_state else None, new_state.get("chunks"))

        send_event_to_central({
            "agent_id": AGENT_ID,
            "endpoint": ENDPOINT,
            "hostname": HOSTNAME,
            "username": USERNAME,
            "event_type": "MOVED",
            "source": "realtime",
            "old_path": old_path,
            "new_path": new_path,
            "path": new_path,
            "timestamp": now_iso,
            "snapshot": new_state,
            "chunk_diff": chunk_diff,
        })


# ============================
# Agent runner
# ============================

def run_agent(recursive: bool = True):
    global WATCH_DIRS

    # 1) Load runtime config file (if exists) and apply (including watch_dirs)
    runtime_cfg, runtime_ver = load_runtime_state()
    if runtime_cfg:
        print(f"[*] Loaded runtime config version {runtime_ver} from {RUNTIME_CONFIG_PATH}")
        apply_runtime_config(runtime_cfg, runtime_ver, allow_watch_dir_update=True)

    # 2) Initial heartbeat (may override config)
    print("[*] Sending initial heartbeat to central...")
    agent_heartbeat(periodic=False)

    WATCH_DIRS = normalize_paths_list(WATCH_DIRS)
    if not WATCH_DIRS:
        raise RuntimeError("No watch_dirs configured")

    print("[*] Starting FIM agent with watch roots:")
    for d in WATCH_DIRS:
        print("    -", d)

    print(f"[*] Agent ID: {AGENT_ID}")
    print(f"[*] Endpoint: {ENDPOINT}")
    print(f"[*] Hostname: {HOSTNAME}, Username: {USERNAME}")
    print(f"[*] Central API URL: {CENTRAL_API_URL}")
    print(f"[*] Heartbeat URL: {get_heartbeat_url()}")
    print(f"[*] Heartbeat interval: {HEARTBEAT_INTERVAL} seconds")
    print(f"[*] Chunk size: {CHUNK_SIZE} bytes, max chunked file size: {CHUNK_MAX_BYTES} bytes")
    print(f"[*] Agent timezone: {AGENT_TZ_STR} (resolved to {AGENT_TZ})")
    print(f"[*] Bootstrap ignore_patterns: {BOOTSTRAP_IGNORE_PATTERNS}")
    print(f"[*] Runtime ignore_patterns: {RUNTIME_IGNORE_PATTERNS}")
    print(f"[*] Bootstrap exclude_dirs: {EXCLUDE_DIRS}")
    print(f"[*] Runtime exclude_dirs: {RUNTIME_EXCLUDE_DIRS}")
    print(f"[*] Bootstrap exclude_globs: {EXCLUDE_GLOBS}")
    print(f"[*] Runtime exclude_globs: {RUNTIME_EXCLUDE_GLOBS}")

    # 3) Baseline scan for each root
    for d in WATCH_DIRS:
        baseline_scan(d)

    print("[*] Entering real-time monitoring...")
    print("[*] Press Ctrl+C to stop.\n")

    event_handler = FIMEventHandler()
    observer = Observer()

    for d in WATCH_DIRS:
        if is_excluded_dir(d):
            print(f"[*] Watch root excluded, not scheduling: {d}")
            continue
        observer.schedule(event_handler, d, recursive=recursive)

    observer.start()
    last_hb = time.time()

    try:
        while True:
            time.sleep(1)
            now = time.time()
            if now - last_hb >= HEARTBEAT_INTERVAL:
                print("[*] Sending periodic heartbeat...")
                agent_heartbeat(periodic=True)
                last_hb = now

    except KeyboardInterrupt:
        print("\n[*] Stopping observer...")
        observer.stop()

    observer.join()


if __name__ == "__main__":
    run_agent(recursive=True)
