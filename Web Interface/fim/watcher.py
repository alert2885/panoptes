"""Directory watcher agent using watchdog"""
import os
import time
from datetime import datetime
import socket
import getpass
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .config import WATCH_DIRECTORY, ENDPOINT_NAME
from .hashing import compute_hash
from .models import insert_event, get_latest_hash
from .alerts import print_alert
import json


class FIMEventHandler(FileSystemEventHandler):
    """Handler for file system events"""
    
    def __init__(self):
        super().__init__()
        self.hostname = socket.gethostname()
        self.username = getpass.getuser()
        self.endpoint = ENDPOINT_NAME
    
    def _process_event(self, event_type: str, src_path: str, is_directory: bool = False) -> None:
        """Process a file system event
        
        Args:
            event_type: Type of event (created/modified/deleted)
            src_path: Path to the file or directory
            is_directory: Whether the path is a directory
        """
        # Skip directory events (only monitor files)
        if is_directory:
            return
        
        file_path = os.path.abspath(src_path)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Determine hash values based on event type
        hash_before = None
        hash_after = None
        
        if event_type == "created":
            # Skip if not a file (might be a directory)
            if not os.path.isfile(file_path):
                return
            hash_after = compute_hash(file_path)
        
        elif event_type == "modified":
            # Skip if not a file
            if not os.path.isfile(file_path):
                return
            hash_before = get_latest_hash(file_path)
            hash_after = compute_hash(file_path)
        
        elif event_type == "deleted":
            # For deleted files, we can't check if it's a file anymore
            # Get hash_before from database (file is already deleted)
            hash_before = get_latest_hash(file_path)
            hash_after = None
        
        # Calculate additional fields
        state_hash = None
        content_hash = hash_after  # content_hash is same as hash_after
        file_size = None
        metadata_json = None
        alert_sent = False
        
        if event_type in ["created", "modified"]:
            try:
                if os.path.isfile(file_path):
                    file_size = os.path.getsize(file_path)
                    # Create metadata JSON
                    metadata_json = {
                        "file_size": file_size,
                        "hostname": self.hostname,
                        "username": self.username,
                        "endpoint": self.endpoint
                    }
            except (OSError, IOError):
                pass
        
        # Prepare event data with all fields
        event_data = {
            "event_type": event_type,
            "file_path": file_path,
            "timestamp": timestamp,
            "endpoint": self.endpoint,
            "hostname": self.hostname,
            "username": self.username,
            "hash_before": hash_before,
            "hash_after": hash_after,
            "state_hash": state_hash,
            "content_hash": content_hash,
            "file_size": file_size,
            "metadata_json": metadata_json,
            "alert_sent": alert_sent
        }
        
        # Store event in database
        insert_event(event_data)
        
        # Print console alert
        print_alert(
            event_type=event_type,
            file_path=file_path,
            endpoint=self.endpoint,
            hostname=self.hostname,
            username=self.username,
            timestamp=timestamp
        )
    
    def on_created(self, event):
        """Handle file creation events"""
        self._process_event("created", event.src_path, event.is_directory)
    
    def on_modified(self, event):
        """Handle file modification events"""
        self._process_event("modified", event.src_path, event.is_directory)
    
    def on_deleted(self, event):
        """Handle file deletion events"""
        self._process_event("deleted", event.src_path, event.is_directory)


class DirectoryWatcher:
    """Directory watcher agent"""
    
    def __init__(self, watch_directory: str = None):
        # Use config value if no directory provided
        self.watch_directory = watch_directory or WATCH_DIRECTORY
        self.observer = None
        self.running = False
    
    def start(self) -> None:
        """Start watching the directory"""
        # Ensure watched directory exists
        try:
            os.makedirs(self.watch_directory, exist_ok=True)
        except PermissionError:
            print(f"[WATCHER] ERROR: Permission denied accessing directory: {self.watch_directory}")
            print("[WATCHER] Please check directory permissions or update WATCH_DIRECTORY in config")
            return
        except OSError as e:
            print(f"[WATCHER] ERROR: Cannot access directory {self.watch_directory}: {e}")
            print("[WATCHER] Please check the directory path in config")
            return
        
        if self.running:
            return
        
        # Verify directory exists and is accessible
        if not os.path.exists(self.watch_directory):
            print(f"[WATCHER] ERROR: Directory does not exist: {self.watch_directory}")
            return
        
        if not os.path.isdir(self.watch_directory):
            print(f"[WATCHER] ERROR: Path is not a directory: {self.watch_directory}")
            return
        
        try:
            event_handler = FIMEventHandler()
            self.observer = Observer()
            self.observer.schedule(event_handler, self.watch_directory, recursive=True)
            self.observer.start()
            self.running = True
            
            print(f"[WATCHER] Started monitoring: {os.path.abspath(self.watch_directory)}")
        except Exception as e:
            print(f"[WATCHER] ERROR: Failed to start watcher: {e}")
            self.running = False
    
    def stop(self) -> None:
        """Stop watching the directory"""
        if self.observer and self.running:
            self.observer.stop()
            self.observer.join()
            self.running = False
            print("[WATCHER] Stopped monitoring")


def run_watcher(watch_directory: str = None) -> DirectoryWatcher:
    """Run the directory watcher (blocking)
    
    Args:
        watch_directory: Optional directory to watch
    
    Returns:
        DirectoryWatcher instance
    """
    watcher = DirectoryWatcher(watch_directory)
    watcher.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        watcher.stop()
    
    return watcher

