"""Main entry point - runs watcher and Flask dashboard"""
import threading
import time
from .models import init_database
from .watcher import DirectoryWatcher
from .app import run_app
from .config import FLASK_HOST, FLASK_PORT


def main():
    """Initialize and run both the watcher and Flask app"""
    # Initialize database
    print("[INIT] Initializing database...")
    db_ready = init_database()
    if db_ready:
        print("[INIT] Database ready")
    else:
        print("[INIT] Database connection failed - continuing anyway")
        print("[INIT] Please ensure PostgreSQL is running and accessible at the configured address")
        print("[INIT] Database operations will fail until connection is established")
    
    # Start directory watcher in a background thread
    print("[INIT] Starting directory watcher...")
    watcher = DirectoryWatcher()
    watcher_thread = threading.Thread(target=watcher.start, daemon=True)
    watcher_thread.start()
    
    # Give watcher a moment to start and check for errors
    time.sleep(0.5)
    if not watcher.running:
        print("[INIT] WARNING: Directory watcher failed to start - check directory permissions and path")
    
    # Start Flask app (blocking)
    try:
        run_app(host=FLASK_HOST, port=FLASK_PORT, debug=False)
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Shutting down...")
        watcher.stop()


if __name__ == "__main__":
    main()






