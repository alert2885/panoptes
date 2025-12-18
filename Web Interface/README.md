# File Integrity Monitoring (FIM) System

A minimal viable product (MVP) for real-time file integrity monitoring in Python. This system monitors a directory for file changes (created, modified, deleted), computes SHA256 hashes, stores events in SQLite, and provides a Flask web dashboard.

## Features

- Real-time directory monitoring using watchdog
- SHA256 hash computation for file integrity
- SQLite database for event storage
- Console alerts for file system events
- Flask web dashboard with filtering and hash inspection

## Project Structure

```
.
├── README.md
├── requirements.txt
├── fim/
│   ├── __init__.py
│   ├── config.py          # Configuration settings
│   ├── watcher.py         # Directory watcher agent
│   ├── hashing.py         # SHA256 utilities
│   ├── models.py          # SQLite database layer
│   ├── alerts.py          # Console alert logic
│   ├── app.py             # Flask application
│   └── main.py            # Entry point
├── templates/
│   └── index.html         # Dashboard template
└── data/
    └── fim_events.db      # SQLite database (created on first run)
```

## Installation

### 1. Create a virtual environment

```bash
python -m venv venv
```

### 2. Activate the virtual environment

On Windows:
```bash
venv\Scripts\activate
```

On Linux/Mac:
```bash
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Running the Application

Start the FIM system:

```bash
python main.py
```

Or:

```bash
python -m fim.main
```

This will:
- Initialize the SQLite database in `data/fim_events.db`
- Start monitoring the directory specified in `fim/config.py`
- Launch the Flask dashboard at `http://localhost:5000`

### Configuration

Edit `fim/config.py` to customize:

- `WATCH_DIRECTORY`: Directory to monitor (default: `./watched`)
- `DB_PATH`: SQLite database path (default: `./data/fim_events.db`)
- `ENDPOINT_NAME`: Endpoint identifier for this agent (default: `local_agent`)
- `FLASK_HOST`: Flask host (default: `0.0.0.0`)
- `FLASK_PORT`: Flask port (default: `5000`)

### Dashboard Features

- **Filter by event type**: Use the dropdown to filter events (All, Created, Modified, Deleted)
- **View event details**: See timestamp, event type, file path, endpoint, hostname, and username
- **Inspect hashes**: Click the "Info" button on any row to view hash_before and hash_after values in a modal

### Console Alerts

The system prints alerts to the console when events are detected:

```
[ALERT] 2025-11-28 16:33:22 MODIFIED /home/project/test.txt endpoint=local_agent hostname=myhost user=alice
```

## Database Schema

The `events` table contains:

- `id`: Auto-incrementing primary key
- `event_type`: created / modified / deleted
- `file_path`: Absolute path to the file
- `timestamp`: Local time string
- `endpoint`: Endpoint identifier
- `hostname`: System hostname
- `username`: Current user
- `hash_before`: Previous hash (for modified/deleted events)
- `hash_after`: New hash (for created/modified events)

## Notes

- The watched directory will be created automatically if it doesn't exist
- Only files are monitored (directories are ignored)
- Large files are hashed in chunks for efficiency
- The dashboard shows the latest 100 events by default

